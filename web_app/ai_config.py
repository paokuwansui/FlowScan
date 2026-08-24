"""AI 配置 / MCP / Skill 路由 + 配置辅助函数。

_ai_config / _skills_config / _skill_prompt_section 被 ai_analysis、ai_schedule、
ai_logs、agent 等模块共享,故集中在本文档。
"""
import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from flask import jsonify, request

from flowscan import mcp_verify
from flowscan.config import load_yaml, save_yaml
from flowscan.llm import _REASONING_EFFORTS, _apply_reasoning_effort  # re-export:统一 LLM 调用核心
from flowscan.utils import project_root

from ._common import _to_bool, login_required


def _mask_secret(s: str) -> str:
    if not s:
        return ""
    if len(s) <= 8:
        return "****"
    return s[:4] + "****" + s[-4:]


def _ai_config(config: Dict[str, Any]) -> Dict[str, Any]:
    cfg = config.get("ai_analysis", {}) or {}
    system_prompt = str(cfg.get("system_prompt", "") or "")
    if not system_prompt.strip():
        prompt_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "prompts", "ai_analysis.txt")
        if os.path.exists(prompt_file):
            with open(prompt_file, "r", encoding="utf-8") as handle:
                system_prompt = handle.read().strip()
    skill_section = _skill_prompt_section(config)
    if skill_section:
        system_prompt = (system_prompt + "\n\n" + skill_section).strip()
    approval_mode = str(cfg.get("agent_approval_mode", "") or "").strip().lower()
    if approval_mode not in ("auto", "human", "ai"):
        # 兼容旧配置: agent_require_approval=true → 人工审批，否则自动放行
        approval_mode = "human" if cfg.get("agent_require_approval") else "auto"
    return {
        "base_url": str(cfg.get("base_url", "")).rstrip("/"),
        "api_key": str(cfg.get("api_key", "")),
        "model": str(cfg.get("model", "gpt-4o-mini")),
        "timeout_seconds": int(cfg.get("timeout_seconds", 120) or 120),
        "max_events": int(cfg.get("max_events", 5000) or 5000),
        "system_prompt": system_prompt,
        "skill_section": skill_section,
        "log_api_key": str(cfg.get("log_api_key", "")),
        "agent_max_iterations": int(cfg.get("agent_max_iterations", 50) or 50),
        "agent_scan_gap_seconds": int(cfg.get("agent_scan_gap_seconds", 5) or 5),
        "agent_plan_mode": _to_bool(cfg.get("agent_plan_mode", False)),
        "agent_context_max_chars": int(cfg.get("agent_context_max_chars", 60000) or 60000),
        # 上下文预算(token 计量):压缩按 token 近似计量(替代字符数预算,中英混合更准)
        "agent_context_max_tokens": int(cfg.get("agent_context_max_tokens", 24000) or 24000),
        "agent_approval_mode": approval_mode,
        "agent_require_approval": approval_mode == "human",  # 兼容旧调用方
        "reasoning_effort": str(cfg.get("reasoning_effort", "off") or "off").strip().lower()
                            if str(cfg.get("reasoning_effort", "off") or "off").strip().lower() in _REASONING_EFFORTS
                            else "off",
    }


_AI_CONFIG_FIELDS = ("base_url", "api_key", "model", "timeout_seconds", "max_events", "log_api_key",
                     "agent_max_iterations", "agent_scan_gap_seconds", "agent_plan_mode",
                     "agent_context_max_chars", "agent_context_max_tokens",
                     "agent_approval_mode", "reasoning_effort")


def _skill_dirs(config: Dict[str, Any]) -> List[str]:
    """解析技能目录：未配置/为空时默认项目内 skills/；相对路径基于项目根解析。"""
    cfg = config.get("skills", {}) or {}
    raw = [str(d).strip() for d in (cfg.get("dirs") or []) if str(d).strip()]
    if not raw:
        raw = ["skills"]
    resolved = []
    for d in raw:
        if not os.path.isabs(d):
            d = os.path.join(project_root(), d)
        if d not in resolved:
            resolved.append(d)
    return resolved


def _skills_config(config: Dict[str, Any]) -> Dict[str, Any]:
    cfg = config.get("skills", {}) or {}
    return {
        # 默认启用(用户要求:启用 Skill 加载默认勾选;未配置 skills 段时视为开启)
        "enabled": _to_bool(cfg.get("enabled", True)),
        "dirs": _skill_dirs(config),
        "loaded": [str(n) for n in (cfg.get("loaded", []) or []) if n],
        "force_load": bool(cfg.get("force_load", False)),
    }


def _parse_skill_md(path: str) -> Dict[str, str]:
    """解析 SKILL.md，返回 {"description": str, "content": str(去 frontmatter)}。"""
    out = {"description": "", "content": ""}
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return out
    m = re.search(r"^---\s*\n(.*?)\n---", content, re.S)
    if m:
        dm = re.search(r"^description:\s*(.+)$", m.group(1), re.M)
        if dm:
            raw = dm.group(1).strip()
            if raw in ("", ">", ">-", ">+", "|", "|-", "|+"):
                # YAML 折叠/字面块:内容在下一行缩进
                block = re.search(r"^description:\s*[^\n]*\n((?:[ \t]+[^\n]*(?:\n|$))+)", m.group(1), re.M)
                if block:
                    lines = [re.sub(r"^[ \t]+", "", ln).strip() for ln in block.group(1).splitlines()]
                    out["description"] = " ".join(x for x in lines if x)
            else:
                out["description"] = raw
        out["content"] = re.sub(r"^---\s*\n.*?\n---\s*\n?", "", content, count=1, flags=re.S).strip()
    else:
        out["content"] = content.strip()
    return out


# skill 扫描缓存(919 个 SKILL.md 全量解析 IO 大,而 _scan_skills 被
# system prompt 组装/load_skill/API 高频调用;按 dirs+mtime 缓存 30s)
_SCAN_CACHE_TTL = 30.0
_scan_cache: Dict[str, Any] = {"key": "", "ts": 0.0, "result": []}


def _invalidate_skill_cache() -> None:
    """配置变更后使 skill 扫描缓存失效(POST /api/skills 保存时调用)。"""
    _scan_cache["key"] = ""


def _scan_skills(dirs: List[str]) -> List[Dict[str, Any]]:
    """扫描 skill 目录,返回 [{name, category, description}]。结果按 (dirs+mtime) 缓存 30s。"""
    key_parts = []
    for d in dirs or []:
        try:
            key_parts.append(f"{d}:{os.stat(d).st_mtime_ns}")
        except OSError:
            key_parts.append(f"{d}:missing")
    key = "|".join(key_parts)
    now = time.time()
    if key and _scan_cache.get("key") == key and now - _scan_cache.get("ts", 0) < _SCAN_CACHE_TTL:
        return _scan_cache["result"]
    result = []
    seen = set()
    for d in dirs or []:
        if not d or not os.path.isdir(d):
            continue
        category = os.path.basename(os.path.normpath(d))
        try:
            entries = sorted(os.listdir(d))
        except OSError:
            continue
        for entry in entries:
            skill_md = os.path.join(d, entry, "SKILL.md")
            if not os.path.isfile(skill_md):
                continue
            if entry in seen:
                continue
            seen.add(entry)
            parsed = _parse_skill_md(skill_md)
            result.append({"name": entry, "category": category,
                           "description": parsed.get("description", "")})
    if key:
        _scan_cache.update(key=key, ts=now, result=result)
    return result


def _skill_paths(config: Dict[str, Any]) -> Dict[str, str]:
    """已配置目录中 skill 名 → SKILL.md 路径（后者覆盖前者）。"""
    scfg = _skills_config(config)
    paths = {}
    for d in scfg["dirs"]:
        if not os.path.isdir(d):
            continue
        try:
            for entry in os.listdir(d):
                p = os.path.join(d, entry, "SKILL.md")
                if os.path.isfile(p):
                    paths[entry] = p
        except OSError:
            continue
    return paths


def _read_skill_content(dirs: List[str], name: str) -> Optional[str]:
    """按需读取某个 skill 的全文（渐进式加载用）。不存在/失败返回 None。"""
    for d in dirs or []:
        p = os.path.join(d, name, "SKILL.md")
        if os.path.isfile(p):
            parsed = _parse_skill_md(p)
            return parsed.get("content") or None
    return None


def _skill_prompt_section(config: Dict[str, Any], max_chars_per_skill: int = 3000,
                          max_skills: int = 10, for_agent: bool = False,
                          max_index_skills: int = 100, redis=None) -> str:
    """生成 skill section(注入 system prompt)。

    滑块开(loaded)的 skill → 全文注入(必然加载,护栏 max_chars_per_skill 防爆);
    滑块关的 skill → 渐进式:仅索引(名字+短描述,限量 max_index_skills 防上下文爆炸),
    Agent 需要时可调用 load_skill 工具按需取全文。

    2026-08 调整:
    - max_chars_per_skill 6000→3000、max_skills 20→10——全文注入总预算
      从 12 万字符降到 3 万,默认窗口 6 万留 3 万给历史,50 轮不溢出;
    - 索引描述 60→120/200 自适应(技能少时预算富余用 200);
    - 最近 load_skill 使用过的技能(Redis zset)索引置顶,标记 ★常用。
    """
    scfg = _skills_config(config)
    if not scfg["enabled"]:
        return ""
    paths = _skill_paths(config)
    loaded = set(scfg["loaded"])

    # ① 全文部分:滑块开的 skill
    sections = []
    for name in scfg["loaded"][:max_skills]:
        content = _read_skill_content(scfg["dirs"], name)
        if content is None:
            continue
        if len(content) > max_chars_per_skill:
            content = content[:max_chars_per_skill] + "\n...[truncated]..."
        sections.append(f"===== SKILL: {name} =====\n{content}")

    # ② 渐进式索引:全部可用 skill(名字+短描述,限量;标记已全文/渐进式;
    #    常用技能优先入选,保证最近用过的永远在索引内)
    all_skills = _scan_skills(scfg["dirs"])
    top_used = []
    if redis is not None:
        try:
            top_used = [str(x) for x in redis.conn.zrevrange("fs3:ai:skill_usage", 0, 9)]
        except Exception:
            pass
    used_set = set(top_used)
    ordered = ([sk for sk in all_skills if sk.get("name") in used_set] +
               [sk for sk in all_skills if sk.get("name") not in used_set])[:max_index_skills]
    # 描述长度自适应:技能少(<50)预算富余用 200,否则压缩到 120
    desc_show_len = 200 if len(all_skills) <= 50 else 120
    index = []
    for sk in ordered:
        name = str(sk.get("name") or "")
        if not name:
            continue
        p = paths.get(name)
        desc = str(sk.get("description") or "") or (_parse_skill_md(p).get("description", "") if p else "")
        marker = "[已加载全文]" if name in loaded else "[渐进式]"
        hot = " ★常用" if name in used_set else ""
        index.append(f"- {name} {marker}{hot}: {desc[:desc_show_len]}")
    if len(all_skills) > max_index_skills:
        index.append(f"- …(共 {len(all_skills)} 个 skill,索引仅显示前 {max_index_skills} 个;"
                     f"可用 search_skills 工具按关键词搜索,load_skill 按名称获取全文)")

    header = "\n\n[技能库]\n" + "\n".join(index)
    if not sections:
        return header
    return header + "\n\n[技能全文(滑块开启)]\n" + "\n\n".join(sections)


def register(app):
    @app.route("/api/ai-config")
    @login_required
    def ai_config_get():
        config = load_yaml(app.config["CONFIG_PATH"])
        ai = config.get("ai_analysis", {}) or {}
        out = {k: ai.get(k, "") for k in _AI_CONFIG_FIELDS}
        for k in ("api_key", "log_api_key"):
            v = str(out.get(k, "") or "")
            out[k + "_masked"] = bool(v and not v.startswith("YOUR_"))
            if out[k + "_masked"]:
                out[k] = _mask_secret(v)
        return jsonify({"ok": True, "config": out})

    @app.route("/api/ai-config", methods=["POST"])
    @login_required
    def ai_config_post():
        config = load_yaml(app.config["CONFIG_PATH"])
        ai = dict(config.get("ai_analysis", {}) or {})
        data = request.get_json(silent=True) or {}
        for k in _AI_CONFIG_FIELDS:
            if k not in data:
                continue
            v = data[k]
            if k in ("api_key", "log_api_key"):
                v = str(v or "").strip()
                if not v or "****" in v:
                    continue  # 脱敏值或空,保留原值
                if any(ord(c) > 127 for c in v):
                    continue  # 含非 ASCII(粘贴错误/UI 文案误存),拒绝写入
            elif k in ("timeout_seconds", "max_events", "agent_max_iterations", "agent_scan_gap_seconds", "agent_context_max_chars", "agent_context_max_tokens"):
                try:
                    v = int(v)
                except (TypeError, ValueError):
                    continue
            elif k == "agent_approval_mode":
                v = str(v or "").strip().lower()
                if v not in ("auto", "human", "ai"):
                    continue  # 非法模式忽略，保留原值
            elif k == "reasoning_effort":
                v = str(v or "").strip().lower()
                if v not in _REASONING_EFFORTS:
                    continue  # 非法强度忽略，保留原值
            elif k in ("agent_plan_mode", "agent_require_approval"):
                v = _to_bool(v)
            else:
                v = str(v or "").strip()
            ai[k] = v
        config["ai_analysis"] = ai
        save_yaml(app.config["CONFIG_PATH"], config)
        return jsonify({"ok": True, "message": "AI 配置已保存,下次分析/Agent 生效"})

    @app.route("/api/ai-config/models", methods=["POST"])
    @login_required
    def ai_config_models():
        """从 OpenAI 兼容的 /models 接口获取可用模型列表。

        请求体: {base_url, api_key}。api_key 留空或为脱敏值(****)时,
        使用 config.yaml 中已保存的密钥(服务端代发,避免浏览器 CORS 问题)。
        """
        config = load_yaml(app.config["CONFIG_PATH"])
        ai_cfg = _ai_config(config)
        data = request.get_json(silent=True) or {}
        base_url = str(data.get("base_url", "") or "").strip() or ai_cfg.get("base_url", "")
        api_key = str(data.get("api_key", "") or "").strip()
        if not api_key or "****" in api_key:
            api_key = str(ai_cfg.get("api_key", "") or "")
        if api_key and any(ord(c) > 127 for c in api_key):
            return jsonify({"ok": False, "error": "API Key 含非 ASCII 字符,请到 AI 配置重新填写"}), 400
        if not base_url:
            return jsonify({"ok": False, "error": "请先填写 Base URL"}), 400
        try:
            req = urllib.request.Request(base_url.rstrip("/") + "/models", headers={
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "FlowScan-AIConfig/1.0",
            })
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw)
            models = sorted(m.get("id") for m in (parsed.get("data") or [])
                            if isinstance(m, dict) and m.get("id"))
            return jsonify({"ok": True, "count": len(models), "models": models})
        except urllib.error.HTTPError as exc:
            detail = (exc.read() or b"").decode("utf-8", errors="replace")[:300] if exc.fp else str(exc)
            return jsonify({"ok": False, "error": f"HTTP {exc.code}: {detail}"})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)})

    # ── MCP 配置与验证 ──

    @app.route("/api/mcp/servers")
    @login_required
    def mcp_servers_get():
        config = load_yaml(app.config["CONFIG_PATH"])
        mcp = config.get("mcp", {}) or {}
        return jsonify({"ok": True, "enabled": bool(mcp.get("enabled", False)),
                        "servers": mcp.get("servers", []) or []})

    @app.route("/api/mcp/servers", methods=["POST"])
    @login_required
    def mcp_servers_post():
        config = load_yaml(app.config["CONFIG_PATH"])
        data = request.get_json(silent=True) or {}
        enabled = _to_bool(data.get("enabled", False))
        norm = []
        for s in (data.get("servers", []) or []):
            if not isinstance(s, dict):
                continue
            name = str(s.get("name", "")).strip()
            if not name:
                continue
            norm.append({
                "name": name,
                "type": (str(s.get("type", "sse")).strip().lower() or "sse"),
                "url": str(s.get("url", "")).strip(),
                "command": str(s.get("command", "")).strip(),
                "enabled": _to_bool(s.get("enabled", True)),
            })
        config["mcp"] = {"enabled": enabled, "servers": norm}
        save_yaml(app.config["CONFIG_PATH"], config)
        return jsonify({"ok": True, "message": "MCP 配置已保存"})

    @app.route("/api/mcp/verify", methods=["POST"])
    @login_required
    def mcp_verify_endpoint():
        data = request.get_json(silent=True) or {}
        server = {
            "name": str(data.get("name", "") or ""),
            "type": str(data.get("type", "sse") or "sse"),
            "url": str(data.get("url", "") or ""),
            "command": str(data.get("command", "") or ""),
        }
        ok, msg, detail = mcp_verify.verify_mcp_server(server, timeout=int(data.get("timeout", 10) or 10))
        return jsonify({"ok": ok, "message": msg, "detail": detail})

    # ── Skill 加载 ──

    @app.route("/api/skills")
    @login_required
    def skills_get():
        config = load_yaml(app.config["CONFIG_PATH"])
        scfg = _skills_config(config)
        skills = _scan_skills(scfg["dirs"])
        return jsonify({"ok": True, "enabled": scfg["enabled"], "dirs": scfg["dirs"],
                        "loaded": scfg["loaded"],
                        # force_load 已废弃(滑块语义取代),保留字段仅为旧前端兼容
                        "force_load": False,
                        "skills": skills, "total": len(skills)})

    @app.route("/api/skills", methods=["POST"])
    @login_required
    def skills_post():
        config = load_yaml(app.config["CONFIG_PATH"])
        data = request.get_json(silent=True) or {}
        enabled = _to_bool(data.get("enabled", False))
        loaded = [str(n) for n in (data.get("loaded", []) or []) if n]
        dirs = [str(d) for d in (data.get("dirs", []) or []) if d]
        cfg = dict(config.get("skills", {}) or {})
        cfg["enabled"] = enabled
        cfg["loaded"] = loaded
        cfg.pop("force_load", None)   # 废弃字段,保存时移除(滑块语义取代)
        if dirs:
            cfg["dirs"] = dirs
        config["skills"] = cfg
        save_yaml(app.config["CONFIG_PATH"], config)
        _invalidate_skill_cache()  # 配置变更,扫描缓存失效
        return jsonify({"ok": True, "message": f"Skill 配置已保存(启用 {len(loaded)} 个技能, 滑块开启=全文加载)"})
