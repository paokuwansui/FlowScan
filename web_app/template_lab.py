"""模板实验室路由:模块 YAML 的编辑 / 校验 / transform / 执行 / parse 调试。"""
import os
import tempfile
import time
from typing import Any, Dict, List

import yaml
from flask import flash, jsonify, redirect, render_template, request, url_for

from flowscan.code_runner import CodeExecutionError, run_input_transform, run_output_parse
from flowscan.config import load_yaml, render_template as render_command_template
from flowscan.tool_module import ToolModule
from flowscan.utils import run_cmd

from ._common import _to_int, login_required


def _validate_yaml_text(yaml_text: str) -> Dict[str, Any]:
    try:
        data = yaml.safe_load(yaml_text) or {}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    if not isinstance(data, dict):
        return {"ok": False, "error": "YAML 顶层必须是对象"}
    warnings = []
    for key in ("name", "io_contract", "execution"):
        if key not in data:
            warnings.append(f"缺少字段: {key}")
    io_contract = data.get("io_contract") or {}
    execution = data.get("execution") or {}
    if not io_contract.get("input_events"):
        warnings.append("io_contract.input_events 为空")
    if not execution.get("command"):
        warnings.append("execution.command 为空")
    return {"ok": True, "error": "", "warnings": warnings, "data": data}


def _module_yaml_files(modules_dir: str) -> List[Dict[str, str]]:
    if not os.path.isdir(modules_dir):
        return []
    files = []
    for filename in sorted(os.listdir(modules_dir)):
        if filename.endswith((".yaml", ".yml")):
            files.append({"filename": filename, "path": os.path.join(modules_dir, filename)})
    return files


def _safe_module_path(modules_dir: str, filename: str) -> str:
    if not filename or not filename.endswith((".yaml", ".yml")):
        return ""
    base = os.path.abspath(modules_dir)
    path = os.path.abspath(os.path.join(base, filename))
    if path == base or not path.startswith(base + os.sep):
        return ""
    return path


def _tool_from_yaml_text(yaml_text: str) -> ToolModule:
    validation = _validate_yaml_text(yaml_text)
    if not validation["ok"]:
        raise ValueError(validation["error"])
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", encoding="utf-8", delete=False) as handle:
        handle.write(yaml_text)
        temp_path = handle.name
    try:
        return ToolModule.from_yaml(temp_path)
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass


def _run_template_lab_action(
    action: str,
    yaml_text: str,
    event_type: str,
    target: str,
    stdout: str,
    timeout: int,
    install_step: int,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    started = time.time()
    validation = _validate_yaml_text(yaml_text)
    if action == "validate":
        return {"ok": validation["ok"], "action": action, "error": validation.get("error", ""), "warnings": validation.get("warnings", []), "elapsed": round(time.time() - started, 3)}
    if not validation["ok"]:
        return {"ok": False, "action": action, "error": validation["error"], "elapsed": round(time.time() - started, 3)}
    try:
        tool = _tool_from_yaml_text(yaml_text)
    except Exception as exc:
        return {"ok": False, "action": action, "error": str(exc), "elapsed": round(time.time() - started, 3)}

    if action == "check":
        command = render_command_template(tool.check_command, {}, config)
        if not command:
            return {"ok": True, "action": action, "message": "未配置 check.command，默认视为可用", "elapsed": round(time.time() - started, 3)}
        ok, output, code = run_cmd(command, timeout=max(1, min(timeout, 300)))
        haystack = output.lower()
        expected = (tool.expect_keyword or "").lower()
        excluded = (tool.exclude_keyword or "").lower()
        keyword_ok = ok and (not expected or expected in haystack) and (not excluded or excluded not in haystack)
        return {"ok": ok and keyword_ok, "action": action, "command": command, "exit_code": code, "stdout": output[-12000:], "keyword_ok": keyword_ok, "expect_keyword": tool.expect_keyword, "exclude_keyword": tool.exclude_keyword, "elapsed": round(time.time() - started, 3)}

    if action == "install":
        steps = list(tool.install_steps or [])
        if not steps:
            return {"ok": True, "action": action, "message": "未配置 install.steps", "steps": [], "elapsed": round(time.time() - started, 3)}
        if install_step > 0:
            indexes = [install_step - 1] if install_step <= len(steps) else []
        else:
            indexes = list(range(len(steps)))
        results = []
        overall_ok = True
        for index in indexes:
            command = render_command_template(steps[index], {}, config)
            ok, output, code = run_cmd(command, timeout=max(1, min(timeout, tool.install_timeout or 900)))
            results.append({"step": index + 1, "command": command, "ok": ok, "exit_code": code, "stdout": output[-12000:]})
            overall_ok = overall_ok and ok
            if not ok:
                break
        return {"ok": overall_ok, "action": action, "results": results, "elapsed": round(time.time() - started, 3)}

    if action in {"transform", "scan"}:
        try:
            params_list = run_input_transform(tool.input_transform_code, {"event_type": event_type, "value": target}, config) if tool.input_transform_code else [{"target": target, "value": target, "event_type": event_type}]
        except CodeExecutionError as exc:
            return {"ok": False, "action": action, "stage": "input_transform", "error": str(exc), "elapsed": round(time.time() - started, 3)}
        commands = [render_command_template(tool.command_template, params, config) for params in params_list]
        if action == "transform":
            return {"ok": True, "action": action, "params": params_list, "commands": commands, "allowed_output_events": tool.allowed_output_events, "elapsed": round(time.time() - started, 3)}
        command_results = []
        parsed_results = []
        overall_ok = True
        for params, command in zip(params_list, commands):
            ok, output, code = run_cmd(command, timeout=max(1, min(timeout, 600)))
            item = {"params": params, "command": command, "ok": ok, "exit_code": code, "stdout": output[-12000:]}
            command_results.append(item)
            overall_ok = overall_ok and ok
            if ok and tool.output_parse_code:
                try:
                    parsed = run_output_parse(tool.output_parse_code, output, config)
                except CodeExecutionError as exc:
                    parsed = [{"__parse_error__": str(exc)}]
                    overall_ok = False
                parsed_results.extend(parsed)
        return {"ok": overall_ok, "action": action, "params": params_list, "commands": commands, "results": command_results, "parsed": parsed_results, "elapsed": round(time.time() - started, 3)}

    if action == "parse":
        try:
            parsed = run_output_parse(tool.output_parse_code, stdout, config) if tool.output_parse_code else []
            return {"ok": True, "action": action, "parsed": parsed, "elapsed": round(time.time() - started, 3)}
        except CodeExecutionError as exc:
            return {"ok": False, "action": action, "error": str(exc), "elapsed": round(time.time() - started, 3)}

    return {"ok": False, "action": action, "error": f"未知动作: {action}", "elapsed": round(time.time() - started, 3)}


def register(app):
    @app.route("/template-lab")
    @login_required
    def template_lab():
        modules_dir = app.config["MODULES_DIR"]
        selected = request.args.get("file", "").strip()
        module_files = _module_yaml_files(modules_dir)
        if not selected and module_files:
            selected = module_files[0]["filename"]
        selected_path = _safe_module_path(modules_dir, selected) if selected else ""
        yaml_text = ""
        if selected_path and os.path.exists(selected_path):
            with open(selected_path, "r", encoding="utf-8") as handle:
                yaml_text = handle.read()
        return render_template(
            "template_lab.html",
            module_files=module_files,
            selected=selected,
            yaml_text=yaml_text,
            default_event_type="DOMAIN",
            default_target="example.com",
        )

    @app.route("/template-lab/save", methods=["POST"])
    @login_required
    def template_lab_save():
        modules_dir = app.config["MODULES_DIR"]
        filename = request.form.get("filename", "").strip()
        yaml_text = request.form.get("yaml_text", "")
        result = _validate_yaml_text(yaml_text)
        if not result["ok"]:
            flash(f"YAML 无效，未保存: {result['error']}", "error")
            return redirect(url_for("template_lab", file=filename))
        path = _safe_module_path(modules_dir, filename)
        if not path:
            flash("文件名无效", "error")
            return redirect(url_for("template_lab"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(yaml_text.rstrip() + "\n")
        flash(f"已保存 {filename}", "success")
        return redirect(url_for("template_lab", file=filename))

    @app.route("/template-lab/api/run", methods=["POST"])
    @login_required
    def template_lab_api_run():
        payload = request.get_json(silent=True) or request.form.to_dict()
        action = (payload.get("action") or "validate").strip()
        yaml_text = payload.get("yaml_text") or ""
        event_type = (payload.get("event_type") or "DOMAIN").strip()
        target = (payload.get("target") or "example.com").strip()
        stdout = payload.get("stdout") or ""
        timeout = _to_int(str(payload.get("timeout", "")), 60)
        install_step = _to_int(str(payload.get("install_step", "")), 0)
        config = load_yaml(app.config["CONFIG_PATH"])
        result = _run_template_lab_action(action, yaml_text, event_type, target, stdout, timeout, install_step, config)
        return jsonify(result)
