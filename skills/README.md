# skills/ — AI 技能库目录

FlowScan3 AI 分析 / Agent 会从这里加载技能（Skill）。每个技能一个子目录，目录内放 `SKILL.md`：

```
skills/
└── 示例技能/
    └── SKILL.md
```

## SKILL.md 格式

```markdown
---
description: 一句话描述这个技能做什么
---

# 技能标题

具体操作步骤 / 规则 / 知识……
```

- `description` 会出现在「AI 配置 → Skill 加载」的列表和注入提示词的技能索引里
- 正文（frontmatter 之后的内容）是技能全文

## 使用方式

1. Web 面板 → AI 分析 → AI 配置 → Skill 加载：勾选「启用 Skill 加载」，在列表里勾选要加载的技能
2. 「强制加载技能全文」开关：
   - **关（默认，渐进式）**：提示词只注入技能索引，Agent 需要时按需调用 `load_skill` 获取全文
   - **开**：把已勾选技能的全文直接注入提示词
3. 保存后对下一次 AI 分析 / Agent 会话生效

也可以在 `config.yaml` 的 `skills.dirs` 里追加其他技能目录（支持绝对路径）。
