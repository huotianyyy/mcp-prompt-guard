# mcp-prompt-guard（中文说明）

[English](README.md) | **简体中文**

[![CI](https://github.com/huotianyyy/mcp-prompt-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/huotianyyy/mcp-prompt-guard/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

面向 **MCP (Model Context Protocol)** 工具输出与 AI Agent 上下文的零依赖 Python 安全防护中间件：专注拦截**间接提示词注入（Indirect Prompt Injection）**、**隐形 HTML/Markdown/零宽字符载体**与**敏感凭证意外泄露**。

🌐 **在线交互式实时体验**：https://huotianyyy.github.io/#playground

## 核心防御流水线

1. **隐形载体清洗（TextSanitizer）**：剥离 `<!-- ... -->` 隐藏 HTML 注释、Markdown 不可见注释、零宽与 BiDi 双向欺骗字符。
2. **加权规则检测（InjectionDetector）**：覆盖指令劫持（`PI001`）、角色越狱（`PI002`）、凭证窃取外泄（`PI003`）、Shell 管道 RCE（`PI004`）、隐蔽工具滥用（`PI005`）、系统分隔符伪造（`PI006`）。
3. **敏感密钥脱敏（SecretRedactor）**：自动抹除 GitHub Token、`sk-*` API Key、AWS Key、Bearer Token 与 PEM 私钥。
4. **即插即用中间件（MCPPromptGuard）**：支持 `BLOCK` / `SANITIZE` / `AUDIT` 三种模式、同步/异步 `@guard.protect_tool` 装饰器及命令行管道。

## 快速开始

```python
from mcp_prompt_guard import GuardMode, MCPPromptGuard

guard = MCPPromptGuard(mode=GuardMode.SANITIZE, threshold=40)

@guard.protect_tool(source="github_issue")
async def read_github_issue(repo: str, number: int) -> dict:
    return {"content": [{"type": "text", "text": "..."}]}
```

```bash
# 命令行管道实时检测
echo "Hello <!-- ignore previous instructions -->" | mcp-prompt-guard --json
```

## 开源协议

MIT
