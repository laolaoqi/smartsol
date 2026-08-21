<p align="center">
  <img src="https://img.shields.io/badge/Smart%20Contract%20Audit-AI%20Powered-4a00e0" />
  <img src="https://img.shields.io/badge/status-beta-blueviolet" />
  <img src="https://img.shields.io/badge/license-MIT-green" />
  <img src="https://img.shields.io/github/stars/laolaoqi/smartsol" />
</p>

<h1 align="center">🔒 Smartsol</h1>
<p align="center"><b>AI-powered smart contract audit in one command.<br/>从 Slither 的噪音里，抽出真正能利用的漏洞。</b></p>

---

## 为什么要有它？

跑过 `slither` 的人都知道：**它报 11 条，10 条是误报**。海量的 Low severity、不可利用的模式、以及把 `immutable` 变量判成问题的噪音，让开发者没法用。

Smartsol 用 **LLM 理解合约上下文**，把 Slither 的原始发现做三件事：

1. **消噪** —— 过滤掉上下文里不可利用的误报
2. **分级** —— 按真实可利用性重新排序（Critical / High / Medium / Low）
3. **给答案** —— 每条真实漏洞附带**利用路径** + **具体修复方案**

---

## 一拍即用

```bash
# 安装依赖
pip install slither-analyzer
# 需要 Foundry (forge) 编译 Solidity 0.8.19+ 项目

# AI 消噪需要 LLM key（兼容 OpenAI 协议，可用 DeepSeek）
export SMARTSOL_API_KEY=sk-...   # 或 DEEPSEEK_API_KEY

# 扫描一个合约或整个目录
python3 smartsol.py scan demos/
# → 输出人类可读的 Markdown 审计报告

# 输出 JSON（给 CI / 脚本消费）
python3 smartsol.py scan demos/ --json
```

**没有 key 也能用**：未设置 `SMARTSOL_API_KEY` 时，工具只跑 Slither 原始扫描（跳过 AI 消噪），仍返回全部 findings。

## 真实输出

对 `demos/`（故意包含典型漏洞的示例合约）：

```
▶ Slither scanning demos ...
  Slither: 11 raw findings
▶ AI triage with deepseek-chat ...
✅ report written

Summaries:
  🔴 Critical  1  = Reentrancy in ReentrancyVault.withdraw
  🟠 High      1  = Uninitialized token (DoS)
  🟡 Medium    2  = Unchecked low-level call; Reentrancy in batch loop
  🔵 Low       5  = code-quality items
  ⚪ Filtered  2  = false positives removed
```

完整报告见 **[examples/ReentrancyVault-report.md](examples/ReentrancyVault-report.md)** —— 里面每条漏洞都有利用路径和修复代码。

---

## 命令行

```
smartsol scan <dir_or_sol> [--json] [--out FILE] [--model MODEL] [--no-slither]
smartsol version
```

| 参数 | 说明 |
|------|------|
| `--json` | 只输出 JSON 漏洞数组（供 CI） |
| `--out FILE` | 报告写入文件 |
| `--model` | 指定 LLM 模型（默认 deepseek-chat，兼容 OpenAI 协议） |
| `--no-slither` | 跳过 Slither（仅调试） |

---

## 它怎么工作

```
┌─────────┐   ┌────────────┐   ┌────────────────┐   ┌──────────┐
│  .sol    │──▶│  Slither   │──▶│  LLM triage    │──▶│  Report  │
│  code    │   │ (11 finds) │   │ (context-aware)│   │ (ranked) │
└─────────┘   └────────────┘   └────────────────┘   └──────────┘
```

1. **Slither** 静态扫描目标，产出原始 findings（含误报）
2. **上下文抽取**：定位每条 finding 附近的源码行，构建"代码片段 + finding"组合
3. **LLM 判读**：理解合约逻辑，判断每条是否可真利用，给出严重性、利用路径、修复
4. **报告**：过滤误报，按严重性排序输出

LLM 提示词约束它**只返回结构化 JSON**，结果稳定可解析。

---

## CI 集成（GitHub Action）

把 AI 审计直接接进你的 PR 流程，提交 `.sol` 的 PR 自动触发审计：

```yaml
# .github/workflows/audit.yml
name: Smartsol Audit
on:
  pull_request:
    paths: ['**/*.sol']
  workflow_dispatch:
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { submodules: recursive }
      - uses: foundry-rs/foundry-toolchain@v1
      - run: pip install slither-analyzer && pip install -r requirements.txt
        env:
          SMARTSOL_API_KEY: ${{ secrets.SMARTSOL_API_KEY }}
      - run: python3 smartsol.py scan ./contracts --json > report.json
```

完整示例在 [`.github/workflows/audit.yml`](.github/workflows/audit.yml)。仓库设置里加一个 `SMARTSOL_API_KEY` secret 即可。

---

## Demo 合约（自包含，无外部依赖）

`demos/` 里的合约故意包含真实漏洞，作为工具的自测套件：

- **ReentrancyVault.sol** — 经典重入（CEI 违背）
- **UncheckedArithmetic.sol** — 下溢/回绕
- **BatchPayout.sol** — 未检查的低层 call + 批量支付重入

这些合约**故意不能安全部署**，仅用于演示工具能力。

---

## 路线图

- [x] v0.1：Slither + LLM 消噪分级
- [ ] v0.2：多文件逐 contract 报告 + PDF 导出
- [ ] v0.3：Web UI（拖拽上传 .sol 即出报告）
- [ ] v0.4：GitHub Action（PR 自动审计）

---

## License

MIT — 自由使用。运行本工具处理真实合约前，请自行评估风险；工具**不保证无遗漏**，正式审计仍需人工复核。

**Built by laolaoqi. Powered by DeepSeek.**
