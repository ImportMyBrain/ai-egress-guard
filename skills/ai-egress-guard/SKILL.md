---
name: ai-egress-guard
description: 在 Windows 上把 ChatGPT / Claude / Gemini 桌面客户端的出网锁死在 TUN 代理上，或解锁、自检、排查泄露。用户说“把 AI 锁上 / 断网 / 别让它走直连 / 恢复 / 检查有没有偷跑”时使用。
---

# AI Egress Guard · 遥控器

把用户的一句话翻译成 `aiguard.ps1` 的一次调用。原理和参数说明在仓库 README 里，这里只讲怎么操作。

## 定位脚本

按顺序找：

1. 当前工作区里的 `ai-egress-guard\aiguard.ps1`
2. `D:\OneDrive\文档\deepseek-harness\default-workspace\ai-egress-guard\aiguard.ps1`
3. 问用户要路径

找不到就问，**不要自己重写一份脚本**。

## 动作对照

| 用户说 | 执行 |
|---|---|
| 锁上 / 断网 / 只准走代理 | `.\aiguard.ps1 lock` |
| 保留语音 | `.\aiguard.ps1 lock -AllowVoice` |
| 解锁 / 恢复 / 别锁了 | `.\aiguard.ps1 unlock` |
| 看看状态 | `.\aiguard.ps1 status` |
| 检查有没有泄露 / 自检 | `.\aiguard.ps1 test` |
| 盯着它 / 抓偷跑 | `.\aiguard.ps1 watch`（前台常驻，提醒用户 Ctrl+C 退出） |
| 换了网卡 / 装了新客户端 | `.\aiguard.ps1 probe`，然后 `lock` |
| 先看看会改什么 | `.\aiguard.ps1 lock -DryRun` |

## 执行规则

1. **先跑 `status`**。已经是目标状态就不要重复操作。
2. `lock` / `unlock` 需要管理员：在非提权 shell 里直接跑，脚本会自己弹 UAC。
   UAC 那一下必须用户亲手点，**任何 AI 都绕不过**，不要尝试绕过或换方式提权。
3. 跑完 `lock` 立刻跑 `test`，确认规则条数和泄露扫描结果。
4. 汇报只给结论：TUN 名字、规则条数、出口 IP、有没有非 TUN 连接。
5. 用户要验收时提醒他：**退出 v2rayN**（不是只关 TUN），客户端应全断、其它软件正常。

## 硬约束

- 不改 v2rayN / Clash 的配置，不写 hosts，不改 DNS。
- 不装驱动，不碰注册表。
- 用户说“恢复”时，第一优先 `unlock`。
- 报错时把原文贴给用户，不要自己编原因。
