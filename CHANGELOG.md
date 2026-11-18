# Changelog

本项目遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [1.0.1] - 2026-11-18

### 修复

- **严重**：`-PackageFamilyName` 在 Windows 11 build 26200 上会静默生成**没有作用域**的规则（`Program: Any`、`Package: 空`），等价于全系统禁止走物理网卡 / 禁止 UDP / 禁止 IPv6，会误伤微信等无关程序。现在不再使用包名规则，只按 exe 路径建规则。
- 新增建后校验：每条规则创建后立即检查作用域，作用域为空则自动删除并报错。
- `test` 增加作用域检查，发现无作用域规则会红字告警。

### 变更

- 目标客户端必须有 exe 路径；只有包名没有路径的会被跳过并提示。

## [1.0.0] - 2026-11-17

首个版本。

### 新增

- 六个命令：`probe` / `lock` / `unlock` / `watch` / `test` / `status`
- 三道锁：
  - 物理网卡出站封禁（按网卡别名排除 TUN，绕开防火墙 Block > Allow 的优先级坑）
  - UDP 封禁，堵死 WebRTC / STUN 泄露公网 IP
  - IPv6 封禁（`::/1` + `8000::/1` 两段覆盖全部地址空间）
- MSIX 客户端按包名 + exe 路径双规则，抗客户端更新
- `-AllowVoice`：UDP 只封物理网卡，保留 ChatGPT 语音
- `-DryRun`：只打印将要执行的防火墙命令
- Agent Skill 遥控器（`skills/ai-egress-guard/SKILL.md`），DSH / Claude 可直接操作

### 已验证

- Windows 11 build 26200 + v2rayN TUN（TUN 网卡 `172.19.0.0/24`）
- `lock` 创建 6 条规则全部成功，`unlock` 清理干净
- 防火墙 API 在 `-Protocol Any` 时拒绝 `-RemoteAddress '::/0'`，改用两段 `/1` 前缀绕过

### 已知限制

- 不改代理软件的分流配置时，它自己把流量判成 `direct` 的口子堵不上，只能监控告警
- UDP 全禁会让 ChatGPT 语音模式失效
- 网卡清单是上锁时的快照，换网卡后需要重新 `lock`
