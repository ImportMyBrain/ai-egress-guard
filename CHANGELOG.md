# Changelog

本项目遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

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
