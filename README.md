# AI Egress Guard · AI 客户端出网保险

让 ChatGPT / Claude / Gemini 桌面客户端**只能走 TUN 代理**。任何绕过代理的直连——不管是客户端自己偷跑，还是 IPv6 旁路、WebRTC 打洞——都会被 Windows 内核直接丢弃。

> **不是“发现直连再断网”，而是“直连这条路根本不存在”。**

```
 ChatGPT.exe / Claude.exe / Gemini 客户端
          │
          │  ① 物理网卡出站 → 内核丢包（kill switch）
          ▼
    TUN 虚拟网卡（v2rayN / sing-box / Clash …）
          │
          │  ② 规则分流 → 代理节点
          ▼
        目标服务器
```

---

## 它解决什么问题

用 TUN 代理时，客户端理论上都该走代理。但实际会漏：

| 泄露路径 | 怎么漏的 | 本工具 |
|---|---|---|
| 客户端绕过 TUN 直连 | 部分客户端绑物理网卡、或用独立网络栈 | ✅ 物理网卡出站全封 |
| WebRTC / STUN | TCP 全走代理，UDP 仍能打洞拿到你的公网 IP | ✅ UDP 全封（可选保留语音） |
| IPv6 旁路 | TUN 只接管 IPv4 时，客户端走 IPv6 直连 | ✅ IPv6 全封 |
| TUN 掉线 | 默认路由切回物理网卡，瞬间裸奔 | ✅ 客户端直接全断 |
| **代理软件自己判 direct** | 包是从 sing-box 进程出去的，客户端侧拦不住 | ⚠️ 只能监控告警 |

最后一条是这套方案**唯一**的缺口，详见下方[已知限制](#已知限制)。

---

## 原理：为什么只写 Block，不写 Allow

Windows 防火墙的规则优先级是 **Block > Allow**。所以“全锁 + 放行代理”这种写法是无效的：

```text
❌  Block: 程序 → 全部
    Allow: 程序 → 127.0.0.1:7890     # 被上面的 Block 压死
```

本工具的做法是**只写 Block、按网卡排除 TUN**：

```text
✅  Block: 程序 → 出站走 WLAN / 以太网 / 蓝牙 …（TUN 不在列表里，天然放行）
```

TUN 网卡不是通过名字写死的，而是靠 **`0.0.0.0/1` + `128.0.0.0/1` 路由**识别——所有 TUN 型代理（v2rayN、sing-box、Clash、WireGuard）都用这个 split-default 技巧，比按名字猜可靠得多。

---

## 支持范围

| 客户端 | 形态 | 支持 |
|---|---|---|
| ChatGPT（微软商店版） | MSIX 包 `OpenAI.Codex` | ✅ 包名规则 + 路径规则双保险，抗版本更新 |
| Claude Desktop | Electron，`%LOCALAPPDATA%\AnthropicClaude\app-*` | ✅ 自动找最新版本目录 |
| Gemini Desktop | 官方暂无 Windows 客户端 | ✅ 第三方壳可写进 `config.json` |
| 自定义客户端 | 任意 exe / MSIX | ✅ `config.json` 里加一条即可 |

系统要求：Windows 10 / 11，Windows PowerShell 5.1 或 PowerShell 7，仅支持 TUN 模式代理。

---

## 快速开始

```powershell
# 1. 确认 v2rayN 已开 TUN 模式，然后探测环境
.\aiguard.ps1 probe

# 2. 上锁（会自动弹 UAC 请求管理员权限）
.\aiguard.ps1 lock

# 3. 自检
.\aiguard.ps1 test
```

`probe` 会生成 `config.json`，里面是探测到的客户端、TUN 网卡和物理网卡清单。**换机器、装新客户端、换代理软件之后重跑一次 `probe`。**

### 验收标准

**手动关掉 v2rayN 的 TUN**：三个客户端应该立刻全部连不上，微信/浏览器等其它程序照常。过了这一条，说明锁死了。

---

## 命令

| 命令 | 说明 |
|---|---|
| `probe` | 探测 TUN / 物理网卡 / 客户端，写 `config.json` |
| `lock` | 上锁，自动请求管理员权限 |
| `unlock` | 解锁，删掉所有 `AIGuard` 组规则 |
| `watch` | 常驻监控：发现非 TUN 连接、规则被清掉 |
| `test` | 自检：TUN / 规则 / 出口 IP / 实时泄露扫描 |
| `status` | 当前状态 |

### 开关

```powershell
.\aiguard.ps1 lock -AllowVoice    # 保留 ChatGPT 语音：UDP 只封物理网卡
.\aiguard.ps1 lock -DryRun        # 只打印要执行的命令，不动防火墙
.\aiguard.ps1 watch -Interval 2   # 2 秒一轮监控
```

---

## 已知限制

1. **代理软件自己判 direct 的口子堵不上。**
   如果 v2rayN 把某个 AI 域名的路由判成 `direct`，包是从 sing-box 进程出去的，客户端侧怎么封都没用。本工具能做的只有 `watch` 监控告警。
   v2rayN 默认规则是 `geosite:cn → direct`、其余 → proxy，AI 域名不在 CN 清单里，所以正常情况下不会命中。真要彻底堵死，需要改代理软件的分流规则。

2. **UDP 一刀切会让 ChatGPT 语音模式失效。**
   语音走 WebRTC 实时通话，需要 UDP。想保留语音用 `-AllowVoice`，但那样 WebRTC 会走 TUN 代理，安全等级下降一档。

3. **网卡清单是上锁时的快照。**
   中途插网卡、开热点、连 VPN 之后，需要重新 `lock`。`watch` 会提示，但不会自动改规则。

4. **只覆盖本机流量。**
   虚拟机、WSL、手机热点共享不在范围内。

5. **规则需要管理员权限。**
   Windows 防火墙的写入必须提权，这是系统限制。

---

## 常见问题

**Q：上锁后客户端直接打不开了？**
先看 TUN 是否开着：`.\aiguard.ps1 status`。TUN 没开时客户端本来就该全断，这是设计目标。要临时恢复：`.\aiguard.ps1 unlock`。

**Q：客户端更新后规则失效？**
MSIX 客户端的包名规则不受影响；Electron 版路径变了重跑 `probe` + `lock` 即可。

**Q：怎么彻底卸载？**
```powershell
.\aiguard.ps1 unlock
Remove-Item "$env:LOCALAPPDATA\AIGuard" -Recurse -Force
```
不会留下别的痕迹：工具不改 hosts、不改 DNS、不改注册表。

**Q：会被杀毒误报吗？**
不会。整个工具只调用 Windows 自带防火墙和网络命令，不加载驱动、不注入进程、不联网（`test` 的出口 IP 查询除外）。

---

## 安全与隐私

- 不联网、不上传任何数据；唯一的外部请求是 `test` 里查询出口 IP。
- 只操作 `Group = AIGuard` 的防火墙规则，不碰系统其它规则。
- 所有改动都可以 `unlock` 一键还原。
- 日志写在 `%LOCALAPPDATA%\AIGuard\aiguard.log`，不含敏感内容。

---

## License

MIT
