<#
.SYNOPSIS
  AI Egress Guard — 让 ChatGPT / Claude / Gemini 桌面客户端只能走 TUN 代理。

.DESCRIPTION
  给目标客户端加三道锁，任何绕过代理的直连都会被 Windows 内核丢弃：

    1) 网卡锁：出站流量只允许从 TUN 虚拟网卡出去
    2) UDP 锁：堵死 WebRTC / STUN，网站拿不到你的公网 IP 和内网 IP
    3) IPv6 锁：堵死 IPv6 直连绕过

  只写 Block 规则、不写 Allow 规则 —— Windows 防火墙里 block 的优先级高于 allow，
  "全锁 + 放行代理"那种写法是无效的；按网卡别名排除 TUN 才能做到真正的白名单。

  锁上之后：TUN 一断，客户端立刻全断（这就是 kill switch 的验收标准）。

.PARAMETER Command
  probe   探测环境，生成 config.json
  lock    上锁（需要管理员权限，会自动请求提权）
  unlock  解锁（需要管理员权限）
  watch   常驻监控：非 TUN 连接、规则漂移
  test    自检：TUN / 规则 / 出口 IP / 实时泄露扫描
  status  查看当前状态
  help    显示帮助

.PARAMETER AllowVoice
  lock 时不要一刀切封 UDP，只封物理网卡上的 UDP。
  这样 ChatGPT 语音（WebRTC）还能走 TUN 代理，但安全等级下降一档。

.PARAMETER DryRun
  只打印将执行的命令，不真正改防火墙。

.EXAMPLE
  .\aiguard.ps1 probe
  .\aiguard.ps1 lock
  .\aiguard.ps1 test

.NOTES
  Windows 10/11，Windows PowerShell 5.1 或 PowerShell 7。
  只操作本机 Windows 防火墙里 Group 为 AIGuard 的规则，不联网、不收集数据。
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Command = 'help',

    [switch]$AllowVoice,
    [switch]$DryRun,
    [switch]$Json,
    [int]$Interval = 0,
    [string]$ConfigPath
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- 全局常量

$script:Group = 'AIGuard'
if ($PSScriptRoot) {
    $script:Root = $PSScriptRoot
} else {
    $script:Root = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ($ConfigPath) {
    $script:ConfigPath = $ConfigPath
} else {
    $script:ConfigPath = Join-Path $script:Root 'config.json'
}
$script:StateDir = Join-Path $env:LOCALAPPDATA 'AIGuard'
if (-not (Test-Path -LiteralPath $script:StateDir)) {
    New-Item -ItemType Directory -Path $script:StateDir -Force | Out-Null
}
$script:LogFile = Join-Path $script:StateDir 'aiguard.log'
$script:StateFile = Join-Path $script:StateDir 'state.json'

# ---------------------------------------------------------------- 基础输出

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 } catch { }
    switch ($Level) {
        'OK'    { Write-Host $line -ForegroundColor Green }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line -ForegroundColor Gray }
    }
}

function Write-Head {
    param([string]$Text)
    Write-Host ''
    Write-Host "== $Text ==" -ForegroundColor Cyan
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-Elevation {
    param([string]$Arguments)
    $exe = (Get-Process -Id $PID).Path
    $argList = @('-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath)) + $Arguments.Split(' ')
    try {
        Start-Process -FilePath $exe -ArgumentList $argList -Verb RunAs | Out-Null
        Write-Host '已请求管理员权限，请在新窗口里确认。' -ForegroundColor Yellow
    } catch {
        Write-Host '提权失败或被取消。请右键“以管理员身份运行”。' -ForegroundColor Red
    }
}

# ---------------------------------------------------------------- 环境探测

function Get-TunInterfaces {
    $indexes = New-Object System.Collections.Generic.List[int]
    foreach ($prefix in @('0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1')) {
        try {
            $routes = Get-NetRoute -DestinationPrefix $prefix -ErrorAction Stop
        } catch {
            $routes = @()
        }
        foreach ($route in $routes) {
            $idx = [int]$route.InterfaceIndex
            if (-not $indexes.Contains($idx)) { $indexes.Add($idx) }
        }
    }

    if ($indexes.Count -eq 0) {
        $candidates = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
            $_.Status -eq 'Up' -and (
                $_.InterfaceDescription -match 'tun|tap|wintun|sing-box|wireguard' -or
                $_.Name -match 'tun|tap|velo|sing-box|proxy'
            )
        }
        foreach ($adapter in $candidates) {
            $idx = [int]$adapter.InterfaceIndex
            if (-not $indexes.Contains($idx)) { $indexes.Add($idx) }
        }
    }

    $result = @()
    foreach ($idx in $indexes) {
        $adapter = Get-NetAdapter -InterfaceIndex $idx -ErrorAction SilentlyContinue
        if (-not $adapter) { continue }
        $addresses = @(Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike '169.254.*' })
        $result += [pscustomobject]@{
            IfIndex     = $idx
            Name        = $adapter.Name
            Description = $adapter.InterfaceDescription
            Status      = $adapter.Status
            Addresses   = $addresses
        }
    }
    return $result
}

function Get-PhysicalAdapters {
    param([int[]]$ExcludeIndex = @())
    return Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -notmatch 'Loopback' -and
        $_.Status -ne 'Disabled' -and
        ($ExcludeIndex -notcontains [int]$_.InterfaceIndex)
    }
}

function Get-IPv4Prefix {
    param([string]$Address, [int]$Length)
    $parts = $Address.Split('.')
    if ($parts.Count -ne 4) { return $null }
    $full = [math]::Floor($Length / 8)
    if ($full -le 0) { return '' }
    if ($full -ge 4) { return $Address }
    return (($parts[0..($full - 1)] -join '.')) + '.'
}

function Test-TunAddress {
    param([string]$Address, $Tun)
    if (-not $Address) { return $false }
    if ($Address -eq '::1') { return $true }
    if ($Address -like '127.*') { return $true }
    foreach ($tunItem in $Tun) {
        foreach ($addr in $tunItem.Addresses) {
            $prefix = Get-IPv4Prefix -Address $addr.IPAddress -Length $addr.PrefixLength
            if ($prefix -and $Address.StartsWith($prefix)) { return $true }
        }
    }
    return $false
}

# ---------------------------------------------------------------- 客户端发现

function Find-Targets {
    $found = New-Object System.Collections.ArrayList

    # ChatGPT：微软商店版 / MSIX 包
    $allPackages = @(Get-AppxPackage -ErrorAction SilentlyContinue)
    $pkg = $allPackages | Where-Object { $_.Name -eq 'OpenAI.Codex' } | Select-Object -First 1
    if (-not $pkg) {
        $pkg = $allPackages | Where-Object { $_.Name -match 'ChatGPT' } | Select-Object -First 1
    }
    if (-not $pkg) {
        $pkg = $allPackages | Where-Object { $_.Name -match '^OpenAI\.' -and $_.Name -notmatch 'Runtime|Bundle' } | Select-Object -First 1
    }
    if ($pkg) {
        $exe = Join-Path $pkg.InstallLocation 'app\ChatGPT.exe'
        if (-not (Test-Path -LiteralPath $exe)) {
            $hit = Get-ChildItem -LiteralPath $pkg.InstallLocation -Filter 'ChatGPT.exe' -Recurse -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if ($hit) { $exe = $hit.FullName } else { $exe = $null }
        }
        if (-not $exe) {
            $running = Get-Process -Name 'ChatGPT' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($running -and $running.Path) { $exe = $running.Path }
        }
        [void]$found.Add([pscustomobject]@{
            key     = 'chatgpt'
            name    = 'ChatGPT'
            kind    = 'msix'
            package = $pkg.PackageFamilyName
            exe     = $exe
            process = 'ChatGPT'
        })
    }

    # Claude Desktop（Electron，版本目录会变）
    $claudeExe = $null
    $claudeDir = Join-Path $env:LOCALAPPDATA 'AnthropicClaude'
    if (Test-Path -LiteralPath $claudeDir) {
        $appDir = Get-ChildItem -LiteralPath $claudeDir -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'app-*' } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        if ($appDir) {
            $candidate = Join-Path $appDir.FullName 'Claude.exe'
            if (Test-Path -LiteralPath $candidate) { $claudeExe = $candidate }
        }
    }
    if (-not $claudeExe) {
        foreach ($candidate in @(
            (Join-Path $env:LOCALAPPDATA 'Programs\Claude\Claude.exe'),
            (Join-Path $env:ProgramFiles 'Claude\Claude.exe')
        )) {
            if ($candidate -and (Test-Path -LiteralPath $candidate)) { $claudeExe = $candidate; break }
        }
    }
    if ($claudeExe) {
        [void]$found.Add([pscustomobject]@{
            key     = 'claude'
            name    = 'Claude'
            kind    = 'exe'
            package = $null
            exe     = $claudeExe
            process = 'Claude'
        })
    }

    # Gemini：官方目前没有 Windows 客户端，这里是给第三方壳 / 未来版本留的口子
    $geminiPkg = Get-AppxPackage -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'Gemini' } |
        Select-Object -First 1
    $geminiExe = $null
    if ($geminiPkg) {
        $hit = Get-ChildItem -LiteralPath $geminiPkg.InstallLocation -Filter 'Gemini.exe' -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($hit) { $geminiExe = $hit.FullName }
    }
    if (-not $geminiExe) {
        foreach ($candidate in @(
            (Join-Path $env:LOCALAPPDATA 'Programs\Gemini\Gemini.exe'),
            (Join-Path $env:ProgramFiles 'Gemini\Gemini.exe')
        )) {
            if ($candidate -and (Test-Path -LiteralPath $candidate)) { $geminiExe = $candidate; break }
        }
    }
    if ($geminiPkg -or $geminiExe) {
        [void]$found.Add([pscustomobject]@{
            key     = 'gemini'
            name    = 'Gemini'
            kind    = $(if ($geminiPkg) { 'msix' } else { 'exe' })
            package = $(if ($geminiPkg) { $geminiPkg.PackageFamilyName } else { $null })
            exe     = $geminiExe
            process = 'Gemini'
        })
    }

    return $found.ToArray()
}

function Get-TargetList {
    param($Config)

    $list = New-Object System.Collections.ArrayList
    foreach ($item in @(Find-Targets)) { [void]$list.Add($item) }

    if ($Config -and $Config.targets) {
        foreach ($t in @($Config.targets)) {
            if (-not $t) { continue }
            $key = $t.key
            if (-not $key -and $t.name) { $key = ($t.name -replace '[^A-Za-z0-9]', '').ToLower() }
            if (-not $key) { continue }

            $existing = $list | Where-Object { $_.key -eq $key } | Select-Object -First 1
            if ($existing) {
                # 默认以自动探测结果为准，config 只补空；写了 "override": true 才强制覆盖
                if ($t.override) {
                    if ($t.exe)     { $existing.exe = $t.exe }
                    if ($t.package) { $existing.package = $t.package }
                    if ($t.process) { $existing.process = $t.process }
                    if ($t.name)    { $existing.name = $t.name }
                } else {
                    if (-not $existing.exe -and $t.exe)         { $existing.exe = $t.exe }
                    if (-not $existing.package -and $t.package) { $existing.package = $t.package }
                    if (-not $existing.process -and $t.process) { $existing.process = $t.process }
                    if (-not $existing.name -and $t.name)       { $existing.name = $t.name }
                }
            } else {
                $exePath = $t.exe
                $procName = $t.process
                if (-not $procName -and $exePath) {
                    $procName = [IO.Path]::GetFileNameWithoutExtension($exePath)
                }
                [void]$list.Add([pscustomobject]@{
                    key     = $key
                    name    = $(if ($t.name) { $t.name } else { $key })
                    kind    = $(if ($t.package) { 'msix' } else { 'exe' })
                    package = $t.package
                    exe     = $exePath
                    process = $procName
                })
            }
        }
    }

    return $list.ToArray()
}

# ---------------------------------------------------------------- 配置

function Get-DefaultConfig {
    return [ordered]@{
        lockPhysical         = $true
        blockUdp             = $true
        blockIpv6            = $true
        watchIntervalSeconds = 3
        targets              = @()
    }
}

function Get-Config {
    $cfg = Get-DefaultConfig
    if (Test-Path -LiteralPath $script:ConfigPath) {
        try {
            $raw = Get-Content -Path $script:ConfigPath -Raw -Encoding UTF8
            $data = $raw | ConvertFrom-Json
            foreach ($key in @('lockPhysical', 'blockUdp', 'blockIpv6', 'watchIntervalSeconds')) {
                if ($null -ne $data.$key) { $cfg[$key] = $data.$key }
            }
            if ($data.targets) { $cfg['targets'] = @($data.targets) }
        } catch {
            Write-Host "config.json 读取失败，使用默认配置：$($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    return $cfg
}

function Save-Config {
    param($Config)
    $Config | ConvertTo-Json -Depth 8 | Set-Content -Path $script:ConfigPath -Encoding UTF8
}

# ---------------------------------------------------------------- 泄露扫描

function Get-LeakConnections {
    param($Targets, $Tun)

    $names = @($Targets | ForEach-Object { $_.process } | Where-Object { $_ } | Sort-Object -Unique)
    $hits = @()
    foreach ($name in $names) {
        $procs = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
        foreach ($proc in $procs) {
            $conns = @(Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue)
            foreach ($conn in $conns) {
                if (-not $conn.RemoteAddress) { continue }
                if ($conn.RemoteAddress -eq '0.0.0.0' -or $conn.RemoteAddress -eq '::') { continue }
                if (Test-TunAddress -Address $conn.LocalAddress -Tun $Tun) { continue }
                $hits += [pscustomobject]@{
                    Process = $proc.ProcessName
                    PID     = $proc.Id
                    Local   = ('{0}:{1}' -f $conn.LocalAddress, $conn.LocalPort)
                    Remote  = ('{0}:{1}' -f $conn.RemoteAddress, $conn.RemotePort)
                    State   = $conn.State
                }
            }
        }
    }
    return $hits
}

# ---------------------------------------------------------------- 规则

function Format-RuleCommand {
    param([hashtable]$Params)
    $parts = foreach ($key in ($Params.Keys | Sort-Object)) {
        $value = $Params[$key]
        if ($value -is [array]) { $value = ($value -join ',') }
        ('-{0} "{1}"' -f $key, $value)
    }
    return 'New-NetFirewallRule ' + ($parts -join ' ')
}

function New-GuardRule {
    param(
        [pscustomobject]$Target,
        [string]$Suffix,
        [hashtable]$Extra,
        [bool]$Preview = $false
    )

    $display = 'AIGuard - {0} - {1}' -f $Target.name, $Suffix
    $params = @{
        DisplayName = $display
        Group       = $script:Group
        Direction   = 'Outbound'
        Action      = 'Block'
        Profile     = 'Any'
        Enabled     = 'True'
        Description = 'AI Egress Guard: only TUN egress allowed'
    }
    # 作用域（Program / PackageFamilyName）由调用方通过 Extra 传入，避免同时出现两个
    if (-not ($Extra.ContainsKey('Program') -or $Extra.ContainsKey('PackageFamilyName'))) {
        if ($Target.package) {
            $params['PackageFamilyName'] = $Target.package
        } else {
            $params['Program'] = $Target.exe
        }
    }
    foreach ($key in $Extra.Keys) { $params[$key] = $Extra[$key] }

    if ($Preview) {
        Write-Host ('  ' + (Format-RuleCommand -Params $params)) -ForegroundColor DarkGray
        return
    }
    New-NetFirewallRule @params | Out-Null
}

function Get-GuardRulePlan {
    param($Targets, [string[]]$Aliases, $Config)

    $plan = New-Object System.Collections.ArrayList
    foreach ($t in $Targets) {
        $scopes = @()
        if ($t.package) { $scopes += @{ kind = 'pkg'; params = @{ PackageFamilyName = $t.package } } }
        if ($t.exe)     { $scopes += @{ kind = 'exe'; params = @{ Program = $t.exe } } }

        foreach ($scope in $scopes) {
            $tag = $(if ($scope.kind -eq 'pkg') { 'pkg' } else { 'exe' })

            if ($Config.lockPhysical) {
                $extra = @{}
                foreach ($k in $scope.params.Keys) { $extra[$k] = $scope.params[$k] }
                $extra['InterfaceAlias'] = $Aliases
                [void]$plan.Add([pscustomobject]@{ Target = $t; Suffix = ('{0}-physical' -f $tag); Extra = $extra })
            }

            if ($Config.blockUdp) {
                $extra = @{}
                foreach ($k in $scope.params.Keys) { $extra[$k] = $scope.params[$k] }
                $extra['Protocol'] = 'UDP'
                if ($AllowVoice) { $extra['InterfaceAlias'] = $Aliases }
                $suffix = $(if ($AllowVoice) { '{0}-udp-physical' -f $tag } else { '{0}-udp' -f $tag })
                [void]$plan.Add([pscustomobject]@{ Target = $t; Suffix = $suffix; Extra = $extra })
            }

            if ($Config.blockIpv6) {
                $extra = @{}
                foreach ($k in $scope.params.Keys) { $extra[$k] = $scope.params[$k] }
                # 防火墙不接受 Protocol=Any 时的 "::/0"，用两段 /1 覆盖整个 IPv6 空间
                $extra['RemoteAddress'] = @('::/1', '8000::/1')
                [void]$plan.Add([pscustomobject]@{ Target = $t; Suffix = ('{0}-ipv6' -f $tag); Extra = $extra })
            }
        }
    }
    return $plan.ToArray()
}

# ---------------------------------------------------------------- 命令：probe

function Invoke-Probe {
    $config = Get-Config
    $tun = @(Get-TunInterfaces)
    $tunIndexes = @($tun | ForEach-Object { [int]$_.IfIndex })
    $physical = @(Get-PhysicalAdapters -ExcludeIndex $tunIndexes)
    $targets = @(Get-TargetList -Config $config)

    if ($Json) {
        [pscustomobject]@{
            tun       = $tun
            physical  = $physical | Select-Object IfIndex, Name, InterfaceDescription, Status
            targets   = $targets
            config    = $config
        } | ConvertTo-Json -Depth 8
        return
    }

    Write-Head 'TUN 虚拟网卡'
    if ($tun.Count -eq 0) {
        Write-Host '  没找到。先把 v2rayN 切到 TUN 模式。' -ForegroundColor Yellow
    } else {
        foreach ($item in $tun) {
            Write-Host ('  {0}  [{1}]  {2}' -f $item.Name, $item.Description, $item.Status) -ForegroundColor Green
            foreach ($addr in $item.Addresses) {
                Write-Host ('       {0}/{1}' -f $addr.IPAddress, $addr.PrefixLength) -ForegroundColor DarkGray
            }
        }
    }

    Write-Head '物理网卡（outbound 将被封）'
    if ($physical.Count -eq 0) {
        Write-Host '  没找到物理网卡。' -ForegroundColor Yellow
    } else {
        foreach ($item in $physical) {
            Write-Host ('  {0}  {1}  [{2}]' -f $item.Name, $item.InterfaceDescription, $item.Status) -ForegroundColor Gray
        }
    }

    Write-Head '目标客户端'
    if ($targets.Count -eq 0) {
        Write-Host '  没发现任何目标客户端。' -ForegroundColor Yellow
    } else {
        foreach ($item in $targets) {
            Write-Host ('  {0,-8} {1,-6} {2}' -f $item.name, $item.kind, $item.exe) -ForegroundColor Green
            if ($item.package) {
                Write-Host ('           package: {0}' -f $item.package) -ForegroundColor DarkGray
            }
        }
    }
    if (-not ($targets | Where-Object { $_.key -eq 'claude' })) {
        Write-Host '  提示：没找到 Claude 客户端。装了以后再跑一次 probe。' -ForegroundColor DarkGray
    }
    if (-not ($targets | Where-Object { $_.key -eq 'gemini' })) {
        Write-Host '  提示：没找到 Gemini 客户端。官方目前没有 Windows 版，第三方壳可以写进 config.json。' -ForegroundColor DarkGray
    }

    $config['targets'] = @($targets)
    Save-Config -Config $config
    Write-Host ''
    Write-Host ('配置已写入 {0}' -f $script:ConfigPath) -ForegroundColor Green
}

# ---------------------------------------------------------------- 命令：lock

function Invoke-Lock {
    if (-not $DryRun -and -not (Test-Admin)) {
        Request-Elevation -Arguments $(if ($AllowVoice) { 'lock -AllowVoice' } else { 'lock' })
        return
    }

    $config = Get-Config
    $targets = @(Get-TargetList -Config $config | Where-Object { $_.exe -or $_.package })
    if ($targets.Count -eq 0) {
        throw '没找到任何目标客户端。先跑 probe。'
    }

    $tun = @(Get-TunInterfaces)
    if ($tun.Count -eq 0) {
        throw '没找到 TUN 虚拟网卡（0.0.0.0/1 + 128.0.0.0/1 路由）。请先打开 v2rayN 的 TUN 模式。'
    }

    $tunIndexes = @($tun | ForEach-Object { [int]$_.IfIndex })
    $physical = @(Get-PhysicalAdapters -ExcludeIndex $tunIndexes)
    $aliases = @($physical | ForEach-Object { $_.Name })
    if ($aliases.Count -eq 0) {
        throw '没找到物理网卡，不敢上锁。'
    }

    Write-Host ''
    Write-Host ('TUN:      {0}' -f (($tun | ForEach-Object { $_.Name }) -join ', ')) -ForegroundColor Green
    Write-Host ('封禁网卡: {0}' -f ($aliases -join ', ')) -ForegroundColor Gray
    Write-Host ('目标:     {0}' -f (($targets | ForEach-Object { $_.name }) -join ', ')) -ForegroundColor Gray
    Write-Host ''

    $plan = @(Get-GuardRulePlan -Targets $targets -Aliases $aliases -Config $config)

    if (-not $DryRun) {
        Get-NetFirewallRule -Group $script:Group -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue
    }

    $created = 0
    $failed = @()
    foreach ($item in $plan) {
        if ($DryRun) {
            New-GuardRule -Target $item.Target -Suffix $item.Suffix -Extra $item.Extra -Preview $true
            $created++
            continue
        }
        try {
            New-GuardRule -Target $item.Target -Suffix $item.Suffix -Extra $item.Extra
            $created++
        } catch {
            $failed += ('{0}: {1}' -f $item.Suffix, $_.Exception.Message)
        }
    }

    if ($DryRun) {
        Write-Host ''
        Write-Host ('（预演）将创建 {0} 条规则，未做任何修改。' -f $created) -ForegroundColor Yellow
        return
    }

    $state = [pscustomobject]@{
        appliedAt  = (Get-Date).ToString('s')
        aliases    = $aliases
        tun        = @($tun | ForEach-Object { $_.Name })
        targets    = @($targets | ForEach-Object { $_.key })
        allowVoice = [bool]$AllowVoice
    }
    $state | ConvertTo-Json -Depth 5 | Set-Content -Path $script:StateFile -Encoding UTF8

    Write-Host ''
    Write-Host ('已上锁：{0} 条规则成功。' -f $created) -ForegroundColor Green
    if ($failed.Count -gt 0) {
        Write-Host ('{0} 条规则创建失败：' -f $failed.Count) -ForegroundColor Red
        $failed | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor Red }
    }
    Write-Host '下一步：.\aiguard.ps1 test' -ForegroundColor DarkGray
    Write-Host '验收：关掉 v2rayN 的 TUN，客户端应该立刻全部连不上。' -ForegroundColor DarkGray
}

# ---------------------------------------------------------------- 命令：unlock

function Invoke-Unlock {
    if (-not $DryRun -and -not (Test-Admin)) {
        Request-Elevation -Arguments 'unlock'
        return
    }

    $rules = @(Get-NetFirewallRule -Group $script:Group -ErrorAction SilentlyContinue)
    if ($rules.Count -eq 0) {
        Write-Host '没有需要清理的 AIGuard 规则。' -ForegroundColor Yellow
        return
    }

    if ($DryRun) {
        $rules | ForEach-Object { Write-Host ('  将删除: {0}' -f $_.DisplayName) -ForegroundColor DarkGray }
        Write-Host ('（预演）共 {0} 条，未做任何修改。' -f $rules.Count) -ForegroundColor Yellow
        return
    }

    $rules | Remove-NetFirewallRule
    if (Test-Path -LiteralPath $script:StateFile) { Remove-Item -LiteralPath $script:StateFile -Force }

    Write-Host ('已删除 {0} 条规则，客户端恢复直连能力。' -f $rules.Count) -ForegroundColor Green
}

# ---------------------------------------------------------------- 命令：watch

function Invoke-Watch {
    $config = Get-Config
    $sleep = $(if ($Interval -gt 0) { $Interval } else { [int]$config.watchIntervalSeconds })
    if ($sleep -lt 1) { $sleep = 3 }
    $targets = @(Get-TargetList -Config $config)
    $expectedRules = 0

    Write-Host ('监控中（每 {0} 秒），Ctrl+C 退出。日志：{1}' -f $sleep, $script:LogFile) -ForegroundColor Cyan
    $lastAlert = @{}

    while ($true) {
        $tun = @(Get-TunInterfaces)
        if ($tun.Count -eq 0) {
            Write-Log 'TUN 不在了，客户端现在应该全部连不上。' 'WARN'
        }

        $hits = @(Get-LeakConnections -Targets $targets -Tun $tun)
        foreach ($hit in $hits) {
            $key = '{0}|{1}' -f $hit.Process, $hit.Remote
            if ($lastAlert.ContainsKey($key)) {
                $elapsed = ((Get-Date) - $lastAlert[$key]).TotalSeconds
                if ($elapsed -lt 30) { continue }
            }
            $lastAlert[$key] = Get-Date
            Write-Log ('疑似绕过 TUN 的直连：{0} [{1}] {2} -> {3} ({4})' -f $hit.Process, $hit.PID, $hit.Local, $hit.Remote, $hit.State) 'WARN'
        }

        $rules = @(Get-NetFirewallRule -Group $script:Group -ErrorAction SilentlyContinue)
        if ($rules.Count -eq 0) {
            Write-Log 'AIGuard 防火墙规则不见了（系统重置或被别的安全软件清掉了）。' 'ERROR'
        } elseif ($expectedRules -eq 0) {
            $expectedRules = $rules.Count
        }

        Start-Sleep -Seconds $sleep
    }
}

# ---------------------------------------------------------------- 命令：test

function Invoke-Test {
    $config = Get-Config
    $tun = @(Get-TunInterfaces)
    $tunIndexes = @($tun | ForEach-Object { [int]$_.IfIndex })
    $physical = @(Get-PhysicalAdapters -ExcludeIndex $tunIndexes)
    $targets = @(Get-TargetList -Config $config)
    $rules = @(Get-NetFirewallRule -Group $script:Group -ErrorAction SilentlyContinue)

    Write-Head '1. TUN 虚拟网卡'
    if ($tun.Count -eq 0) {
        Write-Host '  [X] 没有 TUN。客户端现在应该是全断的。' -ForegroundColor Red
    } else {
        foreach ($item in $tun) {
            Write-Host ('  [OK] {0} ({1})' -f $item.Name, $item.Description) -ForegroundColor Green
        }
    }

    Write-Head '2. 防火墙规则'
    if ($rules.Count -eq 0) {
        Write-Host '  [X] 没有任何 AIGuard 规则，先跑 lock。' -ForegroundColor Red
    } else {
        Write-Host ('  [OK] {0} 条规则生效' -f $rules.Count) -ForegroundColor Green
        $rules | Sort-Object DisplayName | ForEach-Object { Write-Host ('       {0}' -f $_.DisplayName) -ForegroundColor DarkGray }
    }

    Write-Head '3. 出口 IP'
    try {
        $ip = (Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -TimeoutSec 8).ip
        Write-Host ('  当前出口 IP：{0}' -f $ip) -ForegroundColor Green
        Write-Host '  如果这串和你家宽带 IP 一样，说明没走代理。' -ForegroundColor DarkGray
    } catch {
        Write-Host ('  查询失败：{0}' -f $_.Exception.Message) -ForegroundColor Yellow
    }

    Write-Head '4. 实时泄露扫描'
    $hits = @(Get-LeakConnections -Targets $targets -Tun $tun)
    if ($hits.Count -eq 0) {
        Write-Host '  [OK] 没发现非 TUN 连接' -ForegroundColor Green
    } else {
        Write-Host '  [!!] 发现非 TUN 连接：' -ForegroundColor Red
        foreach ($hit in $hits) {
            Write-Host ('       {0} [{1}] {2} -> {3} ({4})' -f $hit.Process, $hit.PID, $hit.Local, $hit.Remote, $hit.State) -ForegroundColor Red
        }
    }

    Write-Head '5. 物理网卡（应被封锁）'
    foreach ($item in $physical) {
        Write-Host ('  {0}  {1}' -f $item.Name, $item.Status) -ForegroundColor Gray
    }

    Write-Host ''
    Write-Host '验收：手动关掉 v2rayN 的 TUN，三个客户端应立刻全部连不上，微信等其它程序不受影响。' -ForegroundColor Cyan
}

# ---------------------------------------------------------------- 命令：status

function Invoke-Status {
    $tun = @(Get-TunInterfaces)
    $config = Get-Config
    $targets = @(Get-TargetList -Config $config)
    $rules = @(Get-NetFirewallRule -Group $script:Group -ErrorAction SilentlyContinue)

    Write-Host ''
    Write-Host ('TUN       : {0}' -f $(if ($tun.Count -gt 0) { (($tun | ForEach-Object { $_.Name }) -join ', ') } else { '未检测到' })) -ForegroundColor $(if ($tun.Count -gt 0) { 'Green' } else { 'Red' })
    Write-Host ('目标客户端: {0}' -f $(if ($targets.Count -gt 0) { (($targets | ForEach-Object { $_.name }) -join ', ') } else { '无' })) -ForegroundColor Gray
    Write-Host ('防火墙规则: {0} 条' -f $rules.Count) -ForegroundColor $(if ($rules.Count -gt 0) { 'Green' } else { 'Yellow' })
    Write-Host ('状态      : {0}' -f $(if ($rules.Count -gt 0) { '已上锁' } else { '未上锁' })) -ForegroundColor $(if ($rules.Count -gt 0) { 'Green' } else { 'Yellow' })

    if (Test-Path -LiteralPath $script:StateFile) {
        $state = Get-Content -Path $script:StateFile -Raw -Encoding UTF8 | ConvertFrom-Json
        Write-Host ('上次上锁  : {0}' -f $state.appliedAt) -ForegroundColor DarkGray
        Write-Host ('封禁网卡  : {0}' -f (@($state.aliases) -join ', ')) -ForegroundColor DarkGray
    }
    Write-Host ''
}

# ---------------------------------------------------------------- 命令：help

function Show-Help {
    Write-Host ''
    Write-Host 'AI Egress Guard — 让 AI 客户端只能走 TUN 代理' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  用法: .\aiguard.ps1 <命令> [-AllowVoice] [-DryRun] [-Interval 秒]'
    Write-Host ''
    Write-Host '  probe    探测环境，生成 config.json'
    Write-Host '  lock     上锁（自动请求管理员权限）'
    Write-Host '  unlock   解锁'
    Write-Host '  watch    常驻监控，抓绕过 TUN 的直连'
    Write-Host '  test     自检：TUN / 规则 / 出口 IP / 泄露扫描'
    Write-Host '  status   看当前状态'
    Write-Host ''
    Write-Host '  示例:'
    Write-Host '    .\aiguard.ps1 probe'
    Write-Host '    .\aiguard.ps1 lock'
    Write-Host '    .\aiguard.ps1 test'
    Write-Host '    .\aiguard.ps1 lock -AllowVoice   # 保留 ChatGPT 语音'
    Write-Host '    .\aiguard.ps1 lock -DryRun       # 只预演，不改防火墙'
    Write-Host ''
}

# ---------------------------------------------------------------- 入口

$commandName = $Command.ToLowerInvariant()
try {
    switch ($commandName) {
        'probe'   { Invoke-Probe }
        'lock'    { Invoke-Lock }
        'unlock'  { Invoke-Unlock }
        'watch'   { Invoke-Watch }
        'test'    { Invoke-Test }
        'status'  { Invoke-Status }
        'help'    { Show-Help }
        default   {
            Write-Host ('未知命令：{0}' -f $Command) -ForegroundColor Red
            Show-Help
        }
    }
} catch {
    Write-Host ''
    Write-Host ('出错：{0}' -f $_.Exception.Message) -ForegroundColor Red
    Write-Host ('详细信息见日志：{0}' -f $script:LogFile) -ForegroundColor DarkGray
    exit 1
}
