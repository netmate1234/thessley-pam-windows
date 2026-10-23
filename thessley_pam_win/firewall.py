"""Apply the admin-selected Windows Firewall source ranges for SSH and Thessley listeners."""

import subprocess


def _ps_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def apply_ssh_source_policy(modes: list[str], vpn_subnets: list[str], addresses: list[str], program: str) -> None:
    if modes == ["all"]:
        remote = ["Any"]
    else:
        remote = []
        if "local" in modes:
            remote.append("LocalSubnet")
        if "vpn" in modes:
            remote.extend(vpn_subnets)
        if "custom" in modes:
            remote.extend(addresses)
    remote = list(dict.fromkeys(remote))
    if not remote:
        raise ValueError("The selected Windows Firewall source policy has no addresses.")

    powershell = f"""
$ErrorActionPreference = 'Stop'
$remote = @({', '.join(_ps_string(item) for item in remote)})
$python = {_ps_string(program)}
$script:created = @()

$existing = @()
$existing += @(Get-NetFirewallRule -DisplayName 'Thessley Passkey approvals' -ErrorAction SilentlyContinue)
$existing += @(Get-NetFirewallRule -DisplayName 'Thessley Passkey approvals VPN' -ErrorAction SilentlyContinue)
$existing += @(Get-NetFirewallRule -DisplayName 'Thessley admin web page' -ErrorAction SilentlyContinue)
$existing += @(Get-NetFirewallRule -DisplayName 'Thessley admin web page VPN' -ErrorAction SilentlyContinue)
$existing += @(Get-NetFirewallRule -DisplayName 'Thessley OpenSSH VPN access' -ErrorAction SilentlyContinue)
$existing += @(Get-NetFirewallRule -DisplayName 'Thessley OpenSSH source policy' -ErrorAction SilentlyContinue)
$existing += @(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)
$existing += @(Get-NetFirewallRule -DisplayName 'OpenSSH SSH Server (sshd)' -ErrorAction SilentlyContinue)
$snapshot = foreach ($rule in $existing | Sort-Object Name -Unique) {{
    $filter = $rule | Get-NetFirewallAddressFilter
    [pscustomobject]@{{Name=$rule.Name; Remote=@($filter.RemoteAddress); Enabled=$rule.Enabled}}
}}

function Set-ThessleyPortRule([string]$name, [int]$port) {{
    $rules = @(Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)
    if ($rules.Count) {{
        $rules | Set-NetFirewallRule -RemoteAddress $remote -Enabled True
    }} else {{
        $newRule = New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol TCP `
            -LocalPort $port -Program $python -Profile Any -RemoteAddress $remote
        $script:created += $newRule.Name
    }}
}}

try {{
    Set-ThessleyPortRule 'Thessley Passkey approvals' 47810
    Set-ThessleyPortRule 'Thessley admin web page' 47820
    foreach ($name in @('Thessley Passkey approvals VPN', 'Thessley admin web page VPN')) {{
        Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Set-NetFirewallRule -Enabled False
    }}
    $sshRules = @(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)
    if (-not $sshRules.Count) {{
        $sshRules = @(Get-NetFirewallRule -DisplayName 'OpenSSH SSH Server (sshd)' -ErrorAction SilentlyContinue)
    }}
    if ($sshRules.Count) {{
        $sshRules | Set-NetFirewallRule -RemoteAddress $remote
        foreach ($name in @('Thessley OpenSSH VPN access', 'Thessley OpenSSH source policy')) {{
            Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Set-NetFirewallRule -Enabled False
        }}
    }} else {{
        $thessleySsh = @(Get-NetFirewallRule -DisplayName 'Thessley OpenSSH VPN access' -ErrorAction SilentlyContinue)
        if (-not $thessleySsh.Count) {{
            $thessleySsh = @(Get-NetFirewallRule -DisplayName 'Thessley OpenSSH source policy' -ErrorAction SilentlyContinue)
        }}
        if ($thessleySsh.Count) {{
            $thessleySsh | Set-NetFirewallRule -RemoteAddress $remote
        }} elseif (Get-Service -Name sshd -ErrorAction SilentlyContinue) {{
            $newRule = New-NetFirewallRule -DisplayName 'Thessley OpenSSH source policy' -Direction Inbound -Action Allow `
                -Protocol TCP -LocalPort 22 -Profile Any -RemoteAddress $remote
            $script:created += $newRule.Name
        }}
    }}
}} catch {{
    foreach ($name in $script:created) {{ Remove-NetFirewallRule -Name $name -ErrorAction SilentlyContinue }}
    foreach ($old in $snapshot) {{
        Get-NetFirewallRule -Name $old.Name -ErrorAction SilentlyContinue | Set-NetFirewallRule `
            -RemoteAddress $old.Remote -Enabled $old.Enabled -ErrorAction SilentlyContinue
    }}
    throw
}}
"""
    try:
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", powershell],
                                capture_output=True, text=True, errors="replace", timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"Could not apply the Windows Firewall source policy: {exc}") from exc
    if result.returncode:
        detail = (result.stderr or result.stdout or "PowerShell returned an error.").strip()
        raise RuntimeError(f"Could not apply the Windows Firewall source policy: {detail}")
