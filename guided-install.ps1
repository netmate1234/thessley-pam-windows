<#
  Guided installer for the Thessley Windows SSH + Web GUI package.
  Run from an elevated PowerShell after extracting the distribution ZIP.
  OpenSSH Server is installed and verified separately; this script never
  installs, starts, or edits OpenSSH configuration or Windows sign-in policy.
#>
$ErrorActionPreference = 'Stop'
# Over ssh the console code page is not UTF-8; the Python tools print UTF-8. Without this their text arrives garbled.
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch { }
$OutputEncoding = [Text.UTF8Encoding]::new($false)

function Ask-YesNo([string]$Prompt, [bool]$Default = $false) {
    $hint = if ($Default) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $answer = Read-Host "$Prompt $hint"
        if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
        if ($answer -match '^(y|yes)$') { return $true }
        if ($answer -match '^(n|no)$') { return $false }
        Write-Host 'Please answer Y or N.'
    }
}

function Find-MachinePython {
    $candidates = @(
        (Get-Command python.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1),
        (Get-ChildItem "$env:ProgramFiles\Python*\python.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName),
        (Get-ChildItem "${env:ProgramFiles(x86)}\Python*\python.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    ) | Where-Object { $_ }
    foreach ($candidate in $candidates) {
        $resolved = (Resolve-Path $candidate -ErrorAction SilentlyContinue).Path
        if ($resolved -and ($resolved.StartsWith($env:ProgramFiles, [StringComparison]::OrdinalIgnoreCase) -or $resolved.StartsWith(${env:ProgramFiles(x86)}, [StringComparison]::OrdinalIgnoreCase))) {
            try {
                & $resolved -c 'import sys; assert sys.version_info >= (3,10)' 2>$null
                if ($LASTEXITCODE -eq 0) { return $resolved }
            } catch { }
        }
    }
    return $null
}

function Select-PhoneNetworkInterface {
    try {
        $candidates = @(
            Get-NetIPConfiguration -ErrorAction Stop |
                Where-Object { $_.NetAdapter.Status -eq 'Up' -and $_.IPv4Address } |
                ForEach-Object {
                    $config = $_
                    $address = @($config.IPv4Address | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | Select-Object -First 1)
                    if ($address.Count -gt 0) {
                        $gateway = @($config.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ', '
                        [pscustomobject]@{
                            Index = [int]$config.InterfaceIndex
                            Alias = [string]$config.InterfaceAlias
                            Address = [string]$address[0].IPAddress
                            Gateway = $gateway
                            Suffix = [string]$config.NetProfile.Name
                        }
                    }
                } |
                Sort-Object @{ Expression = { if ($_.Suffix) { 0 } else { 1 } } },
                            @{ Expression = { if ($_.Alias -match '\s+\d+$') { 1 } else { 0 } } }, Alias, Address
        )
    } catch {
        Write-Warning "Could not enumerate IPv4 adapters; Windows will select its default route. $($_.Exception.Message)"
        return 'auto'
    }

    if ($candidates.Count -eq 0) {
        Write-Warning 'No active IPv4 adapter was found; Windows will select its default route.'
        return 'auto'
    }
    if ($candidates.Count -eq 1) {
        $selected = $candidates[0]
        Write-Host "Phone links will use $($selected.Address) on $($selected.Alias)."
        return [string]$selected.Index
    }

    Write-Host "`nThis PC has multiple active IPv4 adapters. Thessley puts the selected address in phone approval links. Choose an address the phone can reach (your LAN or VPN); do not choose a VM-only NAT address."
    for ($i = 0; $i -lt $candidates.Count; $i++) {
        $gateway = ''
        if ($candidates[$i].Gateway) { $gateway = "; gateway $($candidates[$i].Gateway)" }
        Write-Host "  $($i + 1). Adapter: $($candidates[$i].Alias); current IPv4 address: $($candidates[$i].Address)$gateway"
    }
    Write-Host '  A. Let Windows choose its default route automatically.'
    while ($true) {
        $choice = Read-Host 'Number of the phone-reachable adapter [1]'
        if ([string]::IsNullOrWhiteSpace($choice)) { $choice = '1' }
        if ($choice -match '^(a|auto)$') {
            Write-Host "Phone links will follow Windows default route. On a multi-NIC VM, this may be a private NAT address."
            return 'auto'
        }
        if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $candidates.Count) {
            $selected = $candidates[[int]$choice - 1]
            Write-Host "Phone links will use $($selected.Address) on $($selected.Alias). The address will follow DHCP changes on this adapter."
            return [string]$selected.Index
        }
        Write-Host "Enter a number from 1 to $($candidates.Count), or A for automatic selection."
    }
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open PowerShell as Administrator, then run this installer again.'
}

# Check the SSH prerequisite before installing Python or changing any services.
# The wizard deliberately does not install or reconfigure OpenSSH itself.
$sshCapability = Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
$sshInstalled = $sshCapability.State -eq 'Installed'
$sshdService = Get-Service -Name sshd -ErrorAction SilentlyContinue
$sshReady = $sshInstalled -and $sshdService -and $sshdService.Status -eq 'Running'
if (-not $sshReady) {
    if (-not $sshInstalled) {
        Write-Warning 'OpenSSH Server is not installed. Thessley SSH QR login cannot work until OpenSSH Server is installed.'
    } else {
        Write-Warning 'OpenSSH Server is installed but sshd is not running. Thessley SSH QR login cannot work until sshd is started.'
    }
    if (-not (Ask-YesNo 'Continue with web administration and optional Windows sign-in only, without SSH QR login?' $false)) {
        throw 'No Thessley setup changes were made. Install and start OpenSSH Server, then rerun this wizard.'
    }
}

$repo = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Find-MachinePython
if (-not $python) {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        throw 'Python 3.12+ for all users is required. Install it from python.org, then rerun this wizard.'
    }
    if (Ask-YesNo 'Install Python 3.13 for all users using winget? This is required for the Thessley service.' $true) {
        winget install --id Python.Python.3.13 --scope machine --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -ne 0) { throw 'Python installation failed. Install Python 3.12+ for all users, then rerun this wizard.' }
        $python = Find-MachinePython
    }
    if (-not $python) { throw 'A machine-wide Python 3.12+ installation is required. No service changes were made.' }
}
Write-Host "Using machine-wide Python: $python"

$phoneInterfaceIndex = Select-PhoneNetworkInterface

$cloudAccess = Ask-YesNo 'Is this a cloud host whose SSH clients and phone approvals may come from changing public IP addresses? Cloud mode opens selected Windows firewall ports to any remote IP.' $false
$openSshFirewall = $false
if ($cloudAccess) {
    $openSshFirewall = $sshInstalled -and (Ask-YesNo 'Allow SSH connections on TCP 22 from any remote IP? The cloud provider firewall must also allow this.' $true)
    $openApprovalFirewall = Ask-YesNo 'Allow phone approvals and enrollment on TCP 47810 from any remote IP? The cloud provider firewall must also allow this.' $true
    $enableWeb = Ask-YesNo 'Install and enable the HTTPS admin web page on TCP 47820?' $true
    $openWebFirewall = $false
    if ($enableWeb) {
        $openWebFirewall = Ask-YesNo 'Allow the admin web page on TCP 47820 from any remote IP? Keep this off unless remote web access is needed.' $false
    }
} else {
    $openApprovalFirewall = Ask-YesNo 'Allow phone approvals and enrollment to reach this PC on TCP 47810 from the local subnet?' $true
    $enableWeb = Ask-YesNo 'Install and enable the HTTPS admin web page on TCP 47820?' $true
    $openWebFirewall = $false
    if ($enableWeb) {
        $openWebFirewall = Ask-YesNo 'Allow the local subnet to reach the web page on TCP 47820?' $true
    }
}
$vpnClientSubnets = ''
$sshVpnFirewall = $sshInstalled -and $sshdService -and $sshdService.Status -eq 'Running'
if (-not $cloudAccess -and ($openApprovalFirewall -or $openWebFirewall -or $sshVpnFirewall)) {
    $defaultVpnSubnets = '10.8.0.0/24,10.8.1.0/24'
    $cidrPattern = '^(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])/(?:[0-9]|[12][0-9]|3[0-2])$'
    while ($true) {
        $choice = Read-Host "Also allow SSH, phone approvals, and the web GUI from VPN ranges $defaultVpnSubnets? Local networks remain allowed. [Y/n/custom]"
        if ([string]::IsNullOrWhiteSpace($choice) -or $choice -match '^(y|yes)$') {
            $vpnClientSubnets = $defaultVpnSubnets
            break
        }
        if ($choice -match '^(n|no|none)$') { break }

        if ($choice -match '^(c|custom)$') {
            $choice = Read-Host 'Enter comma-separated IPv4 CIDRs; for one phone source IP shown in its error, add /32 (or type none to skip)'
        }
        if ($choice -ieq 'none') { break }

        $subnets = @($choice -split '\s*,\s*')
        if (@($subnets | Where-Object { $_ -notmatch $cidrPattern }).Count -gt 0) {
            Write-Host 'Choose Y or N, or enter CIDRs such as 10.8.0.0/24 or a single source such as 10.31.19.228/32.'
            continue
        }
        $vpnClientSubnets = $subnets -join ','
        break
    }
}

$install = Join-Path $repo 'install\install.ps1'
$arguments = @{ Python = $python }
$arguments.PhoneInterfaceIndex = $phoneInterfaceIndex
if ($openApprovalFirewall) { $arguments.OpenFirewall = $true }
if ($openWebFirewall) { $arguments.OpenWebFirewall = $true }
if ($cloudAccess) { $arguments.CloudAccess = $true }
if ($openSshFirewall) { $arguments.OpenSshFirewall = $true }
$arguments.VpnClientSubnets = $vpnClientSubnets
& $install @arguments

$cli = Join-Path $env:ProgramData 'ThessleyPamWin\thessley-pam-win.cmd'

function Ensure-PhoneApprover([string]$Account) {
    $listed = @(& $cli list --user $Account 2>&1)
    $listStatus = $LASTEXITCODE
    foreach ($line in $listed) { Write-Host $line }
    if ($listStatus -ne 0) {
        Write-Warning "Could not read approvers for $Account. No login policy was changed."
        return $false
    }
    $entries = @($listed | Where-Object { $_ -match '\benrolled\s+\d{4}-\d{2}-\d{2}' })
    $activeEntries = @($entries | Where-Object { $_ -notmatch '\(disabled\)' })
    $hasApprover = $activeEntries.Count -gt 0
    if (-not $hasApprover) {
        if (-not (Ask-YesNo "No phone is enrolled for $Account. Start phone enrollment now?" $true)) { return $false }
        Write-Host 'Scan the enrollment QR on the phone, compare both pairing codes, approve, then type yes here.'
        & $cli enroll --user $Account
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Enrollment did not complete for $Account. No login policy was changed."
            return $false
        }
    }
    return (Ask-YesNo "Is the enrolled phone available now to test the $Account login?" $false)
}

function Invoke-CliCapture([string[]]$Arguments) {
    # Expected CLI failures (for example, an active one-time link) must be
    # inspected by the caller instead of becoming terminating PowerShell
    # NativeCommandError records under $ErrorActionPreference = 'Stop'.
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& $cli @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    return [pscustomobject]@{ Lines = $lines; ExitCode = $exitCode }
}

if ($enableWeb) {
    $webOnResult = Invoke-CliCapture @('web', 'on')
    if ($webOnResult.ExitCode -ne 0) {
        foreach ($line in $webOnResult.Lines) { Write-Host $line }
        throw 'The web page could not be enabled.'
    }
    $adminSignInLine = $null
    foreach ($line in $webOnResult.Lines) {
        if ([string]$line -match 'https?://') {
            $adminSignInLine = [string]$line
        } else {
            Write-Host $line
        }
    }

    $bootstrapUser = $env:USERNAME
    $listed = @(& $cli list --user $bootstrapUser 2>&1)
    if ($LASTEXITCODE -ne 0) {
        foreach ($line in $listed) { Write-Host $line }
        throw "Could not check first-phone setup for $bootstrapUser. The web page is installed; no login policy was changed."
    }
    $anyDevices = @($listed | Where-Object { $_ -match '\benrolled\s+\d{4}-\d{2}-\d{2}' })
    $enrolled = @($anyDevices | Where-Object { $_ -notmatch '\(disabled\)' })
    if ($anyDevices.Count -eq 0) {
        Write-Host "`nNo phone is enrolled for $bootstrapUser. Creating the one-time first-phone link now."
        $bootstrapResult = Invoke-CliCapture @('web', 'bootstrap', '--user', $bootstrapUser)
        # The web task was started a moment ago; wait for its listener rather than printing a link nobody can open.
        for ($attempt = 0; $attempt -lt 10 -and $bootstrapResult.ExitCode -ne 0 -and (($bootstrapResult.Lines -join "`n") -match 'does not answer'); $attempt++) {
            Start-Sleep -Seconds 3
            $bootstrapResult = Invoke-CliCapture @('web', 'bootstrap', '--user', $bootstrapUser)
        }
        $bootstrapOutput = @($bootstrapResult.Lines)
        $bootstrapCreated = $bootstrapResult.ExitCode -eq 0
        if (-not $bootstrapCreated) {
            foreach ($line in $bootstrapOutput) { Write-Host $line }
            $alreadyActive = ($bootstrapOutput -join "`n") -match 'first-phone setup link is already active'
            if ($alreadyActive -and (Ask-YesNo 'The previous setup link is still active, but its complete URL cannot be recovered. Invalidate it and issue a fresh link now?' $true)) {
                $bootstrapResult = Invoke-CliCapture @('web', 'bootstrap', '--user', $bootstrapUser, '--replace-active')
                $bootstrapOutput = @($bootstrapResult.Lines)
                $bootstrapCreated = $bootstrapResult.ExitCode -eq 0
            }
        }
        if ($bootstrapCreated) {
            foreach ($line in $bootstrapOutput) { Write-Host $line }
            Write-Host 'Open the complete FIRST-PHONE ENROLLMENT LINK printed above, enter its setup code, and enroll the phone. The link expires after 10 minutes.'
            $enrollmentTimer = [Diagnostics.Stopwatch]::StartNew()
            while ($enrollmentTimer.Elapsed.TotalMinutes -lt 10) {
                Start-Sleep -Seconds 3
                $listed = @(& $cli list --user $bootstrapUser 2>&1)
                if ($LASTEXITCODE -ne 0) { Write-Warning "Could not check enrollment status for $bootstrapUser. The service remains installed."; break }
                $enrolled = @($listed | Where-Object { $_ -match '\benrolled\s+\d{4}-\d{2}-\d{2}' -and $_ -notmatch '\(disabled\)' })
                if ($enrolled.Count -gt 0) {
                    Write-Host "First phone enrolled for $bootstrapUser. The installer can now continue."
                    break
                }
            }
            if ($enrolled.Count -eq 0) {
                Write-Warning 'No phone was enrolled before the one-time setup expired. The service and web page remain installed; rerun the guided installer to create a fresh link.'
            }
        } else {
            foreach ($line in $bootstrapOutput) { Write-Host $line }
            Write-Warning 'The service and web page remain installed, but phone enrollment was not started. Rerun the guided installer to try again.'
        }
    } elseif ($adminSignInLine) {
        Write-Host $adminSignInLine
    }
}

Write-Host "`nBase Thessley approval service installed and started."
$sshConfigured = $false
if ($sshInstalled -and $sshdService) {
    if ($sshdService.Status -eq 'Running') {
        $sshRecovery = & (Join-Path $repo 'install\arm-ssh-rollback.ps1') -RollbackMinutes 30
        Write-Host 'Enabling QR approval by default for current local SSH accounts. Existing OpenSSH key/password settings are preserved.'
        & $cli ssh-defaults
        if ($LASTEXITCODE -eq 0) {
            $sshConfigured = $true
            Write-Host 'Accounts with no enrolled phone can use their existing SSH method until enrollment; after enrollment, phone QR approval is required.'
        } else {
            throw 'Could not apply the default QR policy. SSH setup recovery remains armed; keep this session open and check Admin > Setup rollback.'
        }
    } else {
        Write-Warning 'OpenSSH Server is installed but not running. No SSH policy was changed.'
    }
} elseif ($sshInstalled) {
    Write-Warning 'OpenSSH Server is listed as installed, but its sshd service is missing. Repair OpenSSH before enabling QR SSH.'
} else {
    Write-Host 'OpenSSH Server is not installed; the Windows sign-in tile can still be installed below.'
}
if ($cloudAccess) {
    Write-Host 'Cloud mode affects the Windows firewall only. In the cloud provider firewall/security group, allow TCP 22 for SSH and TCP 47810 for phone approvals from your intended sources; allow 47820 only if you selected remote web access.'
}

$providerConfigured = $false
if (Ask-YesNo 'Install or update the experimental Thessley QR Windows sign-in tile now? Keep PIN/password recovery available.' $false) {
    $defaultLogonUser = $env:USERNAME
    $logonUser = Read-Host "Windows account to test at the sign-in screen [$defaultLogonUser]"
    if ([string]::IsNullOrWhiteSpace($logonUser)) { $logonUser = $defaultLogonUser }
    if ($logonUser -notmatch '^[A-Za-z0-9._-]{1,64}$') { throw 'Use a simple account name: letters, numbers, dot, underscore, or hyphen.' }
    if (Ensure-PhoneApprover $logonUser) {
        $providerSetup = Join-Path $repo 'install\setup-logon-provider.ps1'
        & $providerSetup -RollbackMinutes 30
        $providerConfigured = $true
    } else {
        Write-Warning "Skipped Windows sign-in tile setup because a phone approver is not ready for $logonUser."
    }
}

Write-Host "`nTo enroll an approver later, run:"
Write-Host "& `"$cli`" enroll --user YOURNAME"
if ($sshConfigured -or $providerConfigured) {
    Write-Host "`nDo not confirm until every enabled method has been tested successfully."
    Write-Host 'After successful SSH QR login and/or Windows QR sign-in, run elevated:'
    $confirmScript = Join-Path $env:ProgramData 'ThessleyPamWin\confirm-setup.ps1'
    Write-Host "  powershell -ExecutionPolicy Bypass -File `"$confirmScript`""
    if ($sshConfigured) { Write-Host 'SSH config changes have a verified 30-minute rollback timer. After testing a fresh SSH login, use Admin > Setup rollback > Keep setup and stop rollback.' }
    if ($providerConfigured) { Write-Host 'The Windows QR sign-in tile has its own automatic rollback timer.' }
    Write-Host 'The built-in Windows PIN/password tiles remain available as recovery.'
} else {
    Write-Host 'No SSH policy or Windows sign-in provider changes were made. Configure per-user SSH access from the Admin page after setup.'
}
Write-Host "To uninstall the approval service, remove any active SSH Match User block first, then run install\uninstall.ps1 as Administrator."
