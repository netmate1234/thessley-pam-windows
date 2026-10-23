<#
  Guided installer for the Thessley Windows SSH + Web GUI package.
  Run from an elevated PowerShell after extracting the distribution ZIP.
  OpenSSH Server is installed and verified separately; this script never
  installs, starts, or edits OpenSSH configuration or Windows sign-in policy.
#>
$ErrorActionPreference = 'Stop'

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

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open PowerShell as Administrator, then run this installer again.'
}

$repo = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Find-MachinePython
if (-not $python) {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        throw 'Python 3.10+ for all users is required. Install it from python.org, then rerun this wizard.'
    }
    if (Ask-YesNo 'Install Python 3.13 for all users using winget? This is required for the Thessley service.' $true) {
        winget install --id Python.Python.3.13 --scope machine --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -ne 0) { throw 'Python installation failed. Install Python 3.10+ for all users, then rerun this wizard.' }
        $python = Find-MachinePython
    }
    if (-not $python) { throw 'A machine-wide Python 3.10+ installation is required. No service changes were made.' }
}
Write-Host "Using machine-wide Python: $python"

$sshCapability = Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
$sshInstalled = $sshCapability.State -eq 'Installed'
$sshdService = Get-Service -Name sshd -ErrorAction SilentlyContinue

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
            $choice = Read-Host 'Enter comma-separated IPv4 VPN subnets in CIDR form (or none to skip)'
        }
        if ($choice -ieq 'none') { break }

        $subnets = @($choice -split '\s*,\s*')
        if (@($subnets | Where-Object { $_ -notmatch $cidrPattern }).Count -gt 0) {
            Write-Host 'Choose Y, N, or enter CIDR ranges such as 10.8.0.0/24,10.8.1.0/24.'
            continue
        }
        $vpnClientSubnets = $subnets -join ','
        break
    }
}

$install = Join-Path $repo 'install\install.ps1'
$arguments = @{ Python = $python }
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
    return (Ask-YesNo "Is the enrolled phone available now to test $Account's login?" $false)
}

if ($enableWeb) {
    & $cli web on
    if ($LASTEXITCODE -ne 0) { throw 'The web page could not be enabled.' }

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
        & $cli web bootstrap --user $bootstrapUser
        if ($LASTEXITCODE -ne 0) { throw 'The one-time first-phone setup link could not be created.' }
        Write-Host 'Open the complete FIRST-PHONE ENROLLMENT LINK printed above, enter its setup code, and enroll the phone. The link expires after 10 minutes.'
        $deadline = (Get-Date).AddMinutes(10)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 3
            $listed = @(& $cli list --user $bootstrapUser 2>&1)
            if ($LASTEXITCODE -ne 0) { throw "Could not check enrollment status for $bootstrapUser." }
            $enrolled = @($listed | Where-Object { $_ -match '\benrolled\s+\d{4}-\d{2}-\d{2}' -and $_ -notmatch '\(disabled\)' })
            if ($enrolled.Count -gt 0) {
                Write-Host "First phone enrolled for $bootstrapUser. The installer can now continue."
                break
            }
        }
        if ($enrolled.Count -eq 0) {
            Write-Warning 'No phone was enrolled before the one-time setup expired. Rerun the guided installer to generate a fresh link.'
        }
    }
}

Write-Host "`nBase Thessley approval service installed and started."
$sshConfigured = $false
if ($sshInstalled -and $sshdService) {
    if ($sshdService.Status -eq 'Running') {
        Write-Host 'Enabling QR approval by default for current local SSH accounts. Existing OpenSSH key/password settings are preserved.'
        & $cli ssh-defaults
        if ($LASTEXITCODE -eq 0) {
            $sshConfigured = $true
            Write-Host 'Accounts with no enrolled phone can use their existing SSH method until enrollment; after enrollment, phone QR approval is required.'
        } else {
            Write-Warning 'Could not apply the default QR policy. Existing SSH configuration was retained where it had not already been updated; manage accounts from Admin > Users.'
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
    Write-Host "  powershell -ExecutionPolicy Bypass -File `"$(Join-Path $env:ProgramData 'ThessleyPamWin\confirm-setup.ps1')`""
    if ($sshConfigured) { Write-Host 'SSH config changes are validated and backed up in C:\ProgramData\ThessleyPamWin\backups; QR can be turned off per account in Admin.' }
    if ($providerConfigured) { Write-Host 'The Windows QR sign-in tile has its own automatic rollback timer.' }
    Write-Host 'The built-in Windows PIN/password tiles remain available as recovery.'
} else {
    Write-Host 'No SSH policy or Windows sign-in provider changes were made. Configure per-user SSH access from the Admin page after setup.'
}
Write-Host 'To uninstall the approval service, remove any active SSH Match User block first, then run install\uninstall.ps1 as Administrator.'
