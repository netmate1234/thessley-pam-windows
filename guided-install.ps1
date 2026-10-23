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

$openApprovalFirewall = Ask-YesNo 'Allow phone approvals to reach this PC on TCP 47810 from the local subnet?' $false
$enableWeb = Ask-YesNo 'Install and enable the HTTPS admin web page on TCP 47820?' $false
$openWebFirewall = $false
if ($enableWeb) {
    $openWebFirewall = Ask-YesNo 'Allow the local subnet to reach the web page on TCP 47820?' $false
}

$install = Join-Path $repo 'install\install.ps1'
$arguments = @{ Python = $python }
if ($openApprovalFirewall) { $arguments.OpenFirewall = $true }
if ($openWebFirewall) { $arguments.OpenWebFirewall = $true }
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
    & $cli web status
}

Write-Host "`nBase Thessley approval service installed and started."
$sshConfigured = $false
if ($sshInstalled -and $sshdService) {
    if (Ask-YesNo 'Enable the Thessley QR approval gate for one Windows OpenSSH account now?' $false) {
        $defaultUser = $env:USERNAME
        $targetUser = Read-Host "Windows SSH account to configure [$defaultUser]"
        if ([string]::IsNullOrWhiteSpace($targetUser)) { $targetUser = $defaultUser }
        if ($targetUser -notmatch '^[A-Za-z0-9._-]{1,64}$') { throw 'Use a simple account name: letters, numbers, dot, underscore, or hyphen.' }
        Write-Host 'The first SSH factor must already work. The default is an SSH key; phone QR approval follows it.'
        $factor = Read-Host 'First factor: key, password, or key-password [key]'
        if ([string]::IsNullOrWhiteSpace($factor)) { $factor = 'key' }
        if ($factor -notin @('key', 'password', 'key-password')) { throw 'Choose key, password, or key-password.' }
        if (Ensure-PhoneApprover $targetUser) {
            $sshSetup = Join-Path $repo 'install\enable-ssh-qr.ps1'
            & $sshSetup -UserName $targetUser -Python $python -Factor $factor -RollbackMinutes 15
            $sshConfigured = $true
        } else {
            Write-Warning "Skipped SSH policy changes. Enroll first with: & `"$cli`" enroll --user $targetUser ; then rerun setup."
        }
    }
} elseif ($sshInstalled) {
    Write-Warning 'OpenSSH Server is listed as installed, but its sshd service is missing. Repair OpenSSH before enabling QR SSH.'
} else {
    Write-Host 'OpenSSH Server is not installed; the Windows sign-in tile can still be installed below.'
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
    Write-Host "`nDo not confirm until every enabled method has been tested successfully. Any new login changes have automatic rollback timers."
    Write-Host 'After successful SSH QR login and/or Windows QR sign-in, run elevated:'
    Write-Host "  powershell -ExecutionPolicy Bypass -File `"$(Join-Path $env:ProgramData 'ThessleyPamWin\confirm-setup.ps1')`""
    if ($sshConfigured) { Write-Host 'SSH configuration backups are in C:\ProgramData\ThessleyPamWin\backups.' }
    Write-Host 'The built-in Windows PIN/password tiles remain available as recovery.'
} else {
    Write-Host 'No SSH policy or Windows sign-in provider changes were made. Rerun this guided installer when ready.'
}
Write-Host 'To uninstall the approval service, remove any active SSH Match User block first, then run install\uninstall.ps1 as Administrator.'
