$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
Write-Output "Last boot: $boot"
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-TaskScheduler/Operational'
    StartTime = $boot
    Id = @(100, 101, 102, 107, 110, 111, 129, 200, 201, 202, 203)
} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'ThessleyPamWinWeb' } |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List

Get-ScheduledTaskInfo -TaskName 'ThessleyPamWinWeb' | Format-List LastRunTime, LastTaskResult, NextRunTime

foreach ($provider in @('Microsoft-Windows-Dhcp-Client', 'Microsoft-Windows-NetworkProfile', 'Microsoft-Windows-TCPIP')) {
    Write-Output "Provider: $provider"
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $boot; ProviderName = $provider } -ErrorAction SilentlyContinue |
        Select-Object -First 20 TimeCreated, Id, Message |
        Format-List
}
