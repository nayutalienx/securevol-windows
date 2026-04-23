[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$root = Split-Path -Parent $PSScriptRoot
$report = Join-Path $root 'out\securevol-admin-probe.txt'

if (-not (Test-IsAdministrator)) {
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $PSCommandPath)
    ) | Out-Null
    exit 0
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $report) | Out-Null

& {
    "=== timestamp ==="
    Get-Date -Format o
    ""

    "=== services ==="
    Get-CimInstance Win32_Service -Filter "Name='SecureVolSvc'" | Select-Object Name,State,ProcessId,PathName | Format-List
    Get-CimInstance Win32_SystemDriver -Filter "Name='SecureVolFlt'" | Select-Object Name,State,Started,PathName,ServiceType | Format-List
    ""

    "=== filter list ==="
    fltmc filters
    ""

    "=== instance list ==="
    fltmc instances
    ""

    "=== policy ==="
    Get-Content 'C:\ProgramData\SecureVol\config\policy.json'
    ""

    "=== cli state ==="
    & (Join-Path $root 'out\cli\securevol.exe') state
    ""

    "=== recent securevol events ==="
    Get-WinEvent -LogName Application -MaxEvents 30 |
        Where-Object { $_.ProviderName -like '*SecureVol*' -or $_.Message -like '*SecureVol*' } |
        Select-Object TimeCreated, ProviderName, LevelDisplayName, Message |
        Format-List
} 2>&1 | Out-File -FilePath $report -Encoding utf8
