[CmdletBinding()]
param(
    [ValidateSet('install', 'repair', 'uninstall', 'launch')]
    [string]$Action = 'install',

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ForwardedArgs = @()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Step {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('Gray', 'Green', 'Red', 'Yellow', 'Cyan')]
        [string]$Color = 'Gray'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$timestamp] [SecureVol] $Message"
    Write-Host $line -ForegroundColor $Color
    Add-Content -Path $script:LogPath -Value $line
}

function Quote-Argument {
    param([Parameter(Mandatory = $true)][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return '""'
    }

    if ($Value.IndexOfAny([char[]]@(' ', "`t", '"')) -ge 0) {
        return '"' + ($Value -replace '"', '\"') + '"'
    }

    return $Value
}

function Ensure-Elevated {
    if ($Action -eq 'launch' -or (Test-Admin)) {
        return
    }

    $powershell = Join-Path $PSHOME 'powershell.exe'
    $arguments = @(
        '-NoLogo',
        '-ExecutionPolicy', 'Bypass',
        '-File', $PSCommandPath,
        '-Action', $Action
    )

    foreach ($arg in $ForwardedArgs) {
        $arguments += $arg
    }

    try {
        Start-Process -FilePath $powershell -Verb RunAs -ArgumentList $arguments | Out-Null
    }
    catch {
        Write-Step "Elevation was cancelled or failed: $($_.Exception.Message)" Red
        Wait-BeforeExit
        exit 1
    }

    exit 0
}

function Wait-BeforeExit {
    if ($ForwardedArgs -contains '--no-pause') {
        return
    }

    Write-Host ''
    Read-Host 'Press Enter to close' | Out-Null
}

$ReleaseRoot = Split-Path -Parent $PSCommandPath
$SetupHost = Join-Path $ReleaseRoot 'managed\setup\SecureVol.SetupHost.exe'
$AdminApp = Join-Path $ReleaseRoot 'managed\app\SecureVol.ImGui.exe'
$LogsRoot = Join-Path $env:ProgramData 'SecureVol\logs\installer'

New-Item -ItemType Directory -Path $LogsRoot -Force | Out-Null
$script:LogPath = Join-Path $LogsRoot ("securevol-{0}-{1}.log" -f $Action, (Get-Date -Format 'yyyyMMdd-HHmmss'))

Ensure-Elevated

try {
    if ($Action -eq 'launch') {
        if (-not (Test-Path $AdminApp)) {
            throw "SecureVol admin app was not found at '$AdminApp'."
        }

        Write-Step "Launching SecureVol admin app from '$AdminApp'" Cyan
        Start-Process -FilePath $AdminApp | Out-Null
        exit 0
    }

    if (-not (Test-Path $SetupHost)) {
        throw "SecureVol.SetupHost.exe was not found at '$SetupHost'."
    }

    $setupArgs = [System.Collections.Generic.List[string]]::new()
    $setupArgs.Add($Action)

    if (($Action -eq 'install' -or $Action -eq 'repair') -and -not ($ForwardedArgs -contains '--enable-testsigning')) {
        $setupArgs.Add('--enable-testsigning')
    }

    foreach ($arg in $ForwardedArgs) {
        if ($arg -eq '--no-pause') {
            continue
        }

        $setupArgs.Add($arg)
    }

    Write-Step "Release root: $ReleaseRoot" Cyan
    Write-Step "Writing installer log to '$script:LogPath'" Cyan
    Write-Step "Invoking SetupHost: $SetupHost $([string]::Join(' ', ($setupArgs | ForEach-Object { Quote-Argument $_ })))" Cyan
    Write-Host ''

    & $SetupHost @setupArgs 2>&1 | Tee-Object -FilePath $script:LogPath -Append
    $exitCode = $LASTEXITCODE

    Write-Host ''
    if ($exitCode -eq 0) {
        Write-Step 'Completed successfully.' Green
    }
    else {
        Write-Step "Failed with exit code $exitCode. See the log above or '$script:LogPath'." Red
    }

    Wait-BeforeExit
    exit $exitCode
}
catch {
    Write-Host ''
    Write-Step "Bootstrap failed: $($_.Exception.Message)" Red
    Write-Step "See '$script:LogPath' for details." Yellow
    Wait-BeforeExit
    exit 1
}
