[CmdletBinding()]
param(
    [string]$SourceDir = 'A:\Telegram',
    [string]$RunsRoot = ([System.IO.Path]::Combine([Environment]::GetFolderPath('Desktop'), 'runs')),
    [string]$RuleUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Message)
    Write-Host "[SecureVol] $Message" -ForegroundColor Cyan
}

function Ensure-Admin {
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($currentIdentity)
    if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return
    }

    Write-Step 'Requesting elevation for Telegram external-run setup'
    $argumentList = @(
        '-NoProfile'
        '-ExecutionPolicy', 'Bypass'
        '-File', ('"{0}"' -f $PSCommandPath)
        '-SourceDir', ('"{0}"' -f $SourceDir)
        '-RunsRoot', ('"{0}"' -f $RunsRoot)
        '-RuleUser', ('"{0}"' -f $RuleUser)
    )

    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $argumentList -Verb RunAs -PassThru
    $process.WaitForExit()
    exit $process.ExitCode
}

function Invoke-Robocopy {
    param(
        [string]$From,
        [string]$To
    )

    $args = @(
        $From
        $To
        '/E'
        '/R:1'
        '/W:1'
        '/NFL'
        '/NDL'
        '/NJH'
        '/NJS'
        '/NP'
        '/XD', 'tdata'
        '/XF', 'log.txt'
        '/XF', '*.lnk'
    )

    & robocopy.exe @args | Out-Host
    if ($LASTEXITCODE -gt 7) {
        throw "robocopy failed with exit code $LASTEXITCODE."
    }
}

function Assert-PathInside {
    param(
        [string]$Candidate,
        [string]$ExpectedRoot
    )

    $resolvedCandidate = [System.IO.Path]::GetFullPath($Candidate)
    $resolvedRoot = [System.IO.Path]::GetFullPath($ExpectedRoot)
    if (-not $resolvedCandidate.StartsWith($resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to modify '$resolvedCandidate' because it is outside '$resolvedRoot'."
    }
}

function Update-Shortcut {
    param(
        [string]$ShortcutPath,
        [string]$TargetPath,
        [string]$WorkingDirectory
    )

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($ShortcutPath)
    $shortcut.TargetPath = $TargetPath
    $shortcut.WorkingDirectory = $WorkingDirectory
    $shortcut.IconLocation = "$TargetPath,0"
    $shortcut.Save()
}

function Add-SecureVolRule {
    param(
        [string]$CliPath,
        [string]$RuleName,
        [string]$ImagePath,
        [string]$Publisher,
        [string]$ExpectedUser,
        [string]$Notes
    )

    & $CliPath rule add `
        --name $RuleName `
        --image $ImagePath `
        --publisher $Publisher `
        --user $ExpectedUser `
        --require-signed `
        --notes $Notes

    if ($LASTEXITCODE -ne 0) {
        throw "securevol rule add failed for '$RuleName' with exit code $LASTEXITCODE."
    }
}

Ensure-Admin

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$cliPath = Join-Path $repoRoot 'out\cli\securevol.exe'
$resolvedSourceDir = [System.IO.Path]::GetFullPath($SourceDir)
$resolvedRunsRoot = [System.IO.Path]::GetFullPath($RunsRoot)
$destinationDir = Join-Path $resolvedRunsRoot 'Telegram'
$sourceTdata = Join-Path $resolvedSourceDir 'tdata'
$destinationTdata = Join-Path $destinationDir 'tdata'
$destinationExe = Join-Path $destinationDir 'Telegram.exe'
$destinationUpdater = Join-Path $destinationDir 'Updater.exe'
$runsShortcut = Join-Path $resolvedRunsRoot 'Telegram.exe - Shortcut.lnk'
$friendlyShortcut = Join-Path $resolvedRunsRoot 'Secure Telegram.lnk'

if (-not (Test-Path $resolvedSourceDir)) {
    throw "Telegram source directory '$resolvedSourceDir' does not exist."
}

if (-not (Test-Path (Join-Path $resolvedSourceDir 'Telegram.exe'))) {
    throw "Telegram.exe was not found in '$resolvedSourceDir'."
}

if (-not (Test-Path $sourceTdata)) {
    throw "tdata was not found in '$sourceTdata'."
}

if (-not (Test-Path $cliPath)) {
    throw "SecureVol CLI was not found at '$cliPath'."
}

Write-Step "Preparing external Telegram folder in '$destinationDir'"
New-Item -ItemType Directory -Force -Path $destinationDir | Out-Null
Invoke-Robocopy -From $resolvedSourceDir -To $destinationDir

if (Test-Path $destinationTdata) {
    Assert-PathInside -Candidate $destinationTdata -ExpectedRoot $destinationDir
    Write-Step "Removing existing '$destinationTdata' before recreating the junction"
    Remove-Item -LiteralPath $destinationTdata -Recurse -Force
}

Write-Step "Linking '$destinationTdata' -> '$sourceTdata'"
New-Item -ItemType Junction -Path $destinationTdata -Target $sourceTdata | Out-Null

Write-Step 'Updating external Telegram shortcuts'
Update-Shortcut -ShortcutPath $runsShortcut -TargetPath $destinationExe -WorkingDirectory $destinationDir
Update-Shortcut -ShortcutPath $friendlyShortcut -TargetPath $destinationExe -WorkingDirectory $destinationDir

$telegramSignature = Get-AuthenticodeSignature $destinationExe
if ($telegramSignature.Status -ne 'Valid' -or -not $telegramSignature.SignerCertificate) {
    throw "Telegram.exe signature validation failed for '$destinationExe'."
}

$publisherName = $telegramSignature.SignerCertificate.GetNameInfo(
    [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
    $false)

Write-Step "Adding SecureVol allow rules for '$RuleUser'"
Add-SecureVolRule `
    -CliPath $cliPath `
    -RuleName 'telegram' `
    -ImagePath $destinationExe `
    -Publisher $publisherName `
    -ExpectedUser $RuleUser `
    -Notes 'External Telegram binary. Data remains on the protected VeraCrypt volume through a tdata junction.'

if (Test-Path $destinationUpdater) {
    Add-SecureVolRule `
        -CliPath $cliPath `
        -RuleName 'telegram-updater' `
        -ImagePath $destinationUpdater `
        -Publisher $publisherName `
        -ExpectedUser $RuleUser `
        -Notes 'External Telegram updater. Required if Telegram updates itself while using protected-volume data.'
}

Write-Step 'Telegram external-run setup is ready'
Write-Host "Telegram executable : $destinationExe"
Write-Host "Telegram tdata      : $destinationTdata"
Write-Host "Shortcut            : $friendlyShortcut"
