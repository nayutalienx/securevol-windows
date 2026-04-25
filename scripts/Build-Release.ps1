[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')]
    [string]$Configuration = 'Release',

    [string]$RuntimeIdentifier = 'win-x64',

    [ValidateSet('wpf', 'imgui')]
    [string]$UiFlavor = 'wpf',

    [string]$OutputRoot = '',

    [string]$ReleaseTag = '',

    [switch]$SkipTests,
    [switch]$SkipDriver
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Message)
    Write-Host "[SecureVol] $Message" -ForegroundColor Cyan
}

function Invoke-Dotnet {
    param(
        [string[]]$Arguments
    )

    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

function Resolve-ReleaseTag {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [string]$RequestedTag
    )

    if (-not [string]::IsNullOrWhiteSpace($RequestedTag)) {
        return $RequestedTag.Trim()
    }

    if (-not [string]::IsNullOrWhiteSpace($env:SECUREVOL_RELEASE_TAG)) {
        return $env:SECUREVOL_RELEASE_TAG.Trim()
    }

    try {
        $tag = & git -C $RepoRoot describe --tags --always --dirty 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($tag)) {
            return $tag.Trim()
        }
    }
    catch {
        # Fall through to a deterministic local marker.
    }

    return 'dev-local'
}

function Publish-Project {
    param(
        [string]$ProjectPath,
        [string]$DestinationPath
    )

    Write-Step "Publishing $ProjectPath"
    Invoke-Dotnet @(
        'publish',
        $ProjectPath,
        '-c', $Configuration,
        '-r', $RuntimeIdentifier,
        '--self-contained', 'true',
        "/p:SecureVolReleaseTag=$script:ResolvedReleaseTag",
        '-o', $DestinationPath
    )
}

function Get-MSBuildPath {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) {
        throw "vswhere.exe was not found at '$vswhere'."
    }

    $path = & $vswhere -latest -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($path)) {
        throw 'MSBuild.exe could not be located via vswhere.'
    }

    return $path
}

function Build-NativeProject {
    param(
        [string]$ProjectPath,
        [string]$DestinationPath
    )

    $msbuild = Get-MSBuildPath
    Write-Step "Building native UI project $ProjectPath"
    & $msbuild $ProjectPath /t:Build /p:Configuration=$Configuration /p:Platform=x64 "/p:SecureVolReleaseTag=$script:ResolvedReleaseTag"
    if ($LASTEXITCODE -ne 0) {
        throw "MSBuild failed for '$ProjectPath' with exit code $LASTEXITCODE."
    }

    $nativeOutput = Join-Path (Split-Path -Path $ProjectPath -Parent) "out\\x64\\$Configuration"
    if (-not (Test-Path $nativeOutput)) {
        throw "Native UI output folder '$nativeOutput' was not found after build."
    }

    New-Item -ItemType Directory -Force -Path $DestinationPath | Out-Null
    Copy-Item -Path (Join-Path $nativeOutput '*') -Destination $DestinationPath -Recurse -Force
}

function Get-UiProjectPath {
    param([string]$Flavor)

    switch ($Flavor) {
        'wpf'   { return 'app\SecureVol.App\SecureVol.App.csproj' }
        'imgui' { return 'app\SecureVol.ImGuiNative\SecureVol.ImGuiNative.vcxproj' }
        default { throw "Unknown UI flavor '$Flavor'." }
    }
}

function Write-LauncherScript {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$CommandLine
    )

    @(
        '@echo off'
        'setlocal'
        $CommandLine
    ) | Set-Content -Path $Path -Encoding ASCII
}

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$script:ResolvedReleaseTag = Resolve-ReleaseTag -RepoRoot $repoRoot -RequestedTag $ReleaseTag
$OutputRoot = if ([string]::IsNullOrWhiteSpace($OutputRoot)) { Join-Path $repoRoot 'release' } else { $OutputRoot }
$releaseRoot = Join-Path $OutputRoot "SecureVol-$Configuration-$UiFlavor-$RuntimeIdentifier"
$managedRoot = Join-Path $releaseRoot 'managed'
$driverRoot = Join-Path $releaseRoot 'driver'
$docsRoot = Join-Path $releaseRoot 'docs'

Write-Step "Preparing release root '$releaseRoot'"
Write-Step "Embedding release tag '$script:ResolvedReleaseTag'"
if (Test-Path $releaseRoot) {
    Remove-Item -LiteralPath $releaseRoot -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $managedRoot | Out-Null
New-Item -ItemType Directory -Force -Path $driverRoot | Out-Null
New-Item -ItemType Directory -Force -Path $docsRoot | Out-Null

if (-not $SkipTests) {
    Write-Step 'Running managed test suite'
    Invoke-Dotnet @(
        'test',
        (Join-Path $repoRoot 'tests\SecureVol.Service.Tests\SecureVol.Service.Tests.csproj'),
        '-c', $Configuration
    )
}

Publish-Project -ProjectPath (Join-Path $repoRoot 'common\SecureVol.Common\SecureVol.Common.csproj') -DestinationPath (Join-Path $managedRoot 'common')
Publish-Project -ProjectPath (Join-Path $repoRoot 'service\SecureVol.Service\SecureVol.Service.csproj') -DestinationPath (Join-Path $managedRoot 'service')
Publish-Project -ProjectPath (Join-Path $repoRoot 'cli\SecureVol.Cli\SecureVol.Cli.csproj') -DestinationPath (Join-Path $managedRoot 'cli')

$uiProjectPath = Join-Path $repoRoot (Get-UiProjectPath -Flavor $UiFlavor)
if ($UiFlavor -eq 'imgui') {
    Build-NativeProject -ProjectPath $uiProjectPath -DestinationPath (Join-Path $managedRoot 'app')
}
else {
    Publish-Project -ProjectPath $uiProjectPath -DestinationPath (Join-Path $managedRoot 'app')
}

Publish-Project -ProjectPath (Join-Path $repoRoot 'installer\SecureVol.SetupHost\SecureVol.SetupHost.csproj') -DestinationPath (Join-Path $managedRoot 'setup')

if (-not $SkipDriver) {
    $driverPackage = Join-Path $repoRoot 'out\driver\package'
    if (Test-Path $driverPackage) {
        Write-Step 'Copying existing driver package into the release layout'
        Copy-Item -Path (Join-Path $driverPackage '*') -Destination $driverRoot -Recurse -Force
    }
    else {
        Write-Warning "Driver package was not found at '$driverPackage'. Build and sign the minifilter separately, or rerun with -SkipDriver."
    }
}

Write-Step 'Copying docs and top-level metadata'
Copy-Item (Join-Path $repoRoot 'README.md') $docsRoot -Force
Copy-Item (Join-Path $repoRoot 'LICENSE') $docsRoot -Force
Copy-Item (Join-Path $repoRoot 'SECURITY.md') $docsRoot -Force
Copy-Item (Join-Path $repoRoot 'CONTRIBUTING.md') $docsRoot -Force
Copy-Item (Join-Path $repoRoot 'docs\build-install.md') $docsRoot -Force
Copy-Item (Join-Path $repoRoot 'docs\testing-checklist.md') $docsRoot -Force
Copy-Item (Join-Path $repoRoot 'docs\hardening-checklist.md') $docsRoot -Force
Copy-Item (Join-Path $repoRoot 'docs\product-backlog.md') $docsRoot -Force

Write-Step 'Writing convenience launchers'
Copy-Item (Join-Path $repoRoot 'installer\ReleaseBootstrap\Invoke-SecureVol-Release.ps1') (Join-Path $releaseRoot 'Invoke-SecureVol-Release.ps1') -Force
Write-LauncherScript -Path (Join-Path $releaseRoot 'Install-SecureVol.cmd') -CommandLine 'powershell.exe -NoLogo -ExecutionPolicy Bypass -File "%~dp0Invoke-SecureVol-Release.ps1" -Action install %*'
Write-LauncherScript -Path (Join-Path $releaseRoot 'Repair-SecureVol.cmd') -CommandLine 'powershell.exe -NoLogo -ExecutionPolicy Bypass -File "%~dp0Invoke-SecureVol-Release.ps1" -Action repair %*'
Write-LauncherScript -Path (Join-Path $releaseRoot 'Uninstall-SecureVol.cmd') -CommandLine 'powershell.exe -NoLogo -ExecutionPolicy Bypass -File "%~dp0Invoke-SecureVol-Release.ps1" -Action uninstall %*'
Write-LauncherScript -Path (Join-Path $releaseRoot 'Launch-SecureVol-Admin.cmd') -CommandLine 'powershell.exe -NoLogo -ExecutionPolicy Bypass -File "%~dp0Invoke-SecureVol-Release.ps1" -Action launch'

$manifest = [ordered]@{
    createdUtc = [DateTimeOffset]::UtcNow
    releaseTag = $script:ResolvedReleaseTag
    configuration = $Configuration
    runtimeIdentifier = $RuntimeIdentifier
    uiFlavor = $UiFlavor
    paths = [ordered]@{
        common = (Join-Path $managedRoot 'common')
        service = (Join-Path $managedRoot 'service')
        cli = (Join-Path $managedRoot 'cli')
        app = (Join-Path $managedRoot 'app')
        setup = (Join-Path $managedRoot 'setup')
        driver = $driverRoot
    }
    files = @()
}

Get-ChildItem -Path $releaseRoot -Recurse -File | ForEach-Object {
    $manifest.files += [ordered]@{
        path = $_.FullName.Substring($releaseRoot.Length + 1)
        sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        size = $_.Length
    }
}

$manifestPath = Join-Path $releaseRoot 'release-manifest.json'
$manifest | ConvertTo-Json -Depth 6 | Set-Content -Path $manifestPath -Encoding UTF8

$zipPath = "$releaseRoot.zip"
Write-Step "Compressing release layout to '$zipPath'"
if (Test-Path $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}
Compress-Archive -Path $releaseRoot -DestinationPath $zipPath

Write-Step 'Release build completed'
Write-Host "Layout : $releaseRoot"
Write-Host "Zip    : $zipPath"
