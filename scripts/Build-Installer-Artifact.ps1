[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')]
    [string]$Configuration = 'Release',

    [string]$RuntimeIdentifier = 'win-x64',

    [string]$OutputRoot = '',

    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Message)
    Write-Host "[SecureVol] $Message" -ForegroundColor Cyan
}

function Resolve-RepoRoot {
    Split-Path -Parent $PSScriptRoot
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage ExitCode=$LASTEXITCODE"
    }
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

    return $path.Trim()
}

function Get-InstalledWdkVersion {
    $kitsRoot = 'C:\Program Files (x86)\Windows Kits\10\build'
    $kitsContentRoot = 'C:\Program Files (x86)\Windows Kits\10'
    if (-not (Test-Path $kitsRoot)) {
        throw 'WDK build tools were not found. Install the Windows Driver Kit before building the installer artifact.'
    }

    $kit = Get-ChildItem $kitsRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object {
            (Test-Path (Join-Path $_.FullName 'WindowsDriver.Default.props')) -and
            (Test-Path (Join-Path $_.FullName 'x64\WindowsKernelModeDriver\WDK.x64.WindowsKernelModeDriver.props')) -and
            (Test-Path (Join-Path $kitsContentRoot "Include\$($_.Name)\km\ntddk.h")) -and
            (Test-Path (Join-Path $kitsContentRoot "bin\$($_.Name)\x64\rc.exe"))
        } |
        Sort-Object { [version]$_.Name } -Descending |
        Select-Object -First 1

    if (-not $kit) {
        throw 'A supported standalone WDK install was not found under C:\Program Files (x86)\Windows Kits\10\build.'
    }

    return $kit.Name
}

function Resolve-LatestKitTool {
    param(
        [Parameter(Mandatory = $true)][string]$ToolName,
        [string]$Architecture = 'x64'
    )

    $tool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter $ToolName -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -like "*\$Architecture\$ToolName" } |
        Sort-Object FullName -Descending |
        Select-Object -First 1

    if (-not $tool) {
        throw "$ToolName was not found under the Windows Kits bin directory."
    }

    return $tool.FullName
}

function Test-CertificateUsableForSigning {
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if (-not $Certificate.HasPrivateKey) {
        return $false
    }

    $eku = $Certificate.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.3' }
    if (-not $eku) {
        return $false
    }

    $thumbprint = ($Certificate.Thumbprint -replace '\s', '').ToUpperInvariant()
    $certutilOutput = & certutil.exe -user -store My $thumbprint 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        return $false
    }

    return ($certutilOutput -notmatch 'Missing stored keyset')
}

function Build-DriverPackage {
    param([string]$RepoRoot)

    $driverProject = Join-Path $RepoRoot 'driver\SecureVolFlt\SecureVolFlt.vcxproj'
    $msbuild = Get-MSBuildPath
    $wdkVersion = Get-InstalledWdkVersion

    Write-Step "Building SecureVol minifilter driver with WDK $wdkVersion"
    & $msbuild $driverProject /t:Build /p:Configuration=$Configuration /p:Platform=x64 "/p:SecureVolWdkVersion=$wdkVersion" "/p:WindowsTargetPlatformVersion=$wdkVersion"
    if ($LASTEXITCODE -ne 0) {
        throw "Driver build failed with exit code $LASTEXITCODE."
    }
}

function Stage-DriverArtifacts {
    param([string]$RepoRoot)

    $driverOutputDir = Join-Path $RepoRoot 'driver\SecureVolFlt\out\driver\Release\SecureVolFlt'
    $sysPath = Join-Path $driverOutputDir 'SecureVolFlt.sys'
    $infPath = Join-Path $driverOutputDir 'SecureVolFlt.inf'
    $catPath = Get-ChildItem $driverOutputDir -Filter '*.cat' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if (-not (Test-Path $sysPath) -or -not (Test-Path $infPath) -or -not $catPath) {
        throw 'Driver packaging outputs are incomplete. Ensure SecureVolFlt.sys/.inf/.cat were produced.'
    }

    $packageDir = Join-Path $RepoRoot 'out\driver\package'
    if (Test-Path $packageDir) {
        Remove-Item -LiteralPath $packageDir -Recurse -Force
    }

    New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
    Copy-Item -Path $sysPath -Destination (Join-Path $packageDir 'SecureVolFlt.sys') -Force
    Copy-Item -Path $infPath -Destination (Join-Path $packageDir 'SecureVolFlt.inf') -Force
    Copy-Item -Path $catPath.FullName -Destination (Join-Path $packageDir 'SecureVolFlt.cat') -Force

    return $packageDir
}

function Ensure-TestCertificate {
    $subject = 'CN=SecureVol Build Test'
    $certificate = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $subject } |
        Sort-Object NotAfter -Descending |
        Where-Object { Test-CertificateUsableForSigning -Certificate $_ } |
        Select-Object -First 1

    if (-not $certificate) {
        Write-Step 'Creating a local test code-signing certificate for installer artifacts'
        $certificate = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $subject `
            -CertStoreLocation Cert:\CurrentUser\My `
            -HashAlgorithm SHA256 `
            -KeyAlgorithm RSA `
            -KeyLength 2048 `
            -KeyExportPolicy Exportable
    }

    if (-not (Test-CertificateUsableForSigning -Certificate $certificate)) {
        throw 'The generated code-signing certificate is not usable for signtool signing.'
    }

    return $certificate
}

function Sign-DriverPackage {
    param(
        [Parameter(Mandatory = $true)][string]$PackageDir,
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $signtool = Resolve-LatestKitTool -ToolName 'signtool.exe' -Architecture 'x64'
    $thumbprint = ($Certificate.Thumbprint -replace '\s', '').ToUpperInvariant()
    $sysPath = Join-Path $PackageDir 'SecureVolFlt.sys'
    $catPath = Join-Path $PackageDir 'SecureVolFlt.cat'

    Write-Step 'Signing SecureVol driver package with the local test certificate'
    Invoke-External -FilePath $signtool -ArgumentList @('sign', '/fd', 'SHA256', '/s', 'My', '/sha1', $thumbprint, $sysPath) -FailureMessage 'Failed to sign SecureVolFlt.sys.'
    Invoke-External -FilePath $signtool -ArgumentList @('sign', '/fd', 'SHA256', '/s', 'My', '/sha1', $thumbprint, $catPath) -FailureMessage 'Failed to sign SecureVolFlt.cat.'
}

function Export-TestCertificate {
    param(
        [Parameter(Mandatory = $true)][string]$PackageDir,
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $destination = Join-Path $PackageDir 'SecureVolTest.cer'
    Export-Certificate -Cert $Certificate -FilePath $destination -Force | Out-Null
    return $destination
}

function Publish-InstallerApp {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$PayloadZip,
        [Parameter(Mandatory = $true)][string]$InstallerOutputRoot
    )

    $projectPath = Join-Path $RepoRoot 'installer\SecureVol.Installer\SecureVol.Installer.csproj'
    $publishDir = Join-Path $InstallerOutputRoot ('SecureVol.Installer-' + $RuntimeIdentifier + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))

    New-Item -ItemType Directory -Path $publishDir -Force | Out-Null

    Write-Step 'Publishing the SecureVol GUI installer application'
    $null = Invoke-External -FilePath 'dotnet.exe' -ArgumentList @(
        'publish',
        $projectPath,
        '-c', $Configuration,
        '-r', $RuntimeIdentifier,
        '--self-contained', 'true',
        "/p:SecureVolPayloadZip=$PayloadZip",
        '-o', $publishDir
    ) -FailureMessage 'Failed to publish SecureVol.Installer.'

    $installerExe = Join-Path $publishDir 'SecureVol.Installer.exe'
    if (-not (Test-Path $installerExe)) {
        throw "Installer executable was not found at '$installerExe' after publish."
    }

    $zipPath = "$publishDir.zip"
    if (Test-Path $zipPath) {
        Remove-Item -LiteralPath $zipPath -Force
    }

    Compress-Archive -Path $publishDir -DestinationPath $zipPath

    return [pscustomobject]@{
        Directory = $publishDir
        Executable = $installerExe
        Zip = $zipPath
    }
}

$repoRoot = Resolve-RepoRoot
$OutputRoot = if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    Join-Path $repoRoot 'artifacts\installer'
}
else {
    $OutputRoot
}

$bundleOutputRoot = Join-Path $OutputRoot ('payload-staging-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $bundleOutputRoot -Force | Out-Null

Build-DriverPackage -RepoRoot $repoRoot
$packageDir = Stage-DriverArtifacts -RepoRoot $repoRoot
$certificate = Ensure-TestCertificate
Sign-DriverPackage -PackageDir $packageDir -Certificate $certificate
$certificatePath = Export-TestCertificate -PackageDir $packageDir -Certificate $certificate

Write-Step "Driver package staged in '$packageDir'"
Write-Step "Installer certificate exported to '$certificatePath'"

$buildReleaseArgs = @(
    '-ExecutionPolicy', 'Bypass',
    '-File', (Join-Path $repoRoot 'scripts\Build-Release.ps1'),
    '-Configuration', $Configuration,
    '-RuntimeIdentifier', $RuntimeIdentifier,
    '-UiFlavor', 'imgui',
    '-OutputRoot', $bundleOutputRoot
)

if ($SkipTests) {
    $buildReleaseArgs += '-SkipTests'
}

Write-Step 'Building the full SecureVol release bundle with the native Dear ImGui admin UI'
Invoke-External -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $buildReleaseArgs -FailureMessage 'Build-Release.ps1 failed.'

$releaseRoot = Join-Path $bundleOutputRoot "SecureVol-$Configuration-imgui-$RuntimeIdentifier"
$releaseZip = "$releaseRoot.zip"
$installer = Publish-InstallerApp -RepoRoot $repoRoot -PayloadZip $releaseZip -InstallerOutputRoot $OutputRoot

Write-Step 'Installer artifact is ready'
Write-Host "Layout : $releaseRoot"
Write-Host "Zip    : $releaseZip"
Write-Host "Setup  : $($installer.Executable)"
Write-Host "SetupZip: $($installer.Zip)"
