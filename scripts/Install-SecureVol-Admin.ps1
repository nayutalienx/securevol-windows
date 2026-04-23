[CmdletBinding()]
param(
    [string]$ProtectedVolume = 'A:',
    [string]$ChromePath = 'C:\Program Files\Google\Chrome\Application\chrome.exe',
    [string]$AllowedUser = "$env:COMPUTERNAME\$env:USERNAME",
    [switch]$CreateDedicatedUser,
    [string]$DedicatedUserName = 'vc_app',
    [SecureString]$DedicatedUserPassword,
    [switch]$EnableProtection,
    [switch]$EnableTestSigning,
    [switch]$SkipWdkInstall,
    [switch]$SkipBuild,
    [switch]$SkipDriverBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step([string]$Message) {
    Write-Host "`n[SecureVol] $Message" -ForegroundColor Cyan
}

function Test-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Elevated {
    if (Test-Admin) {
        return
    }

    if ($PSBoundParameters.ContainsKey('DedicatedUserPassword')) {
        throw 'Rerun this script from an elevated PowerShell session when passing -DedicatedUserPassword.'
    }

    $argList = @('-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        if ($entry.Key -eq 'DedicatedUserPassword') {
            continue
        }

        if ($entry.Value -is [System.Management.Automation.SwitchParameter]) {
            if ($entry.Value.IsPresent) {
                $argList += "-$($entry.Key)"
            }
        }
        else {
            $argList += "-$($entry.Key)"
            $argList += [string]$entry.Value
        }
    }

    Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -ArgumentList $argList | Out-Null
    exit
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )

    $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -NoNewWindow -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "$FailureMessage ExitCode=$($process.ExitCode)"
    }
}

function Resolve-RepoRoot {
    Split-Path -Parent $PSScriptRoot
}

function Get-VsInstallPath {
    $vsWhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vsWhere) {
        $path = & $vsWhere -latest -products * -property installationPath
        if ($LASTEXITCODE -eq 0 -and $path) {
            return $path.Trim()
        }
    }

    $fallback = 'C:\Program Files\Microsoft Visual Studio\2022\Community'
    if (Test-Path $fallback) {
        return $fallback
    }

    throw 'Visual Studio 2022 was not found.'
}

function Get-MSBuildPath {
    $vsPath = Get-VsInstallPath
    $msbuild = Join-Path $vsPath 'MSBuild\Current\Bin\MSBuild.exe'
    if (-not (Test-Path $msbuild)) {
        throw "MSBuild.exe not found under '$vsPath'."
    }

    return $msbuild
}

function Get-InstalledWdkVersion {
    $kitsRoot = 'C:\Program Files (x86)\Windows Kits\10\build'
    $kitsContentRoot = 'C:\Program Files (x86)\Windows Kits\10'
    if (-not (Test-Path $kitsRoot)) {
        return $null
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
        return $null
    }

    return $kit.Name
}

function Test-WdkToolsetInstalled {
    return $null -ne (Get-InstalledWdkVersion)
}

function Ensure-WdkInstalled {
    if (Test-WdkToolsetInstalled) {
        return
    }

    if ($SkipWdkInstall) {
        throw 'WDK build tools are missing. Install the Windows Driver Kit or rerun without -SkipWdkInstall.'
    }

    $packageIds = @(
        'Microsoft.WindowsWDK.10.0.26100',
        'Microsoft.WindowsWDK.10.0.22621',
        'Microsoft.WindowsWDK.10.0.22000',
        'Microsoft.WindowsWDK.10.0.19041'
    )

    foreach ($packageId in $packageIds) {
        Write-Step "Installing WDK package $packageId"
        try {
            Invoke-External -FilePath 'winget.exe' -ArgumentList @(
                'install',
                '--id', $packageId,
                '-e',
                '--accept-package-agreements',
                '--accept-source-agreements',
                '--disable-interactivity'
            ) -FailureMessage "winget failed for $packageId."
        }
        catch {
            Write-Warning $_.Exception.Message
        }

        Start-Sleep -Seconds 5
        if (Test-WdkToolsetInstalled) {
            return
        }
    }

    throw 'WDK installation did not produce the WindowsKernelModeDriver10.0 toolset.'
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

function Resolve-VolumeGuid([string]$Volume) {
    $normalized = if ($Volume.EndsWith('\')) { $Volume } else { "$Volume\" }
    $guid = (& mountvol $normalized /L).Trim()
    if (-not $guid.StartsWith('\\?\Volume{')) {
        throw "Could not resolve a volume GUID for '$Volume'."
    }

    return $guid.TrimEnd('\')
}

function Ensure-DedicatedUser([string]$UserName, [SecureString]$Password) {
    $existing = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
    if ($existing) {
        return "$env:COMPUTERNAME\$UserName"
    }

    if (-not $Password) {
        $Password = Read-Host "Password for new local user '$UserName'" -AsSecureString
    }

    New-LocalUser -Name $UserName -Password $Password -PasswordNeverExpires -AccountNeverExpires | Out-Null
    return "$env:COMPUTERNAME\$UserName"
}

function Write-Policy {
    param(
        [Parameter(Mandatory = $true)][string]$PolicyPath,
        [Parameter(Mandatory = $true)][string]$VolumeGuid,
        [Parameter(Mandatory = $true)][string]$AppUser,
        [Parameter(Mandatory = $true)][bool]$ProtectionEnabled
    )

    $policy = [ordered]@{
        protectionEnabled = $ProtectionEnabled
        protectedVolume = $VolumeGuid
        defaultExpectedUser = $AppUser
        allowRules = @(
            [ordered]@{
                name = 'chrome'
                imagePath = $ChromePath
                sha256 = $null
                requireSignature = $true
                publisher = 'Google LLC'
                expectedUser = $AppUser
                notes = 'Prepared automatically for Chrome on the protected VeraCrypt volume.'
            }
        )
    }

    $configDir = Split-Path -Parent $PolicyPath
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    ($policy | ConvertTo-Json -Depth 5) | Set-Content -Path $PolicyPath -Encoding UTF8

    $acl = Get-Acl $configDir
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($entry in @($acl.Access)) {
        [void]$acl.RemoveAccessRule($entry)
    }

    $system = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $admins = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $full = [System.Security.AccessControl.FileSystemRights]::FullControl

    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, $full, $inherit, $propagation, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admins, $full, $inherit, $propagation, $allow)))
    Set-Acl -Path $configDir -AclObject $acl
}

function Stop-ServiceIfRunning {
    param([string]$ServiceName)

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return
    }

    if ($service.Status -eq 'Running' -or $service.Status -eq 'StartPending') {
        Write-Step "Stopping $ServiceName"
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
    }
}

function Build-ManagedArtifacts {
    param([string]$RepoRoot)

    if ($SkipBuild) {
        return
    }

    Stop-ServiceIfRunning -ServiceName 'SecureVolSvc'

    Write-Step 'Publishing SecureVol CLI'
    Invoke-External -FilePath 'dotnet.exe' -ArgumentList @(
        'publish',
        (Join-Path $RepoRoot 'cli\SecureVol.Cli\SecureVol.Cli.csproj'),
        '-c', 'Release',
        '-r', 'win-x64',
        '--self-contained', 'true',
        '-o', (Join-Path $RepoRoot 'out\cli'),
        '/p:UseSharedCompilation=false'
    ) -FailureMessage 'Failed to publish the CLI.'

    Write-Step 'Publishing SecureVol service'
    Invoke-External -FilePath 'dotnet.exe' -ArgumentList @(
        'publish',
        (Join-Path $RepoRoot 'service\SecureVol.Service\SecureVol.Service.csproj'),
        '-c', 'Release',
        '-r', 'win-x64',
        '--self-contained', 'true',
        '-o', (Join-Path $RepoRoot 'out\service'),
        '/p:UseSharedCompilation=false'
    ) -FailureMessage 'Failed to publish the service.'
}

function Build-DriverPackage {
    param([string]$RepoRoot)

    if ($SkipDriverBuild) {
        return
    }

    Ensure-WdkInstalled
    $msbuild = Get-MSBuildPath
    $driverProject = Join-Path $RepoRoot 'driver\SecureVolFlt\SecureVolFlt.vcxproj'
    $wdkVersion = Get-InstalledWdkVersion
    if (-not $wdkVersion) {
        throw 'A supported standalone WDK install was not found under C:\Program Files (x86)\Windows Kits\10\build.'
    }

    Write-Step 'Building SecureVol minifilter driver'
    Write-Step "Using WDK build $wdkVersion"
    $output = & $msbuild $driverProject /t:Build /p:Configuration=Release /p:Platform=x64 "/p:SecureVolWdkVersion=$wdkVersion" "/p:WindowsTargetPlatformVersion=$wdkVersion" 2>&1
    $exitCode = $LASTEXITCODE
    $output | ForEach-Object { $_ }
    if ($exitCode -ne 0) {
        throw "Driver build failed with exit code $exitCode."
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

    if (-not (Test-Path $sysPath)) {
        throw "Driver binary was not found at '$sysPath'."
    }

    if (-not (Test-Path $infPath)) {
        throw "Driver INF was not found at '$infPath'."
    }

    if (-not $catPath) {
        throw 'Driver build did not produce SecureVolFlt.cat. Build the driver once from Visual Studio/WDK packaging if needed.'
    }

    $packageDir = Join-Path $RepoRoot 'out\driver\package'
    New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
    Copy-Item -Path $sysPath -Destination (Join-Path $packageDir 'SecureVolFlt.sys') -Force
    Copy-Item -Path $infPath -Destination (Join-Path $packageDir 'SecureVolFlt.inf') -Force
    Copy-Item -Path $catPath.FullName -Destination (Join-Path $packageDir 'SecureVolFlt.cat') -Force

    return $packageDir
}

function Ensure-TestCertificate {
    $subject = 'CN=SecureVol Test'
    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq $subject } | Select-Object -First 1
    if (-not $cert) {
        Write-Step 'Creating a local test code-signing certificate'
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject -CertStoreLocation Cert:\LocalMachine\My -HashAlgorithm SHA256 -KeyExportPolicy Exportable
    }

    $cerPath = Join-Path $env:TEMP 'SecureVolTest.cer'
    Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
    Import-Certificate -FilePath $cerPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Import-Certificate -FilePath $cerPath -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
    Remove-Item $cerPath -Force -ErrorAction SilentlyContinue

    return $cert
}

function Sign-DriverPackage {
    param(
        [Parameter(Mandatory = $true)][string]$PackageDir,
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $signtool = Resolve-LatestKitTool -ToolName 'signtool.exe' -Architecture 'x64'
    $sysPath = Join-Path $PackageDir 'SecureVolFlt.sys'
    $catPath = Join-Path $PackageDir 'SecureVolFlt.cat'
    $thumbprint = ($Certificate.Thumbprint -replace '\s', '').ToUpperInvariant()

    Write-Step 'Signing SecureVol driver package with a local test certificate'
    Invoke-External -FilePath $signtool -ArgumentList @(
        'sign',
        '/v',
        '/fd', 'SHA256',
        '/sm',
        '/s', 'My',
        '/sha1', $thumbprint,
        $sysPath
    ) -FailureMessage 'Failed to sign SecureVolFlt.sys.'

    Invoke-External -FilePath $signtool -ArgumentList @(
        'sign',
        '/v',
        '/fd', 'SHA256',
        '/sm',
        '/s', 'My',
        '/sha1', $thumbprint,
        $catPath
    ) -FailureMessage 'Failed to sign SecureVolFlt.cat.'
}

function Get-TestSigningEnabled {
    $output = & bcdedit.exe /enum 2>&1 | Out-String
    return ($output -match 'testsigning\s+Yes')
}

function Ensure-TestSigningMode {
    if (Get-TestSigningEnabled) {
        return $true
    }

    if (-not $EnableTestSigning) {
        throw 'Test-signing is disabled. Rerun this script with -EnableTestSigning, reboot, and run it again.'
    }

    Write-Step 'Enabling Windows test-signing mode'
    Invoke-External -FilePath 'bcdedit.exe' -ArgumentList @('/set', 'testsigning', 'on') -FailureMessage 'Failed to enable testsigning.'
    Write-Warning 'Windows test-signing mode was enabled. Reboot the machine, then rerun this script with the same arguments.'
    exit
}

function Ensure-ServiceInstalled {
    param(
        [Parameter(Mandatory = $true)][string]$ServiceExe
    )

    $service = Get-Service -Name 'SecureVolSvc' -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Step 'Creating SecureVolSvc'
        New-Service -Name 'SecureVolSvc' -BinaryPathName ('"' + $ServiceExe + '"') -DisplayName 'SecureVol Service' -StartupType Manual | Out-Null
    }
    else {
        Write-Step 'Updating SecureVolSvc binary path'
        $svc = Get-CimInstance Win32_Service -Filter "Name='SecureVolSvc'"
        $result = Invoke-CimMethod -InputObject $svc -MethodName Change -Arguments @{
            PathName = ('"' + $ServiceExe + '"')
            StartMode = 'Manual'
        }

        if ($result.ReturnValue -ne 0) {
            throw "Failed to update SecureVolSvc. Win32_Service.Change returned $($result.ReturnValue)."
        }
    }
}

function Ensure-ServiceRunning {
    $service = Get-Service -Name 'SecureVolSvc' -ErrorAction Stop
    if ($service.Status -ne 'Running') {
        Write-Step 'Starting SecureVolSvc'
        Start-Service -Name 'SecureVolSvc'
    }

    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
}

function Stop-FilterIfRunning {
    $service = Get-Service -Name 'SecureVolFlt' -ErrorAction SilentlyContinue
    if ($null -eq $service -or $service.Status -ne 'Running') {
        return
    }

    Write-Step 'Unloading running SecureVol minifilter'
    $output = & fltmc.exe unload SecureVolFlt 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) {
        return
    }

    $service = Get-Service -Name 'SecureVolFlt' -ErrorAction SilentlyContinue
    if ($null -eq $service -or $service.Status -ne 'Running') {
        return
    }

    throw "fltmc unload SecureVolFlt failed. $output"
}

function Install-DriverFromPackage {
    param(
        [Parameter(Mandatory = $true)][string]$PackageDir
    )

    $infPath = Join-Path $PackageDir 'SecureVolFlt.inf'
    $driverBinary = Join-Path $env:WINDIR 'System32\drivers\SecureVolFlt.sys'

    Write-Step 'Installing SecureVol minifilter service via SetupAPI'
    $output = & "$env:WINDIR\System32\rundll32.exe" setupapi.dll,InstallHinfSection DefaultInstall.NTamd64 132 $infPath 2>&1 | Out-String

    if (-not (Get-Item "HKLM:\SYSTEM\CurrentControlSet\Services\SecureVolFlt" -ErrorAction SilentlyContinue)) {
        throw "SetupAPI did not create the SecureVolFlt service. $output"
    }

    if (-not (Test-Path $driverBinary)) {
        throw "SetupAPI did not copy SecureVolFlt.sys to '$driverBinary'. $output"
    }
}

function Ensure-FilterLoaded {
    Write-Step 'Loading SecureVol minifilter'

    $service = Get-Service -Name 'SecureVolFlt' -ErrorAction SilentlyContinue
    if ($null -ne $service -and $service.Status -eq 'Running') {
        Write-Host '[SecureVol] SecureVolFlt is already running. Skipping redundant fltmc load.' -ForegroundColor DarkGray
        return
    }

    $output = & fltmc.exe load SecureVolFlt 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0 -or $output -match 'already loaded' -or $output -match 'already running') {
        return
    }

    $service = Get-Service -Name 'SecureVolFlt' -ErrorAction SilentlyContinue
    if ($null -ne $service -and $service.Status -eq 'Running') {
        return
    }

    throw "fltmc load SecureVolFlt failed. $output"
}

function Ensure-FilterAttachedToVolume {
    param(
        [Parameter(Mandatory = $true)][string]$Volume
    )

    Write-Step "Attaching SecureVol minifilter to $Volume"

    $output = & fltmc.exe attach SecureVolFlt $Volume 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) {
        return
    }

    if ($output -match 'already attached' -or
        $output -match 'The specified instance already exists' -or
        $output -match 'An instance already exists with this name on the volume specified' -or
        $output -match '0x801f0012' -or
        $output -match '0x80070420') {
        Write-Host '[SecureVol] SecureVolFlt is already attached to the target volume.' -ForegroundColor DarkGray
        return
    }

    throw "fltmc attach SecureVolFlt $Volume failed. $output"
}

function Wait-ForDriverConnection {
    param(
        [Parameter(Mandatory = $true)][string]$CliPath
    )

    Write-Step 'Waiting for SecureVol service to connect to the minifilter'

    $startTime = (Get-Date).AddMinutes(-10)

    $connectedEvent = Get-WinEvent -FilterHashtable @{
        LogName = 'Application'
        ProviderName = 'SecureVol'
        StartTime = $startTime
    } -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 1000 -and $_.Message -like '*connected to the minifilter communication port*' } |
        Select-Object -First 1

    if ($null -ne $connectedEvent) {
        Write-Host '[SecureVol] SecureVolSvc already reported a live driver connection.' -ForegroundColor DarkGray
        return
    }

    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Seconds 2
        $output = & $CliPath state 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0 -and $output -match 'DriverConnected\s*:\s*True') {
            return
        }

        $connectedEvent = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            ProviderName = 'SecureVol'
            StartTime = $startTime
        } -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -eq 1000 -and $_.Message -like '*connected to the minifilter communication port*' } |
            Select-Object -First 1

        if ($null -ne $connectedEvent) {
            return
        }

        if (($i + 1) -in @(5, 10)) {
            Write-Host '[SecureVol] Still waiting for the service/driver handshake...' -ForegroundColor DarkGray
        }
    }

    Write-Warning 'SecureVol service did not report DriverConnected=True within the expected timeout.'
}

function Set-ProtectionState {
    param(
        [Parameter(Mandatory = $true)][string]$CliPath,
        [Parameter(Mandatory = $true)][bool]$ProtectionEnabled
    )

    if ($ProtectionEnabled) {
        Write-Step 'Protected-volume enforcement is controlled by the written policy. Skipping post-start toggle.'
    }
    else {
        Write-Step 'Protected-volume enforcement is controlled by the written policy. Skipping post-start toggle.'
    }
}

function Show-FinalSummary {
    param(
        [Parameter(Mandatory = $true)][string]$VolumeGuid,
        [Parameter(Mandatory = $true)][bool]$ProtectionEnabled
    )

    Write-Step 'Final SecureVol state'

    $driverService = Get-Service -Name 'SecureVolFlt' -ErrorAction SilentlyContinue
    $userService = Get-Service -Name 'SecureVolSvc' -ErrorAction SilentlyContinue
    $connectedEvent = Get-WinEvent -FilterHashtable @{
        LogName = 'Application'
        ProviderName = 'SecureVol'
        StartTime = (Get-Date).AddMinutes(-10)
    } -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 1000 -and $_.Message -like '*connected to the minifilter communication port*' } |
        Select-Object -First 1

    $driverStatus = if ($null -ne $driverService) { $driverService.Status } else { 'NotInstalled' }
    $userServiceStatus = if ($null -ne $userService) { $userService.Status } else { 'NotInstalled' }

    Write-Host ("DriverService     : {0}" -f $driverStatus)
    Write-Host ("UserModeService   : {0}" -f $userServiceStatus)
    Write-Host ("ProtectionEnabled : {0}" -f $ProtectionEnabled)
    Write-Host ("ProtectedVolume   : {0}" -f $VolumeGuid)
    Write-Host ("DriverConnected   : {0}" -f ($(if ($null -ne $connectedEvent) { 'True' } else { 'Unknown' })))
}

Ensure-Elevated

$repoRoot = Resolve-RepoRoot
$cliPath = Join-Path $repoRoot 'out\cli\securevol.exe'
$serviceExe = Join-Path $repoRoot 'out\service\SecureVol.Service.exe'
$policyPath = 'C:\ProgramData\SecureVol\config\policy.json'

if (-not (Test-Path $ChromePath)) {
    throw "Chrome was not found at '$ChromePath'."
}

$targetUser = $AllowedUser
if ($CreateDedicatedUser) {
    $targetUser = Ensure-DedicatedUser -UserName $DedicatedUserName -Password $DedicatedUserPassword
}

Build-ManagedArtifacts -RepoRoot $repoRoot
Build-DriverPackage -RepoRoot $repoRoot
$packageDir = Stage-DriverArtifacts -RepoRoot $repoRoot
$certificate = Ensure-TestCertificate
Sign-DriverPackage -PackageDir $packageDir -Certificate $certificate
Ensure-TestSigningMode

$volumeGuid = Resolve-VolumeGuid -Volume $ProtectedVolume
Write-Step "Writing SecureVol policy for $ProtectedVolume ($volumeGuid)"
Write-Policy -PolicyPath $policyPath -VolumeGuid $volumeGuid -AppUser $targetUser -ProtectionEnabled $EnableProtection.IsPresent

if (-not (Test-Path $cliPath)) {
    throw "CLI not found after publish: '$cliPath'."
}

if (-not (Test-Path $serviceExe)) {
    throw "Service executable not found after publish: '$serviceExe'."
}

Ensure-ServiceInstalled -ServiceExe $serviceExe
Ensure-ServiceRunning
Stop-FilterIfRunning
Install-DriverFromPackage -PackageDir $packageDir
Ensure-FilterLoaded
Ensure-FilterAttachedToVolume -Volume $ProtectedVolume
Wait-ForDriverConnection -CliPath $cliPath
Set-ProtectionState -CliPath $cliPath -ProtectionEnabled:$EnableProtection.IsPresent

Show-FinalSummary -VolumeGuid $volumeGuid -ProtectionEnabled $EnableProtection.IsPresent

Write-Host "`n[SecureVol] Completed." -ForegroundColor Green
if (-not $EnableProtection) {
    Write-Host '[SecureVol] Protection is currently disabled. Enable later with: out\cli\securevol.exe protection enable' -ForegroundColor Yellow
}
