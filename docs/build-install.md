# Stage B / Build and Install

## Repository layout

```text
/cli
  /SecureVol.Cli
/common
  /include
  /SecureVol.Common
/docs
/driver
  /SecureVolFlt
/examples
/service
  /SecureVol.Service
/tests
  /SecureVol.Service.Tests
SecureVol.sln
```

## Prerequisites

- Windows 11 x64
- Visual Studio 2022
- Latest Windows 11 SDK
- Latest WDK with minifilter support
- .NET 8 SDK/runtime
- Administrator shell for driver install/load, service install, and policy directory ACL setup

## Managed build

From the repo root:

```powershell
dotnet build .\common\SecureVol.Common\SecureVol.Common.csproj
dotnet build .\service\SecureVol.Service\SecureVol.Service.csproj
dotnet build .\cli\SecureVol.Cli\SecureVol.Cli.csproj
```

Unit tests:

```powershell
dotnet test .\tests\SecureVol.Service.Tests\SecureVol.Service.Tests.csproj
```

If only .NET 9 runtime is present locally, you can still run the `net8.0-windows` tests with:

```powershell
$env:DOTNET_ROLL_FORWARD='Major'
dotnet test .\tests\SecureVol.Service.Tests\SecureVol.Service.Tests.csproj
```

## Driver build

Open [SecureVol.sln](/C:/Users/nayut/OneDrive/Desktop/vera-crypt-allowlist/SecureVol.sln) in Visual Studio 2022 after installing the WDK. Build the `SecureVolFlt` project from the IDE or Developer Command Prompt with MSBuild.

Notes:

- The driver project is intentionally not built with `dotnet build`.
- The INF uses a placeholder test altitude. Replace it with an assigned production altitude before broader deployment.

## Install sequence

Recommended safe first-time workflow:

1. Build the service, CLI, and driver.
2. Install the minifilter INF:

```powershell
.\cli\SecureVol.Cli\bin\Debug\net8.0-windows\securevol.exe driver install-inf --inf ".\driver\SecureVolFlt\SecureVolFlt.inf"
```

3. Install the service:

```powershell
.\cli\SecureVol.Cli\bin\Debug\net8.0-windows\securevol.exe service install --service-exe ".\service\SecureVol.Service\bin\Debug\net8.0-windows\SecureVol.Service.exe"
```

4. Start the service:

```powershell
.\cli\SecureVol.Cli\bin\Debug\net8.0-windows\securevol.exe service start
```

5. Set the protected mounted volume:

```powershell
.\cli\SecureVol.Cli\bin\Debug\net8.0-windows\securevol.exe volume set --volume V:
```

6. Add allow rules. Example for Chrome:

```powershell
.\cli\SecureVol.Cli\bin\Debug\net8.0-windows\securevol.exe rule add --name chrome --image "C:\Program Files\Google\Chrome\Application\chrome.exe" --publisher "Google LLC" --user ".\vc_app" --require-signed
```

7. Enable protection:

```powershell
.\cli\SecureVol.Cli\bin\Debug\net8.0-windows\securevol.exe protection enable
```

8. Load the minifilter:

```powershell
.\cli\SecureVol.Cli\bin\Debug\net8.0-windows\securevol.exe driver load
```

9. Verify state:

```powershell
.\cli\SecureVol.Cli\bin\Debug\net8.0-windows\securevol.exe state
```

## Dedicated-user launch examples

Chrome:

```powershell
.\cli\SecureVol.Cli\bin\Debug\net8.0-windows\securevol.exe launch --app "C:\Program Files\Google\Chrome\Application\chrome.exe" --args "--user-data-dir=V:\ChromeProfile" --user ".\vc_app"
```

Portable Telegram:

```powershell
.\cli\SecureVol.Cli\bin\Debug\net8.0-windows\securevol.exe launch --app "V:\Apps\Telegram\Telegram.exe" --args "" --user ".\vc_app"
```

The CLI intentionally prompts for the password at launch time. It does not store credentials.

## Emergency recovery

Fastest recovery path:

```powershell
.\cli\SecureVol.Cli\bin\Debug\net8.0-windows\securevol.exe protection disable
.\cli\SecureVol.Cli\bin\Debug\net8.0-windows\securevol.exe driver unload
```

If the service is unavailable, update `C:\ProgramData\SecureVol\config\policy.json` manually to set `"protectionEnabled": false`, then unload the filter:

```powershell
fltmc unload SecureVolFlt
```

Safe Mode guidance:

- Do not start the service or load the minifilter.
- Because the INF uses manual start, the filter is not required on the boot path.

## Uninstall

```powershell
.\cli\SecureVol.Cli\bin\Debug\net8.0-windows\securevol.exe protection disable
.\cli\SecureVol.Cli\bin\Debug\net8.0-windows\securevol.exe driver unload
.\cli\SecureVol.Cli\bin\Debug\net8.0-windows\securevol.exe service stop
.\cli\SecureVol.Cli\bin\Debug\net8.0-windows\securevol.exe service uninstall
```

Then remove the driver package with `pnputil /delete-driver <published-oem-inf> /uninstall /force` after identifying the published INF name with `pnputil /enum-drivers`.
