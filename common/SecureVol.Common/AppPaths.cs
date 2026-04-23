using System.Security.AccessControl;
using System.Security.Principal;

namespace SecureVol.Common;

public static class AppPaths
{
    public const string DriverPortName = @"\SecureVolPort";
    public const string AdminPipeName = "SecureVolAdmin";

    public static string ProgramDataRoot =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SecureVol");

    public static string ConfigDirectory => Path.Combine(ProgramDataRoot, "config");
    public static string LogDirectory => Path.Combine(ProgramDataRoot, "logs");
    public static string PolicyFilePath => Path.Combine(ConfigDirectory, "policy.json");
    public static string StatusFilePath => Path.Combine(ConfigDirectory, "status.json");

    public static void EnsureDirectories()
    {
        Directory.CreateDirectory(ProgramDataRoot);
        Directory.CreateDirectory(ConfigDirectory);
        Directory.CreateDirectory(LogDirectory);
    }

    public static void EnsureDefaultAcls()
    {
        EnsureDirectories();

        var directoryInfo = new DirectoryInfo(ConfigDirectory);
        var security = directoryInfo.GetAccessControl();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        directoryInfo.SetAccessControl(security);
    }
}
