using OpenTK.Mathematics;
using OpenTK.Windowing.Common;
using OpenTK.Windowing.Desktop;
using OpenTK.Windowing.GraphicsLibraryFramework;

namespace SecureVol.ImGui;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        var nativeWindowSettings = new NativeWindowSettings
        {
            Title = "SecureVol",
            ClientSize = new Vector2i(1460, 920),
            API = ContextAPI.OpenGL,
            APIVersion = new Version(4, 1),
            Profile = ContextProfile.Core,
            Flags = ContextFlags.ForwardCompatible,
            WindowBorder = WindowBorder.Resizable
        };

        using var window = new SecureVolImGuiWindow(
            GameWindowSettings.Default,
            nativeWindowSettings);

        window.Run();
    }
}
