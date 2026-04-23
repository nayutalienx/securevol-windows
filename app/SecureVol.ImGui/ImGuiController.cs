using System.Numerics;
using ImGuiNET;
using OpenTK.Graphics.OpenGL4;
using OpenTK.Windowing.Desktop;
using OpenTK.Windowing.GraphicsLibraryFramework;
using ImGuiApi = ImGuiNET.ImGui;
using Matrix4 = OpenTK.Mathematics.Matrix4;

namespace SecureVol.ImGui;

internal sealed class ImGuiController : IDisposable
{
    private readonly IntPtr _context;
    private int _vertexArray;
    private int _vertexBuffer;
    private int _indexBuffer;
    private int _vertexBufferSize;
    private int _indexBufferSize;
    private int _fontTexture;
    private int _shaderProgram;
    private int _shaderVertex;
    private int _shaderFragment;
    private int _attribLocationTex;
    private int _attribLocationProjMtx;
    private int _attribLocationPosition;
    private int _attribLocationUv;
    private int _attribLocationColor;
    private bool _frameBegun;

    public ImGuiController(int width, int height)
    {
        _context = ImGuiApi.CreateContext();
        ImGuiApi.SetCurrentContext(_context);
        var io = ImGuiApi.GetIO();
        io.ConfigFlags |= ImGuiConfigFlags.NavEnableKeyboard;
        io.ConfigFlags |= ImGuiConfigFlags.DockingEnable;
        io.BackendFlags |= ImGuiBackendFlags.RendererHasVtxOffset;
        io.Fonts.AddFontDefault();

        ImGuiApi.StyleColorsDark();
        var style = ImGuiApi.GetStyle();
        style.WindowRounding = 6.0f;
        style.FrameRounding = 6.0f;
        style.GrabRounding = 6.0f;
        style.Colors[(int)ImGuiCol.WindowBg] = new Vector4(0.08f, 0.09f, 0.11f, 1.0f);
        style.Colors[(int)ImGuiCol.ChildBg] = new Vector4(0.11f, 0.12f, 0.15f, 1.0f);
        style.Colors[(int)ImGuiCol.Button] = new Vector4(0.16f, 0.39f, 0.83f, 1.0f);
        style.Colors[(int)ImGuiCol.ButtonHovered] = new Vector4(0.25f, 0.49f, 0.95f, 1.0f);
        style.Colors[(int)ImGuiCol.ButtonActive] = new Vector4(0.14f, 0.31f, 0.72f, 1.0f);

        CreateDeviceResources();
        SetPerFrameImGuiData(1f / 60f, width, height);
        ImGuiApi.NewFrame();
        _frameBegun = true;
    }

    public void Update(GameWindow window, float deltaSeconds)
    {
        if (_frameBegun)
        {
            ImGuiApi.Render();
        }

        SetPerFrameImGuiData(deltaSeconds, window.ClientSize.X, window.ClientSize.Y);
        UpdateInput(window);

        _frameBegun = true;
        ImGuiApi.NewFrame();
    }

    public void PressChar(uint character)
    {
        ImGuiApi.GetIO().AddInputCharacter(character);
    }

    public void Render()
    {
        if (!_frameBegun)
        {
            return;
        }

        _frameBegun = false;
        ImGuiApi.Render();
        RenderImDrawData(ImGuiApi.GetDrawData());
    }

    public void WindowResized(int width, int height)
    {
        SetPerFrameImGuiData(ImGuiApi.GetIO().DeltaTime, width, height);
    }

    public void Dispose()
    {
        if (_vertexBuffer != 0)
        {
            GL.DeleteBuffer(_vertexBuffer);
        }

        if (_indexBuffer != 0)
        {
            GL.DeleteBuffer(_indexBuffer);
        }

        if (_vertexArray != 0)
        {
            GL.DeleteVertexArray(_vertexArray);
        }

        if (_fontTexture != 0)
        {
            GL.DeleteTexture(_fontTexture);
        }

        if (_shaderProgram != 0)
        {
            GL.DeleteProgram(_shaderProgram);
            GL.DeleteShader(_shaderVertex);
            GL.DeleteShader(_shaderFragment);
        }

        ImGuiApi.DestroyContext(_context);
    }

    private void SetPerFrameImGuiData(float deltaSeconds, int width, int height)
    {
        var io = ImGuiApi.GetIO();
        io.DisplaySize = new Vector2(width, height);
        io.DisplayFramebufferScale = Vector2.One;
        io.DeltaTime = deltaSeconds > 0 ? deltaSeconds : 1f / 60f;
    }

    private void UpdateInput(GameWindow window)
    {
        var io = ImGuiApi.GetIO();
        var mouse = window.MouseState;
        var keyboard = window.KeyboardState;

        io.AddMousePosEvent(mouse.X, mouse.Y);
        io.AddMouseButtonEvent(0, mouse.IsButtonDown(MouseButton.Left));
        io.AddMouseButtonEvent(1, mouse.IsButtonDown(MouseButton.Right));
        io.AddMouseButtonEvent(2, mouse.IsButtonDown(MouseButton.Middle));
        io.AddMouseWheelEvent(mouse.ScrollDelta.X, mouse.ScrollDelta.Y);

        io.AddKeyEvent(ImGuiKey.Tab, keyboard.IsKeyDown(Keys.Tab));
        io.AddKeyEvent(ImGuiKey.LeftArrow, keyboard.IsKeyDown(Keys.Left));
        io.AddKeyEvent(ImGuiKey.RightArrow, keyboard.IsKeyDown(Keys.Right));
        io.AddKeyEvent(ImGuiKey.UpArrow, keyboard.IsKeyDown(Keys.Up));
        io.AddKeyEvent(ImGuiKey.DownArrow, keyboard.IsKeyDown(Keys.Down));
        io.AddKeyEvent(ImGuiKey.PageUp, keyboard.IsKeyDown(Keys.PageUp));
        io.AddKeyEvent(ImGuiKey.PageDown, keyboard.IsKeyDown(Keys.PageDown));
        io.AddKeyEvent(ImGuiKey.Home, keyboard.IsKeyDown(Keys.Home));
        io.AddKeyEvent(ImGuiKey.End, keyboard.IsKeyDown(Keys.End));
        io.AddKeyEvent(ImGuiKey.Insert, keyboard.IsKeyDown(Keys.Insert));
        io.AddKeyEvent(ImGuiKey.Delete, keyboard.IsKeyDown(Keys.Delete));
        io.AddKeyEvent(ImGuiKey.Backspace, keyboard.IsKeyDown(Keys.Backspace));
        io.AddKeyEvent(ImGuiKey.Space, keyboard.IsKeyDown(Keys.Space));
        io.AddKeyEvent(ImGuiKey.Enter, keyboard.IsKeyDown(Keys.Enter));
        io.AddKeyEvent(ImGuiKey.Escape, keyboard.IsKeyDown(Keys.Escape));
        io.AddKeyEvent(ImGuiKey.A, keyboard.IsKeyDown(Keys.A));
        io.AddKeyEvent(ImGuiKey.C, keyboard.IsKeyDown(Keys.C));
        io.AddKeyEvent(ImGuiKey.V, keyboard.IsKeyDown(Keys.V));
        io.AddKeyEvent(ImGuiKey.X, keyboard.IsKeyDown(Keys.X));
        io.AddKeyEvent(ImGuiKey.Y, keyboard.IsKeyDown(Keys.Y));
        io.AddKeyEvent(ImGuiKey.Z, keyboard.IsKeyDown(Keys.Z));
        io.AddKeyEvent(ImGuiKey.LeftCtrl, keyboard.IsKeyDown(Keys.LeftControl));
        io.AddKeyEvent(ImGuiKey.RightCtrl, keyboard.IsKeyDown(Keys.RightControl));
        io.AddKeyEvent(ImGuiKey.LeftShift, keyboard.IsKeyDown(Keys.LeftShift));
        io.AddKeyEvent(ImGuiKey.RightShift, keyboard.IsKeyDown(Keys.RightShift));
        io.AddKeyEvent(ImGuiKey.LeftAlt, keyboard.IsKeyDown(Keys.LeftAlt));
        io.AddKeyEvent(ImGuiKey.RightAlt, keyboard.IsKeyDown(Keys.RightAlt));
        io.AddKeyEvent(ImGuiKey.LeftSuper, keyboard.IsKeyDown(Keys.LeftSuper));
        io.AddKeyEvent(ImGuiKey.RightSuper, keyboard.IsKeyDown(Keys.RightSuper));
    }

    private void CreateDeviceResources()
    {
        _vertexBufferSize = 10_000;
        _indexBufferSize = 2_000;

        _vertexBuffer = GL.GenBuffer();
        _indexBuffer = GL.GenBuffer();
        _vertexArray = GL.GenVertexArray();

        RecreateFontDeviceTexture();
        CreateShaders();
        CreateVertexArray();
    }

    private unsafe void RecreateFontDeviceTexture()
    {
        var io = ImGuiApi.GetIO();
        io.Fonts.GetTexDataAsRGBA32(out byte* pixels, out var width, out var height, out _);

        var previousTexture = GL.GetInteger(GetPName.TextureBinding2D);
        _fontTexture = GL.GenTexture();
        GL.BindTexture(TextureTarget.Texture2D, _fontTexture);
        GL.TexParameter(TextureTarget.Texture2D, TextureParameterName.TextureMinFilter, (int)TextureMinFilter.Linear);
        GL.TexParameter(TextureTarget.Texture2D, TextureParameterName.TextureMagFilter, (int)TextureMagFilter.Linear);
        GL.PixelStore(PixelStoreParameter.UnpackRowLength, 0);
        GL.TexImage2D(TextureTarget.Texture2D, 0, PixelInternalFormat.Rgba, width, height, 0, PixelFormat.Rgba, PixelType.UnsignedByte, (nint)pixels);

        io.Fonts.SetTexID((IntPtr)_fontTexture);
        io.Fonts.ClearTexData();
        GL.BindTexture(TextureTarget.Texture2D, previousTexture);
    }

    private void CreateShaders()
    {
        const string vertexSource = @"
#version 330 core
layout (location = 0) in vec2 in_position;
layout (location = 1) in vec2 in_uv;
layout (location = 2) in vec4 in_color;
uniform mat4 projection_matrix;
out vec2 frag_uv;
out vec4 frag_color;
void main()
{
    frag_uv = in_uv;
    frag_color = in_color;
    gl_Position = projection_matrix * vec4(in_position, 0, 1);
}";

        const string fragmentSource = @"
#version 330 core
in vec2 frag_uv;
in vec4 frag_color;
uniform sampler2D in_fontTexture;
layout (location = 0) out vec4 output_color;
void main()
{
    output_color = frag_color * texture(in_fontTexture, frag_uv.st);
}";

        _shaderVertex = GL.CreateShader(ShaderType.VertexShader);
        GL.ShaderSource(_shaderVertex, vertexSource);
        GL.CompileShader(_shaderVertex);

        _shaderFragment = GL.CreateShader(ShaderType.FragmentShader);
        GL.ShaderSource(_shaderFragment, fragmentSource);
        GL.CompileShader(_shaderFragment);

        _shaderProgram = GL.CreateProgram();
        GL.AttachShader(_shaderProgram, _shaderVertex);
        GL.AttachShader(_shaderProgram, _shaderFragment);
        GL.LinkProgram(_shaderProgram);

        _attribLocationTex = GL.GetUniformLocation(_shaderProgram, "in_fontTexture");
        _attribLocationProjMtx = GL.GetUniformLocation(_shaderProgram, "projection_matrix");
        _attribLocationPosition = 0;
        _attribLocationUv = 1;
        _attribLocationColor = 2;
    }

    private unsafe void CreateVertexArray()
    {
        GL.BindVertexArray(_vertexArray);
        GL.BindBuffer(BufferTarget.ArrayBuffer, _vertexBuffer);
        GL.BufferData(BufferTarget.ArrayBuffer, _vertexBufferSize, IntPtr.Zero, BufferUsageHint.DynamicDraw);
        GL.BindBuffer(BufferTarget.ElementArrayBuffer, _indexBuffer);
        GL.BufferData(BufferTarget.ElementArrayBuffer, _indexBufferSize, IntPtr.Zero, BufferUsageHint.DynamicDraw);

        var stride = sizeof(ImDrawVert);
        GL.EnableVertexAttribArray(_attribLocationPosition);
        GL.EnableVertexAttribArray(_attribLocationUv);
        GL.EnableVertexAttribArray(_attribLocationColor);

        GL.VertexAttribPointer(_attribLocationPosition, 2, VertexAttribPointerType.Float, false, stride, 0);
        GL.VertexAttribPointer(_attribLocationUv, 2, VertexAttribPointerType.Float, false, stride, 8);
        GL.VertexAttribPointer(_attribLocationColor, 4, VertexAttribPointerType.UnsignedByte, true, stride, 16);

        GL.BindVertexArray(0);
        GL.BindBuffer(BufferTarget.ArrayBuffer, 0);
        GL.BindBuffer(BufferTarget.ElementArrayBuffer, 0);
    }

    private unsafe void RenderImDrawData(ImDrawDataPtr drawData)
    {
        if (drawData.CmdListsCount == 0)
        {
            return;
        }

        var io = ImGuiApi.GetIO();
        var framebufferWidth = (int)(io.DisplaySize.X * io.DisplayFramebufferScale.X);
        var framebufferHeight = (int)(io.DisplaySize.Y * io.DisplayFramebufferScale.Y);

        if (framebufferWidth <= 0 || framebufferHeight <= 0)
        {
            return;
        }

        drawData.ScaleClipRects(io.DisplayFramebufferScale);

        GL.Enable(EnableCap.Blend);
        GL.BlendEquation(BlendEquationMode.FuncAdd);
        GL.BlendFunc(BlendingFactor.SrcAlpha, BlendingFactor.OneMinusSrcAlpha);
        GL.Disable(EnableCap.CullFace);
        GL.Disable(EnableCap.DepthTest);
        GL.Enable(EnableCap.ScissorTest);
        GL.ActiveTexture(TextureUnit.Texture0);
        GL.Viewport(0, 0, framebufferWidth, framebufferHeight);

        var projection = Matrix4.CreateOrthographicOffCenter(
            0.0f,
            io.DisplaySize.X,
            io.DisplaySize.Y,
            0.0f,
            -1.0f,
            1.0f);

        GL.UseProgram(_shaderProgram);
        GL.Uniform1(_attribLocationTex, 0);
        GL.UniformMatrix4(_attribLocationProjMtx, false, ref projection);
        GL.BindVertexArray(_vertexArray);

        for (var n = 0; n < drawData.CmdListsCount; n++)
        {
            var commandList = drawData.CmdLists[n];
            var vertexSize = commandList.VtxBuffer.Size * sizeof(ImDrawVert);
            if (vertexSize > _vertexBufferSize)
            {
                while (vertexSize > _vertexBufferSize)
                {
                    _vertexBufferSize *= 2;
                }

                GL.BindBuffer(BufferTarget.ArrayBuffer, _vertexBuffer);
                GL.BufferData(BufferTarget.ArrayBuffer, _vertexBufferSize, IntPtr.Zero, BufferUsageHint.DynamicDraw);
            }

            var indexSize = commandList.IdxBuffer.Size * sizeof(ushort);
            if (indexSize > _indexBufferSize)
            {
                while (indexSize > _indexBufferSize)
                {
                    _indexBufferSize *= 2;
                }

                GL.BindBuffer(BufferTarget.ElementArrayBuffer, _indexBuffer);
                GL.BufferData(BufferTarget.ElementArrayBuffer, _indexBufferSize, IntPtr.Zero, BufferUsageHint.DynamicDraw);
            }

            GL.BindBuffer(BufferTarget.ArrayBuffer, _vertexBuffer);
            GL.BufferSubData(BufferTarget.ArrayBuffer, IntPtr.Zero, vertexSize, (IntPtr)commandList.VtxBuffer.Data);

            GL.BindBuffer(BufferTarget.ElementArrayBuffer, _indexBuffer);
            GL.BufferSubData(BufferTarget.ElementArrayBuffer, IntPtr.Zero, indexSize, (IntPtr)commandList.IdxBuffer.Data);

            for (var cmdIndex = 0; cmdIndex < commandList.CmdBuffer.Size; cmdIndex++)
            {
                var drawCommand = commandList.CmdBuffer[cmdIndex];
                GL.BindTexture(TextureTarget.Texture2D, (int)drawCommand.TextureId);
                GL.Scissor(
                    (int)drawCommand.ClipRect.X,
                    (int)(framebufferHeight - drawCommand.ClipRect.W),
                    (int)(drawCommand.ClipRect.Z - drawCommand.ClipRect.X),
                    (int)(drawCommand.ClipRect.W - drawCommand.ClipRect.Y));

                GL.DrawElementsBaseVertex(
                    PrimitiveType.Triangles,
                    (int)drawCommand.ElemCount,
                    DrawElementsType.UnsignedShort,
                    (IntPtr)(drawCommand.IdxOffset * sizeof(ushort)),
                    (int)drawCommand.VtxOffset);
            }
        }

        GL.Disable(EnableCap.ScissorTest);
        GL.BindVertexArray(0);
        GL.UseProgram(0);
        GL.BindTexture(TextureTarget.Texture2D, 0);
    }
}
