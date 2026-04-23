using Microsoft.Win32;
using SecureVol.AppCore;
using SecureVol.Common.Policy;
using System.IO;
using System.Windows;
using System.Windows.Input;

namespace SecureVol.App;

public partial class AddRuleWindow : Window
{
    private readonly SecureVolDesktopController _controller;

    public AddRuleWindow(SecureVolDesktopController controller, string? defaultExpectedUser)
    {
        _controller = controller;
        InitializeComponent();

        ExpectedUserTextBox.Text = defaultExpectedUser ?? string.Empty;
        NotesTextBox.Text = "Added from SecureVol desktop manager.";
    }

    public AllowRule? CreatedRule { get; private set; }

    private async void BrowseExecutableButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Executable files (*.exe)|*.exe|All files (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false,
            Title = "Choose an application executable"
        };

        if (dialog.ShowDialog(this) == true)
        {
            ExecutablePathTextBox.Text = dialog.FileName;
            await InspectExecutableAsync(dialog.FileName).ConfigureAwait(true);
        }
    }

    private async void InspectExecutableButton_Click(object sender, RoutedEventArgs e)
    {
        await InspectExecutableAsync(ExecutablePathTextBox.Text).ConfigureAwait(true);
    }

    private async Task InspectExecutableAsync(string executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            MessageBox.Show(this, "Choose an executable first.", "SecureVol", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            Mouse.OverrideCursor = Cursors.Wait;
            var facts = await _controller.ProbeExecutableAsync(executablePath, CancellationToken.None).ConfigureAwait(true);

            ExecutablePathTextBox.Text = facts.NormalizedPath;
            RuleNameTextBox.Text = string.IsNullOrWhiteSpace(RuleNameTextBox.Text)
                ? Path.GetFileNameWithoutExtension(facts.NormalizedPath)
                : RuleNameTextBox.Text;
            PublisherTextBox.Text = facts.Publisher ?? string.Empty;
            Sha256TextBox.Text = facts.Sha256;
            RequireSignatureCheckBox.IsChecked = facts.IsSigned;
            ExecutableFactsTextBlock.Text = facts.IsSigned
                ? $"Signed by {facts.Publisher ?? "an unknown publisher"}. SHA-256 captured and ready to pin."
                : "The executable is not Authenticode-signed. SHA-256 was captured, but publisher validation is unavailable.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "SecureVol", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            Mouse.OverrideCursor = null;
        }
    }

    private void SaveRuleButton_Click(object sender, RoutedEventArgs e)
    {
        var executablePath = ExecutablePathTextBox.Text.Trim();
        var ruleName = RuleNameTextBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath))
        {
            MessageBox.Show(this, "Choose a valid executable path.", "SecureVol", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (string.IsNullOrWhiteSpace(ruleName))
        {
            MessageBox.Show(this, "Enter a rule name.", "SecureVol", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        CreatedRule = new AllowRule
        {
            Name = ruleName,
            ImagePath = PolicyConfig.NormalizePath(executablePath),
            Sha256 = string.IsNullOrWhiteSpace(Sha256TextBox.Text) ? null : Sha256TextBox.Text.Trim(),
            RequireSignature = RequireSignatureCheckBox.IsChecked == true,
            Publisher = string.IsNullOrWhiteSpace(PublisherTextBox.Text) ? null : PublisherTextBox.Text.Trim(),
            ExpectedUser = string.IsNullOrWhiteSpace(ExpectedUserTextBox.Text) ? null : ExpectedUserTextBox.Text.Trim(),
            Notes = string.IsNullOrWhiteSpace(NotesTextBox.Text) ? null : NotesTextBox.Text.Trim()
        };

        DialogResult = true;
        Close();
    }
}
