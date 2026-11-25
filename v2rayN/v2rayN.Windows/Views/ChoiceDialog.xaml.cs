using System.Windows.Controls;

namespace v2rayN.Views;

/// <summary>
/// PattN: a question that offers buttons of its own (design 3.2.4: "Save anyway", "Get new WARP keys…", Cancel), which a
/// MessageBox cannot. <see cref="Choice" /> is the index of the button clicked; -1 when the window was closed otherwise.
/// </summary>
public partial class ChoiceDialog
{
    public ChoiceDialog()
        : this(string.Empty, string.Empty, [], -1)
    {
    }

    /// <summary>
    /// The question <paramref name="message" />, titled <paramref name="title" />, with <paramref name="buttons" /> from
    /// left to right; the first is the default one, and the one at <paramref name="cancelIndex" /> answers Esc.
    /// </summary>
    public ChoiceDialog(string title, string message, IReadOnlyList<string> buttons, int cancelIndex)
    {
        InitializeComponent();

        Title = title;
        txtMessage.Text = message;
        for (var index = 0; index < buttons.Count; index++)
        {
            var choice = index;
            var button = new Button
            {
                Content = buttons[index],
                MinWidth = 100,
                Margin = (Thickness)FindResource("MarginLeftRight4"),
                Style = (Style)FindResource("DefButton"),
                IsDefault = index == 0,
                IsCancel = index == cancelIndex,
            };
            button.Click += (_, _) =>
            {
                Choice = choice;
                DialogResult = true;
            };
            panelButtons.Children.Add(button);
        }

        WindowsUtils.SetDarkBorder(this, ConfigTextHandler.Config.UiItem.CurrentTheme);
    }

    /// <summary>The index of the button clicked; -1 until one is, and when the window is closed otherwise.</summary>
    public int Choice { get; private set; } = -1;
}
