using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;

namespace v2rayN.Views;

/// <summary>
/// PattN: PattN's donation wallets, <see cref="Global.DonationWallets" />: each network beside its address, which can be
/// selected, and a button that copies the address whole, showing a check mark for a moment; below them the author's ID,
/// <see cref="Global.AuthorId" />, a link to the author's Telegram; OK closes the window.
/// </summary>
public partial class DonateWindow
{
    public DonateWindow()
    {
        InitializeComponent();

        var margin = (Thickness)FindResource("Margin4");
        foreach (var (network, address) in Global.DonationWallets)
        {
            var row = gridWallets.RowDefinitions.Count;
            gridWallets.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var label = new TextBlock
            {
                Text = network,
                Margin = margin,
                VerticalAlignment = VerticalAlignment.Center,
                Style = (Style)FindResource("ToolbarTextBlock"),
            };
            var box = new TextBox
            {
                Text = address,
                IsReadOnly = true,
                Margin = margin,
                VerticalAlignment = VerticalAlignment.Center,
                FontFamily = new FontFamily("Consolas, Courier New"),
                Style = (Style)FindResource("DefTextBox"),
            };
            AutomationProperties.SetName(box, network);
            var copy = new Button
            {
                Content = ResUI.menuEditCopy,
                MinWidth = 100,
                Margin = margin,
                VerticalAlignment = VerticalAlignment.Center,
                Style = (Style)FindResource("DefButton"),
            };
            AutomationProperties.SetName(copy, $"{ResUI.menuEditCopy} {network}");
            var clicks = 0;
            copy.Click += async (_, _) =>
            {
                WindowsUtils.SetClipboardData(address);
                var click = ++clicks;
                // The check mark keeps the button's width, so that the window does not resize under it
                copy.MinWidth = copy.ActualWidth;
                copy.Content = "✓";
                await Task.Delay(1500);
                if (click == clicks)
                {
                    copy.Content = ResUI.menuEditCopy;
                }
            };

            Grid.SetRow(label, row);
            Grid.SetRow(box, row);
            Grid.SetColumn(box, 1);
            Grid.SetRow(copy, row);
            Grid.SetColumn(copy, 2);
            gridWallets.Children.Add(label);
            gridWallets.Children.Add(box);
            gridWallets.Children.Add(copy);
        }

        // The author's ID below the wallets, a link to the author's Telegram
        var idRow = gridWallets.RowDefinitions.Count;
        gridWallets.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        var idLabel = new TextBlock
        {
            Text = "ID",
            Margin = margin,
            VerticalAlignment = VerticalAlignment.Center,
            Style = (Style)FindResource("ToolbarTextBlock"),
        };
        var idLink = new Hyperlink(new Run(Global.AuthorId)) { ToolTip = Global.AuthorTelegramUrl };
        // The theme draws a hyperlink as plain text: the primary color marks it as one, as in the Avalonia window
        idLink.SetResourceReference(TextElement.ForegroundProperty, "MaterialDesign.Brush.Primary");
        idLink.Click += (_, _) => ProcUtils.ProcessStart(Global.AuthorTelegramUrl);
        AutomationProperties.SetName(idLink, $"ID {Global.AuthorId}");
        var idText = new TextBlock(idLink)
        {
            Margin = margin,
            VerticalAlignment = VerticalAlignment.Center,
            FontFamily = new FontFamily("Consolas, Courier New"),
            Style = (Style)FindResource("ToolbarTextBlock"),
        };
        Grid.SetRow(idLabel, idRow);
        Grid.SetRow(idText, idRow);
        Grid.SetColumn(idText, 1);
        gridWallets.Children.Add(idLabel);
        gridWallets.Children.Add(idText);

        WindowsUtils.SetDarkBorder(this, AppManager.Instance.Config.UiItem.CurrentTheme);
    }
}
