using Avalonia.Automation;
using Avalonia.Layout;
using v2rayN.Desktop.Common;

namespace v2rayN.Desktop.Views;

/// <summary>
/// PattN: PattN's donation wallets, <see cref="Global.DonationWallets" />, a twin of the WPF window: each network beside
/// its address, which can be selected, and a button that copies the address whole, showing a check mark for a moment;
/// below them the author's ID, <see cref="Global.AuthorId" />, a link to the author's Telegram; OK closes the window.
/// </summary>
public partial class DonateWindow : Window
{
    public DonateWindow()
    {
        InitializeComponent();

        var margin = new Thickness(4);
        foreach (var (network, address) in Global.DonationWallets)
        {
            var row = gridWallets.RowDefinitions.Count;
            gridWallets.RowDefinitions.Add(new RowDefinition(GridLength.Auto));

            var label = new TextBlock
            {
                Text = network,
                Margin = margin,
                VerticalAlignment = VerticalAlignment.Center,
            };
            var box = new TextBox
            {
                Text = address,
                IsReadOnly = true,
                Margin = margin,
                VerticalAlignment = VerticalAlignment.Center,
                FontFamily = new FontFamily("Cascadia Code,Consolas,Monospace"),
            };
            AutomationProperties.SetName(box, network);
            var copy = new Button
            {
                Content = ResUI.menuEditCopy,
                MinWidth = 100,
                Margin = margin,
                HorizontalContentAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
            };
            AutomationProperties.SetName(copy, $"{ResUI.menuEditCopy} {network}");
            var clicks = 0;
            copy.Click += async (_, _) =>
            {
                await AvaUtils.SetClipboardData(this, address);
                var click = ++clicks;
                // The check mark keeps the button's width, so that the window does not resize under it
                copy.MinWidth = copy.Bounds.Width;
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
        gridWallets.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
        var idLabel = new TextBlock
        {
            Text = "ID",
            Margin = margin,
            VerticalAlignment = VerticalAlignment.Center,
        };
        var idLink = new HyperlinkButton
        {
            Content = Global.AuthorId,
            Margin = margin,
            HorizontalAlignment = HorizontalAlignment.Left,
            VerticalAlignment = VerticalAlignment.Center,
            FontFamily = new FontFamily("Cascadia Code,Consolas,Monospace"),
        };
        ToolTip.SetTip(idLink, Global.AuthorTelegramUrl);
        AutomationProperties.SetName(idLink, $"ID {Global.AuthorId}");
        idLink.Click += (_, _) => ProcUtils.ProcessStart(Global.AuthorTelegramUrl);
        Grid.SetRow(idLabel, idRow);
        Grid.SetRow(idLink, idRow);
        Grid.SetColumn(idLink, 1);
        gridWallets.Children.Add(idLabel);
        gridWallets.Children.Add(idLink);

        btnOk.Click += (_, _) => Close();
        CanMinimize = false;
    }
}
