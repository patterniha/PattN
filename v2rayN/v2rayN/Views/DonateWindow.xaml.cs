using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;

namespace v2rayN.Views;

/// <summary>
/// PattN: PattN's donation wallets, <see cref="Global.DonationWallets" />: each network beside its address, which can be
/// selected, and a button that copies the address whole, showing a check mark for a moment; OK closes the window.
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

        WindowsUtils.SetDarkBorder(this, AppManager.Instance.Config.UiItem.CurrentTheme);
    }
}
