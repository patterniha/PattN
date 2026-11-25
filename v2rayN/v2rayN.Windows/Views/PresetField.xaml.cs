using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;

namespace v2rayN.Views;

/// <summary>
/// PattN: the preset field of design 3.3 (PattNG PresetField), for a <see cref="PresetFieldViewModel" />: the text, an
/// arrow whose menu lists "default", a separator and the presets by name, and under the text the name of the preset it
/// holds. Only the arrow opens the menu; a pick that would replace a value of the user's own asks first. Set
/// <see cref="IsMultiline" /> for JSON such as a finalMask, and <see cref="ShowsText" /> false where the window edits the
/// text in a box of its own.
/// </summary>
public partial class PresetField
{
    private bool _isMultiline;
    private bool _showsText = true;

    public PresetField()
    {
        InitializeComponent();

        btnChoose.Click += (_, _) => OpenMenu();

        this.WhenActivated(disposables =>
        {
            this.Bind(ViewModel, vm => vm.Text, v => v.txtValue.Text).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.HeldName, v => v.txtHeld.Text).DisposeWith(disposables);
            this.OneWayBind(ViewModel, vm => vm.HeldName, v => v.txtHeld.Visibility,
                name => string.IsNullOrEmpty(name) ? Visibility.Collapsed : Visibility.Visible).DisposeWith(disposables);

            var handler = new SingleReplaceableDisposable();
            handler.DisposeWith(disposables);
            this.WhenAnyValue(v => v.ViewModel)
                .KeepNotNull()
                .Subscribe(vm =>
                {
                    btnChoose.ToolTip = vm.ChooseTip;
                    AutomationProperties.SetName(btnChoose, vm.ChooseTip);
                    handler.Create(vm.ReplaceInteraction.RegisterHandler(interaction =>
                    {
                        var (setting, pick) = interaction.Input;
                        var choice = UI.ShowChoice(
                            string.Format(ResUI.TbPresetReplaceTitle, setting),
                            string.Format(ResUI.TbPresetReplaceMessage, setting, pick),
                            [ResUI.TbPresetReplace, ResUI.TbCancel],
                            cancelIndex: 1);
                        interaction.SetOutput(choice == 0);
                    }));
                })
                .DisposeWith(disposables);
        });
    }

    /// <summary>Whether the text runs over several lines, as a finalMask's JSON does.</summary>
    public bool IsMultiline
    {
        get => _isMultiline;
        set
        {
            _isMultiline = value;
            txtValue.AcceptsReturn = value;
            txtValue.TextWrapping = TextWrapping.NoWrap;
            txtValue.MinLines = value ? 3 : 1;
            txtValue.MaxLines = value ? 8 : 1;
            txtValue.VerticalScrollBarVisibility = value ? ScrollBarVisibility.Auto : ScrollBarVisibility.Disabled;
            txtValue.HorizontalScrollBarVisibility = value ? ScrollBarVisibility.Auto : ScrollBarVisibility.Hidden;
            txtValue.Style = (Style)FindResource(value ? "MyOutlinedTextBox" : "DefTextBox");
        }
    }

    /// <summary>
    /// Whether the field shows its own text box, as it does unless told otherwise. Without it, where the window edits the
    /// text in a box of its own (AddServerWindow's finalMask, in a popup), the arrow stands alone and the name of the
    /// preset the text holds sits beside it, so both are in sight while the popup is closed.
    /// </summary>
    public bool ShowsText
    {
        get => _showsText;
        set
        {
            _showsText = value;
            txtValue.Visibility = value ? Visibility.Visible : Visibility.Collapsed;
            Grid.SetRow(txtHeld, value ? 1 : 0);
            Grid.SetColumn(txtHeld, value ? 0 : 2);
            Grid.SetColumnSpan(txtHeld, value ? 3 : 1);
            txtHeld.VerticalAlignment = value ? VerticalAlignment.Top : VerticalAlignment.Center;
        }
    }

    private void OpenMenu()
    {
        var vm = ViewModel;
        if (vm == null)
        {
            return;
        }
        var menu = new ContextMenu
        {
            PlacementTarget = btnChoose,
            Placement = PlacementMode.Bottom,
            Style = (Style)FindResource("DefContextMenu"),
        };
        for (var index = 0; index < vm.PickNames.Count; index++)
        {
            // "default" first, set apart from the presets.
            if (index == 1)
            {
                menu.Items.Add(new Separator());
            }
            var pick = index;
            var item = new MenuItem { Header = vm.PickNames[index] };
            item.Click += async (_, _) => await vm.ChooseAtAsync(pick);
            menu.Items.Add(item);
        }
        menu.IsOpen = true;
    }
}
