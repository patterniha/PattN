using System.Collections.Specialized;

namespace v2rayN.Views;

/// <summary>
/// PattN: the log panel of the Aether pages, for an <see cref="AetherLogViewModel" />: errors in the error colour,
/// warnings in amber, the core's own output dimmed; it follows the newest line, and Copy puts every line on the clipboard.
/// </summary>
public partial class AetherLogPanel
{
    private AetherLogViewModel? _shown;

    public AetherLogPanel()
    {
        InitializeComponent();

        btnCopy.Click += (_, _) =>
        {
            if (ViewModel is { } log && log.Entries.Count > 0)
            {
                WindowsUtils.SetClipboardData(log.Text);
                NoticeManager.Instance.Enqueue(ResUI.OperationSuccess);
            }
        };

        this.WhenActivated(disposables =>
        {
            this.WhenAnyValue(v => v.ViewModel)
                .Subscribe(Show)
                .DisposeWith(disposables);
        });
    }

    private void Show(AetherLogViewModel? log)
    {
        if (_shown != null)
        {
            _shown.Entries.CollectionChanged -= OnEntriesChanged;
        }
        _shown = log;
        lstLog.ItemsSource = log?.Entries;
        txtEmpty.Text = log?.EmptyText ?? string.Empty;
        if (log != null)
        {
            log.Entries.CollectionChanged += OnEntriesChanged;
        }
        OnEntriesChanged(null, null);
    }

    private void OnEntriesChanged(object? sender, NotifyCollectionChangedEventArgs? e)
    {
        var entries = _shown?.Entries;
        var any = entries is { Count: > 0 };
        txtEmpty.Visibility = any ? Visibility.Collapsed : Visibility.Visible;
        btnCopy.IsEnabled = any;
        if (any)
        {
            lstLog.ScrollIntoView(entries![^1]);
        }
    }
}
