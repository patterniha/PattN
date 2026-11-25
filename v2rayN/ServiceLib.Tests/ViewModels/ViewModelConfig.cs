using ReactiveUI.Builder;

namespace ServiceLib.Tests.ViewModels;

/// <summary>
/// PattN: the app's settings for a view model under test. Tests that use it share the "AppManager config" key of
/// NotInParallel, as every view model also keeps the settings it was made with in one static field.
/// </summary>
internal static class ViewModelConfig
{
    // ReactiveUI set up once for the test run, as the apps set it up at start (v2rayN App.xaml.cs), without a platform:
    // WhenAnyValue, which some view models call as they are made, throws otherwise.
    private static readonly Lazy<bool> _reactiveUi = new(() =>
    {
        RxAppBuilder.CreateReactiveUIBuilder()
            .WithCoreServices()
            .BuildApp();
        return true;
    });

    /// <summary>
    /// <paramref name="create" /> with <paramref name="config" /> as the app's settings, which a view model reads as it is
    /// made; the settings before are put back afterwards.
    /// </summary>
    public static T With<T>(Config config, Func<T> create)
    {
        _ = _reactiveUi.Value;
        var field = typeof(ConfigState).GetField("_current", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var previous = field.GetValue(ConfigState.Instance);
        field.SetValue(ConfigState.Instance, config);
        try
        {
            return create();
        }
        finally
        {
            field.SetValue(ConfigState.Instance, previous);
        }
    }
}
