namespace ServiceLib.Tests.Common;

/// <summary>
/// PattN: the choices a fixed dropdown of the server editor (alpn, curvePreferences) offers for a profile whose value is
/// none of them, as a share link can carry any: the value comes after the choices, so that the box shows it.
/// </summary>
public class DropdownChoicesTests
{
    [Test]
    public async Task AValueNoChoiceHoldsComesAfterTheChoices()
    {
        await DropdownChoices.With(Global.CurvePreferences, "CurveP256").SequenceEqual([.. Global.CurvePreferences, "CurveP256"]).Should().BeTrue();
        await DropdownChoices.With(Global.Alpns, "h2,h3").SequenceEqual([.. Global.Alpns, "h2,h3"]).Should().BeTrue();
        // Compared as written: the same names in another order or case are a value of their own.
        await DropdownChoices.With(Global.CurvePreferences, "X25519,X25519MLKEM768").Last().Should().BeEqualTo("X25519,X25519MLKEM768");
        await DropdownChoices.With(Global.CurvePreferences, "x25519").Last().Should().BeEqualTo("x25519");
    }

    [Test]
    public async Task AChoiceOrNoValueLeavesTheChoicesAsTheyAre()
    {
        foreach (var value in new[] { null, "", "X25519", "X25519MLKEM768,X25519" })
        {
            await DropdownChoices.With(Global.CurvePreferences, value).SequenceEqual(Global.CurvePreferences).Should().BeTrue().Because(value ?? "null");
        }
        await DropdownChoices.With(Global.Alpns, "h3,h2").SequenceEqual(Global.Alpns).Should().BeTrue();

        // The settings' own lists are never changed.
        _ = DropdownChoices.With(Global.CurvePreferences, "CurveP256");
        _ = DropdownChoices.With(Global.Alpns, "h2,h3");
        await Global.CurvePreferences.Count.Should().BeEqualTo(4);
        await Global.Alpns.Contains("h2,h3").Should().BeFalse();
    }
}
