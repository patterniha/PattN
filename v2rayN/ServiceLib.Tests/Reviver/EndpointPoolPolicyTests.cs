using ServiceLib.Discovery.Models;

namespace ServiceLib.Tests.Reviver;

public class EndpointPoolPolicyTests
{
    [Test]
    public async Task NormalizeLabel_ShouldTrimAndBoundLabels()
    {
        await EndpointPoolPolicy.NormalizeLabel("  primary edge  ").Should().BeEqualTo("primary edge");

        var threw = false;
        try
        {
            EndpointPoolPolicy.NormalizeLabel(new string('x', EndpointPoolPolicy.MaxLabelLength + 1));
        }
        catch (ArgumentOutOfRangeException)
        {
            threw = true;
        }

        await threw.Should().BeTrue();
    }
}
