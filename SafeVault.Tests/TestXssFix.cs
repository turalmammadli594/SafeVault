using NUnit.Framework;
using System.Text.Encodings.Web;

namespace SafeVault.Tests;

[TestFixture]
public class TestXssFix
{
    [Test]
    public void HtmlEncoding_ShouldNeutralizeScriptTags()
    {
        var payload = "<script>alert('xss')</script>";
        var encoded = HtmlEncoder.Default.Encode(payload);

        Assert.False(encoded.Contains("<script>", StringComparison.OrdinalIgnoreCase));
        Assert.True(encoded.Contains("&lt;script&gt;"));
    }
}
