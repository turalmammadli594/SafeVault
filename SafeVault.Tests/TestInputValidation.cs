using NUnit.Framework;
using SafeVault.Security;

namespace SafeVault.Tests;

[TestFixture]
public class TestInputValidation
{
    [Test]
    public void TestForSQLInjection_InUsername_IsRejectedOrNeutralized()
    {
        var payload = "admin' OR 1=1; --";
        var (ok, err, sanitized) = InputSanitizer.SanitizeUsername(payload);

        Assert.IsFalse(ok);
        Assert.IsNotNull(err);
        Assert.False(sanitized.Contains("'"));
        Assert.False(sanitized.Contains(";"));
        Assert.False(sanitized.Contains("--"));
    }

    [Test]
    public void TestForXSS_InEmail_IsEncodedOrRejected()
    {
        var payload = "<script>alert(1)</script>@evil.com";
        var (ok, err, sanitized) = InputSanitizer.SanitizeEmail(payload);

        if (ok)
        {
            Assert.False(sanitized.Contains("<script>", StringComparison.OrdinalIgnoreCase));
            Assert.True(sanitized.Contains("&lt;", StringComparison.OrdinalIgnoreCase)
                        || !sanitized.Contains("script", StringComparison.OrdinalIgnoreCase));
        }
        else
        {
            Assert.IsNotNull(err);
        }
    }
}
