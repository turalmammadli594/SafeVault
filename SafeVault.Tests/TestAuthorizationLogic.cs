using System.Security.Claims;
using NUnit.Framework;

namespace SafeVault.Tests;

[TestFixture]
public class TestAuthorizationLogic
{
    private static ClaimsPrincipal MakeUser(string role)
    {
        var identity = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Name, "testuser"),
            new Claim(ClaimTypes.Role, role)
        }, "TestAuth");

        return new ClaimsPrincipal(identity);
    }

    [Test]
    public void NonAdmin_CannotAccess_AdminDashboard()
    {
        var user = MakeUser("user");
        Assert.IsFalse(user.IsInRole("admin"));
    }

    [Test]
    public void Admin_CanAccess_AdminDashboard()
    {
        var user = MakeUser("admin");
        Assert.IsTrue(user.IsInRole("admin"));
    }
}
