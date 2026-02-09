using NUnit.Framework;
using SafeVault.Security;

namespace SafeVault.Tests;

[TestFixture]
public class TestPasswordHashing
{
    [Test]
    public void Hash_Then_Verify_ShouldReturnTrue()
    {
        var password = "P@ssw0rd!";
        var hash = PasswordHasher.HashPassword(password);

        Assert.IsTrue(PasswordHasher.VerifyPassword(password, hash));
        Assert.IsFalse(PasswordHasher.VerifyPassword("wrong", hash));
    }
}
