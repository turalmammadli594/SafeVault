using MySqlConnector;
using NUnit.Framework;
using SafeVault.Data;

namespace SafeVault.Tests;

[TestFixture]
public class TestParameterizedQueries
{
    [Test]
    public void GetUserByUsername_UsesParameters_NotStringConcatenation()
    {
        using var conn = new MySqlConnection("Server=localhost;Database=SafeVault;User ID=root;Password=x;");
        var payload = "admin' OR 1=1 --";

        var cmd = UserRepository.BuildGetUserByUsernameCommand(conn, payload);

        Assert.False(cmd.CommandText.Contains(payload));
        Assert.True(cmd.Parameters.Contains("@username"));
        Assert.AreEqual(payload, cmd.Parameters["@username"]!.Value);
    }
}
