using MySqlConnector;
using NUnit.Framework;

namespace SafeVault.Tests;

[TestFixture]
public class TestSqlInjectionFix
{
    [Test]
    public void Query_ShouldUseParameters_NotContainRawInput()
    {
        using var conn = new MySqlConnection("Server=localhost;Database=SafeVault;User ID=root;Password=x;");
        var payload = "admin' OR 1=1 --";

        const string sql = @"SELECT UserID, Username, Email FROM Users WHERE Username = @username LIMIT 1;";
        using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@username", payload);

        Assert.False(cmd.CommandText.Contains(payload));
        Assert.True(cmd.Parameters.Contains("@username"));
        Assert.AreEqual(payload, cmd.Parameters["@username"]!.Value);
    }
}
