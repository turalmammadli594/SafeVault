using MySqlConnector;

namespace SafeVault.Data;

public class UserRepository
{
    private readonly string _cs;
    public UserRepository(string connectionString) => _cs = connectionString;

    public async Task<int> CreateUserAsync(string username, string email, CancellationToken ct = default)
    {
        const string sql = @"
            INSERT INTO Users (Username, Email)
            VALUES (@username, @email);
            SELECT LAST_INSERT_ID();
        ";

        await using var conn = new MySqlConnection(_cs);
        await conn.OpenAsync(ct);

        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@username", username);
        cmd.Parameters.AddWithValue("@email", email);

        var result = await cmd.ExecuteScalarAsync(ct);
        return Convert.ToInt32(result);
    }

    public async Task<(int userId, string username, string email)?> GetUserByUsernameAsync(string username, CancellationToken ct = default)
    {
        const string sql = @"
            SELECT UserID, Username, Email
            FROM Users
            WHERE Username = @username
            LIMIT 1;
        ";

        await using var conn = new MySqlConnection(_cs);
        await conn.OpenAsync(ct);

        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@username", username);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null;

        return (
            reader.GetInt32("UserID"),
            reader.GetString("Username"),
            reader.GetString("Email")
        );
    }

    // test helper
    internal static MySqlCommand BuildGetUserByUsernameCommand(MySqlConnection conn, string username)
    {
        const string sql = @"SELECT UserID, Username, Email FROM Users WHERE Username = @username LIMIT 1;";
        var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@username", username);
        return cmd;
    }
}
