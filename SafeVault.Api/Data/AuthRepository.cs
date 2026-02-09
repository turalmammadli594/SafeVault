using MySqlConnector;

namespace SafeVault.Data;

public record AuthUser(int UserId, string Username, string PasswordHash, string Role);

public class AuthRepository
{
    private readonly string _cs;
    public AuthRepository(string connectionString) => _cs = connectionString;

    public async Task<AuthUser?> GetByUsernameAsync(string username, CancellationToken ct = default)
    {
        const string sql = @"
            SELECT UserID, Username, PasswordHash, Role
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

        return new AuthUser(
            reader.GetInt32("UserID"),
            reader.GetString("Username"),
            reader.GetString("PasswordHash"),
            reader.GetString("Role")
        );
    }

    public async Task<int> CreateUserAsync(string username, string email, string passwordHash, string role, CancellationToken ct = default)
    {
        const string sql = @"
            INSERT INTO Users (Username, Email, PasswordHash, Role)
            VALUES (@u, @e, @p, @r);
            SELECT LAST_INSERT_ID();
        ";

        await using var conn = new MySqlConnection(_cs);
        await conn.OpenAsync(ct);

        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@u", username);
        cmd.Parameters.AddWithValue("@e", email);
        cmd.Parameters.AddWithValue("@p", passwordHash);
        cmd.Parameters.AddWithValue("@r", role);

        var result = await cmd.ExecuteScalarAsync(ct);
        return Convert.ToInt32(result);
    }
}
