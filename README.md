# SafeVault

Secure ASP.NET Core Minimal API sample:
- Input validation + XSS encoding
- Parameterized SQL queries (MySqlConnector)
- Authentication (bcrypt) + Authorization (RBAC with JWT)
- NUnit tests for SQLi & XSS scenarios

## Run
1) Create MySQL database: SafeVault
2) Run `database.sql`
3) Update connection string in `SafeVault.Api/appsettings.json`
4) Run API:
   - `dotnet run --project SafeVault.Api`

## Test
- `dotnet test`
