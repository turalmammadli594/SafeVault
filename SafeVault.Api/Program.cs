using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Data;
using SafeVault.Endpoints;
using SafeVault.Models;
using SafeVault.Security;

var builder = WebApplication.CreateBuilder(args);

// ---- Config ----
var cs = builder.Configuration.GetConnectionString("SafeVaultDb")
         ?? "Server=localhost;Database=SafeVault;User ID=root;Password=your_password;";

var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "SafeVault";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "SafeVaultUsers";
var jwtSecret = builder.Configuration["Jwt:Secret"] ?? "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET_32+CHARS";

// ---- DI ----
builder.Services.AddSingleton(new UserRepository(cs));
builder.Services.AddSingleton(new AuthRepository(cs));
builder.Services.AddSingleton(new JwtTokenService(jwtIssuer, jwtAudience, jwtSecret));

// ---- Auth ----
builder.Services
  .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
  .AddJwtBearer(options =>
  {
      options.TokenValidationParameters = new TokenValidationParameters
      {
          ValidateIssuer = true,
          ValidateAudience = true,
          ValidateLifetime = true,
          ValidateIssuerSigningKey = true,
          ValidIssuer = jwtIssuer,
          ValidAudience = jwtAudience,
          IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret))
      };
  });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("admin"));
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// ---------- Part 1: Secure input validation + create user ----------
app.MapPost("/submit", async (HttpRequest request, UserRepository repo) =>
{
    var form = await request.ReadFormAsync();

    var (uOk, uErr, uSan) = InputSanitizer.SanitizeUsername(form["username"]);
    if (!uOk) return Results.BadRequest(new { error = uErr });

    var (eOk, eErr, eSan) = InputSanitizer.SanitizeEmail(form["email"]);
    if (!eOk) return Results.BadRequest(new { error = eErr });

    // demo: password optional (if you want to create auth users via form later)
    var id = await repo.CreateUserAsync(uSan, eSan);
    return Results.Ok(new { userId = id, username = uSan, email = eSan });
});

// ---------- Part 2: Authentication (bcrypt) + RBAC ----------
app.MapPost("/login", async (LoginRequest req, AuthRepository repo, JwtTokenService jwt) =>
{
    var (uOk, _, username) = InputSanitizer.SanitizeUsername(req.Username);
    if (!uOk) return Results.Unauthorized();

    var user = await repo.GetByUsernameAsync(username);
    if (user is null) return Results.Unauthorized();

    var ok = PasswordHasher.VerifyPassword(req.Password, user.PasswordHash);
    if (!ok) return Results.Unauthorized();

    var token = jwt.CreateToken(user.UserId, user.Username, user.Role, TimeSpan.FromHours(1));
    return Results.Ok(new { token, role = user.Role });
});

// Any authenticated user
app.MapGet("/me", (HttpContext ctx) =>
{
    var name = ctx.User.Identity?.Name ?? "(unknown)";
    var role = ctx.User.Claims.FirstOrDefault(c => c.Type.EndsWith("/role"))?.Value
               ?? ctx.User.Claims.FirstOrDefault(c => c.Type == "role")?.Value
               ?? "unknown";
    return Results.Ok(new { user = name, role });
}).RequireAuthorization();

// Admin-only
app.MapGet("/admin/dashboard", () =>
{
    return Results.Ok(new { message = "Welcome to Admin Dashboard" });
}).RequireAuthorization("AdminOnly");

// ---------- Part 3: XSS-safe endpoint ----------
app.MapUserContent();

app.Run();
