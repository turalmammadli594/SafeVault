using System.Text.Encodings.Web;

namespace SafeVault.Endpoints;

public static class UserContentEndpoints
{
    public static void MapUserContent(this WebApplication app)
    {
        app.MapGet("/welcome", (string username) =>
        {
            var safe = HtmlEncoder.Default.Encode(username);
            return Results.Content($"<h1>Welcome {safe}</h1>", "text/html");
        });
    }
}
