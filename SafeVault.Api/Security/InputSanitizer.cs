using System.Net.Mail;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;

namespace SafeVault.Security;

public static class InputSanitizer
{
    private static readonly Regex UsernameAllowed = new(@"^[a-zA-Z0-9._\- ]{3,100}$", RegexOptions.Compiled);

    public static (bool ok, string? error, string sanitized) SanitizeUsername(string? input)
    {
        var s = Normalize(input);

        // XSS: encode first
        s = HtmlEncoder.Default.Encode(s);

        // basic hardening (main defense is parameterized SQL)
        s = RemoveCommonInjectionTokens(s);

        if (!UsernameAllowed.IsMatch(s))
            return (false, "Username must be 3-100 chars and contain only letters, digits, space, . _ -", s);

        return (true, null, s);
    }

    public static (bool ok, string? error, string sanitized) SanitizeEmail(string? input)
    {
        var s = Normalize(input);
        s = HtmlEncoder.Default.Encode(s);
        s = RemoveCommonInjectionTokens(s);

        try
        {
            var addr = new MailAddress(s);
            if (addr.Address.Length > 100) return (false, "Email is too long", s);
            return (true, null, addr.Address);
        }
        catch
        {
            return (false, "Invalid email format", s);
        }
    }

    private static string Normalize(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) return string.Empty;

        var trimmed = input.Trim();
        var sb = new StringBuilder(trimmed.Length);
        foreach (var ch in trimmed)
        {
            if (!char.IsControl(ch)) sb.Append(ch);
        }
        return sb.ToString();
    }

    private static string RemoveCommonInjectionTokens(string s)
    {
        return s
            .Replace("--", "", StringComparison.Ordinal)
            .Replace("/*", "", StringComparison.Ordinal)
            .Replace("*/", "", StringComparison.Ordinal)
            .Replace(";", "", StringComparison.Ordinal)
            .Replace("'", "", StringComparison.Ordinal)
            .Replace("\"", "", StringComparison.Ordinal);
    }
}
