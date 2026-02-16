using System.Security.Cryptography;
using System.Text;

namespace Vibe.Edge.Proxy;

public static class HmacSigner
{
    public static string ComputeSignature(string stringToSign, string base64Key)
    {
        var keyBytes = Convert.FromBase64String(base64Key);
        var dataBytes = Encoding.UTF8.GetBytes(stringToSign);

        using var hmac = new HMACSHA256(keyBytes);
        var hash = hmac.ComputeHash(dataBytes);
        return Convert.ToBase64String(hash);
    }

    public static string BuildStringToSign(string timestamp, string method, string path)
    {
        var signingPath = path.Split('?')[0];
        var upperMethod = method.ToUpperInvariant();
        return $"{timestamp}|{upperMethod}|{signingPath}";
    }
}
