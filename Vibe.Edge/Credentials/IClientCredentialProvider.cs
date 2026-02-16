namespace Vibe.Edge.Credentials;

public interface IClientCredentialProvider
{
    Task<string?> GetSigningKeyAsync(string clientId);
}
