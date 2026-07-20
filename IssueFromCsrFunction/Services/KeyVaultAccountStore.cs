using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

namespace IssueFromCsrFunction.Services;

public class KeyVaultAccountStore
{
    private readonly SecretClient _secretClient;

    public KeyVaultAccountStore(DefaultAzureCredential credential)
    {
        var vaultUri = new Uri(Environment.GetEnvironmentVariable("KeyVaultUri")
            ?? throw new InvalidOperationException("KeyVaultUri app setting not configured"));
        _secretClient = new SecretClient(vaultUri, credential);
    }

    public async Task<string?> TryGetAcmeAccountKeyAsync()
    {
        try
        {
            var secret = await _secretClient.GetSecretAsync("acme-account-key");
            return secret.Value.Value;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
    }

    public async Task SaveAcmeAccountKeyAsync(string pemKey) =>
        await _secretClient.SetSecretAsync("acme-account-key", pemKey);

    public async Task<Uri> SaveCertificateChainAsync(string certificateName, string chainPem)
    {
        var result = await _secretClient.SetSecretAsync($"{certificateName}-chain", chainPem);
        return result.Value.Id;
    }
}