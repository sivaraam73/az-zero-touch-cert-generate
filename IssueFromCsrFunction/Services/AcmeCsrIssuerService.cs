using System.Security.Cryptography.X509Certificates;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;

namespace IssueFromCsrFunction.Services;

public class AcmeCsrIssuerService
{
    private readonly KeyVaultAccountStore _accountStore;
    private readonly AzureDnsChallengeService _dnsService;
    private readonly bool _staging;
    private readonly string _acmeEmail;

    public AcmeCsrIssuerService(KeyVaultAccountStore accountStore, AzureDnsChallengeService dnsService)
    {
        _accountStore = accountStore;
        _dnsService = dnsService;
        _staging = bool.TryParse(Environment.GetEnvironmentVariable("AcmeStaging"), out var s) && s;
        _acmeEmail = Environment.GetEnvironmentVariable("AcmeEmail")
            ?? throw new InvalidOperationException("AcmeEmail app setting not configured");
    }

    public async Task<(string ChainPem, Uri ChainSecretUri, Uri P7bSecretUri, Uri DerSecretUri, Uri CrtSecretUri)> IssueFromCsrAsync(
        string certificateName, byte[] csrDer, IReadOnlyList<string> domains)
    {
        var server = _staging ? WellKnownServers.LetsEncryptStagingV2 : WellKnownServers.LetsEncryptV2;

        var existingKeyPem = await _accountStore.TryGetAcmeAccountKeyAsync();
        AcmeContext acme;

        if (existingKeyPem is null)
        {
            acme = new AcmeContext(server);
            await acme.NewAccount(_acmeEmail, termsOfServiceAgreed: true);
            await _accountStore.SaveAcmeAccountKeyAsync(acme.AccountKey.ToPem());
        }
        else
        {
            acme = new AcmeContext(server, KeyFactory.FromPem(existingKeyPem));
        }

        var order = await acme.NewOrder(domains.ToList());
        var authorizations = await order.Authorizations();
        var recordsToClean = new List<string>();

        try
        {
            foreach (var authz in authorizations)
            {
                var authzResource = await authz.Resource();
                var domain = authzResource.Identifier.Value;

                var dnsChallenge = await authz.Dns()
                    ?? throw new InvalidOperationException($"No DNS-01 challenge available for {domain}");

                var txtValue = acme.AccountKey.DnsTxt(dnsChallenge.Token);
                await _dnsService.CreateTxtRecordAsync(domain, txtValue);
                recordsToClean.Add(domain);
            }

            await Task.Delay(TimeSpan.FromSeconds(30));

            foreach (var authz in authorizations)
            {
                var dnsChallenge = await authz.Dns();
                await dnsChallenge!.Validate();

                Challenge status;
                var attempts = 0;
                do
                {
                    await Task.Delay(TimeSpan.FromSeconds(5));
                    status = await dnsChallenge.Resource();
                } while (status.Status is ChallengeStatus.Pending or ChallengeStatus.Processing && ++attempts < 24);

                if (status.Status != ChallengeStatus.Valid)
                {
                    throw new InvalidOperationException(
                        $"DNS-01 challenge failed: {status.Status} — {status.Error?.Detail}");
                }
            }

            await order.Finalize(csrDer);

            Order orderDetails;
            var finalizeAttempts = 0;
            do
            {
                await Task.Delay(TimeSpan.FromSeconds(5));
                orderDetails = await order.Resource();
            } while (orderDetails.Status is OrderStatus.Processing && ++finalizeAttempts < 24);

            if (orderDetails.Status != OrderStatus.Valid)
            {
                throw new InvalidOperationException($"Order did not finalize: {orderDetails.Status}");
            }

            var certChain = await order.Download();
            var chainPem = BuildChainPem(certChain);
            var chainSecretUri = await _accountStore.SaveCertificateChainAsync(certificateName, chainPem);

            var p7bBase64 = BuildP7bBase64(chainPem);
            var p7bSecretUri = await _accountStore.SaveP7bAsync(certificateName, p7bBase64);

            var derBase64 = BuildLeafDerBase64(certChain);
            var derSecretUri = await _accountStore.SaveDerLeafAsync(certificateName, derBase64);

            var crtPem = BuildLeafCrtPem(certChain);
            var crtSecretUri = await _accountStore.SaveCrtAsync(certificateName, crtPem);

            return (chainPem, chainSecretUri, p7bSecretUri, derSecretUri, crtSecretUri);
        }
        finally
        {
            foreach (var domain in recordsToClean)
            {
                try { await _dnsService.DeleteTxtRecordAsync(domain); }
                catch { /* best-effort cleanup — don't fail the request over a leftover TXT record */ }
            }
        }
    }

    private static string BuildChainPem(CertificateChain certChain)
    {
        var sb = new System.Text.StringBuilder();
        AppendPemBlock(sb, certChain.Certificate.ToPem());
        foreach (var issuer in certChain.Issuers)
        {
            AppendPemBlock(sb, issuer.ToPem());
        }
        return sb.ToString();
    }

    private static void AppendPemBlock(System.Text.StringBuilder sb, string pemBlock)
    {
        sb.Append(pemBlock.TrimEnd());
        sb.Append('\n');
    }

    private static string BuildP7bBase64(string chainPem)
    {
        var certs = new X509Certificate2Collection();
        certs.ImportFromPem(chainPem);
        var p7bBytes = certs.Export(X509ContentType.Pkcs7)
            ?? throw new InvalidOperationException("Failed to export PKCS#7 bundle.");
        return Convert.ToBase64String(p7bBytes);
    }

    private static string BuildLeafDerBase64(CertificateChain certChain)
    {
        var leafPem = certChain.Certificate.ToPem();
        using var leafCert = X509Certificate2.CreateFromPem(leafPem);
        var derBytes = leafCert.Export(X509ContentType.Cert);
        return Convert.ToBase64String(derBytes);
    }

    private static string BuildLeafCrtPem(CertificateChain certChain)
    {
        return certChain.Certificate.ToPem().TrimEnd() + "\n";
    }
}
