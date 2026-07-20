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

    public async Task<(string ChainPem, Uri KeyVaultSecretUri)> IssueFromCsrAsync(
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
            var secretUri = await _accountStore.SaveCertificateChainAsync(certificateName, chainPem);

            return (chainPem, secretUri);
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
        sb.Append(certChain.Certificate.ToPem());
        foreach (var issuer in certChain.Issuers)
        {
            sb.Append(issuer.ToPem());
        }
        return sb.ToString();
    }
}