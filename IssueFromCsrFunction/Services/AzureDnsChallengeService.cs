using Azure;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Dns;
using Azure.ResourceManager.Dns.Models;

namespace IssueFromCsrFunction.Services;

public class AzureDnsChallengeService
{
    private readonly ArmClient _armClient;
    private readonly string _subscriptionId;
    private readonly string _resourceGroup;
    private readonly string[] _managedZones;

    public AzureDnsChallengeService(DefaultAzureCredential credential)
    {
        _armClient = new ArmClient(credential);
        _subscriptionId = Environment.GetEnvironmentVariable("AzureSubscriptionId")
            ?? throw new InvalidOperationException("AzureSubscriptionId app setting not configured");
        _resourceGroup = Environment.GetEnvironmentVariable("DnsResourceGroup")
            ?? throw new InvalidOperationException("DnsResourceGroup app setting not configured");
        _managedZones = (Environment.GetEnvironmentVariable("AllowedDomains") ?? "")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private (string ZoneName, string RelativeRecordName) ResolveZone(string domain)
    {
        var zone = _managedZones.FirstOrDefault(z =>
            domain.Equals(z, StringComparison.OrdinalIgnoreCase) ||
            domain.EndsWith("." + z, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException($"Domain '{domain}' is not under a managed DNS zone.");

        var relativeLabel = domain.Equals(zone, StringComparison.OrdinalIgnoreCase)
            ? "_acme-challenge"
            : $"_acme-challenge.{domain[..^(zone.Length + 1)]}";

        return (zone, relativeLabel);
    }

    public async Task CreateTxtRecordAsync(string domain, string txtValue)
    {
        var (zoneName, recordName) = ResolveZone(domain);
        var zoneId = DnsZoneResource.CreateResourceIdentifier(_subscriptionId, _resourceGroup, zoneName);
        var zone = _armClient.GetDnsZoneResource(zoneId);

        var recordData = new DnsTxtRecordData { TtlInSeconds = 60 };
        recordData.DnsTxtRecords.Add(new DnsTxtRecordInfo { Values = { txtValue } });

        await zone.GetDnsTxtRecords().CreateOrUpdateAsync(WaitUntil.Completed, recordName, recordData);
    }

    public async Task DeleteTxtRecordAsync(string domain)
    {
        var (zoneName, recordName) = ResolveZone(domain);
        var zoneId = DnsZoneResource.CreateResourceIdentifier(_subscriptionId, _resourceGroup, zoneName);
        var zone = _armClient.GetDnsZoneResource(zoneId);

        var record = await zone.GetDnsTxtRecords().GetAsync(recordName);
        await record.Value.DeleteAsync(WaitUntil.Completed);
    }
}