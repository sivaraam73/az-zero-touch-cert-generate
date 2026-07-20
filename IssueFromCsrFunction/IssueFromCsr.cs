using System.Net;
using System.Text.Json;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using IssueFromCsrFunction.Services;

namespace IssueFromCsrFunction;

public class IssueFromCsr
{
    private readonly AcmeCsrIssuerService _issuer;
    private readonly ILogger _logger;
    private readonly string[] _allowedDomains;

    public IssueFromCsr(AcmeCsrIssuerService issuer, ILoggerFactory loggerFactory)
    {
        _issuer = issuer;
        _logger = loggerFactory.CreateLogger<IssueFromCsr>();
        _allowedDomains = (Environment.GetEnvironmentVariable("AllowedDomains") ?? "")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    [Function("IssueFromCsr")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "issue-from-csr")] HttpRequestData req)
    {
        IssueRequest? payload;
        try
        {
            var jsonOptions = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            payload = await JsonSerializer.DeserializeAsync<IssueRequest>(req.Body, jsonOptions);
        }
        catch (JsonException)
        {
            return await WriteError(req, HttpStatusCode.BadRequest, "Invalid JSON body.");
        }

        if (payload is null || string.IsNullOrWhiteSpace(payload.CertificateName) || string.IsNullOrWhiteSpace(payload.Csr))
        {
            return await WriteError(req, HttpStatusCode.BadRequest, "certificateName and csr are required.");
        }

        byte[] csrDer;
        List<string> domains;
        try
        {
            var csrBytes = Convert.FromBase64String(payload.Csr);
            (csrDer, domains) = CsrParser.ParseDomains(csrBytes);
        }
        catch (Exception ex)
        {
            return await WriteError(req, HttpStatusCode.BadRequest, $"Could not parse CSR: {ex.Message}");
        }

        var disallowed = domains.Where(d => !_allowedDomains.Any(a =>
            d.Equals(a, StringComparison.OrdinalIgnoreCase) || d.EndsWith("." + a, StringComparison.OrdinalIgnoreCase))).ToList();

        if (disallowed.Count > 0)
        {
            return await WriteError(req, HttpStatusCode.Forbidden,
                $"Domain(s) not in allowed list: {string.Join(", ", disallowed)}");
        }

        try
        {
            var (_, secretUri) = await _issuer.IssueFromCsrAsync(payload.CertificateName, csrDer, domains);
            var response = req.CreateResponse(HttpStatusCode.OK);
            await response.WriteAsJsonAsync(new { certificateName = payload.CertificateName, keyVaultSecretUri = secretUri.ToString(), domains });
            return response;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Certificate issuance failed for {CertificateName}", payload.CertificateName);
            return await WriteError(req, HttpStatusCode.InternalServerError, "Issuance failed — check Function logs.");
        }
    }

    private static async Task<HttpResponseData> WriteError(HttpRequestData req, HttpStatusCode status, string message)
    {
        var response = req.CreateResponse(status);
        await response.WriteAsJsonAsync(new { error = message });
        return response;
    }
}

public record IssueRequest
{
    public string? CertificateName { get; init; }
    public string? Csr { get; init; }
}