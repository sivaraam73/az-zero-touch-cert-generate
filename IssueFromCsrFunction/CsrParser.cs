using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace IssueFromCsrFunction;

public static class CsrParser
{
    public static (byte[] Der, List<string> Domains) ParseDomains(byte[] csrBytes)
    {
        var der = LooksLikePem(csrBytes) ? PemToDer(csrBytes) : csrBytes;

        var request = CertificateRequest.LoadSigningRequest(
            der, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.SkipSignatureValidation);

        var domains = new List<string>();

        var cn = request.SubjectName.EnumerateRelativeDistinguishedNames()
            .FirstOrDefault(rdn => rdn.GetSingleElementType().Value == "2.5.4.3");
        if (cn is not null) domains.Add(cn.GetSingleElementValue()!);

        var san = request.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        if (san is not null) domains.AddRange(san.EnumerateDnsNames());

        return (der, domains.Distinct(StringComparer.OrdinalIgnoreCase).ToList());
    }

    private static bool LooksLikePem(byte[] bytes) =>
        System.Text.Encoding.ASCII.GetString(bytes, 0, Math.Min(bytes.Length, 30)).Contains("-----BEGIN");

    private static byte[] PemToDer(byte[] pemBytes)
    {
        var base64 = System.Text.Encoding.ASCII.GetString(pemBytes)
            .Replace("-----BEGIN CERTIFICATE REQUEST-----", "")
            .Replace("-----END CERTIFICATE REQUEST-----", "")
            .Replace("\r", "").Replace("\n", "").Trim();
        return Convert.FromBase64String(base64);
    }
}