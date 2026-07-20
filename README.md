# az-zero-touch-cert-generate

Zero-touch ACME certificate issuance for Azure, two flows:
- Auto-renewal for Azure-managed resources via a timer-triggered Function App
- CSR-based issuance for externally-generated CSRs, requested via PR in this repo

## Requesting a certificate from an external CSR
1. Add your `.csr` file under `csrs/<certificate-name>.csr`
2. Open a PR — the workflow validates the CSR's CN/SANs are in the allowed domain list
3. On merge, the workflow calls the issuance Function over OIDC and the cert lands in Key Vault
