using Azure.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using IssueFromCsrFunction.Services;

var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults()
    .ConfigureServices(services =>
    {
        services.AddSingleton(new DefaultAzureCredential());
        services.AddSingleton<KeyVaultAccountStore>();
        services.AddSingleton<AzureDnsChallengeService>();
        services.AddSingleton<AcmeCsrIssuerService>();
    })
    .Build();

host.Run();