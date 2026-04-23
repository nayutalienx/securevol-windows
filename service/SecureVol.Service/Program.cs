using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SecureVol.Common;
using SecureVol.Common.Logging;
using SecureVol.Common.Policy;
using SecureVol.Service;

AppPaths.EnsureDefaultAcls();

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "SecureVolSvc");

builder.Services.AddSingleton(_ => new JsonFileLogger(Path.Combine(AppPaths.LogDirectory, "securevol-service.jsonl")));
builder.Services.AddSingleton<WindowsEventLogger>();
builder.Services.AddSingleton<IProcessIdentityResolver, ProcessIdentityResolver>();
builder.Services.AddSingleton<PolicyEngine>();
builder.Services.AddSingleton<SecureVolCoordinator>();
builder.Services.AddHostedService<SecureVolWorker>();
builder.Services.AddHostedService<AdminPipeServer>();
builder.Services.AddHostedService<PolicyFileWatcher>();

await builder.Build().RunAsync();
