using System;
using System.CommandLine;
using System.Threading;
using System.Threading.Tasks;
using Prism.Config;

namespace Prism;

class Program
{
    public static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("DPI Evasion Proxy Tool");

        var listenOption = new Option<string>("--listen") { Description = "Local endpoint to listen on (e.g., 0.0.0.0:1080 or 1080)", DefaultValueFactory = _ => "0.0.0.0:1080" };
        var ipOption = new Option<string>("--ip") { Description = "Target whitelisted IP address", DefaultValueFactory = _ => "1.1.1.1" };
        var targetPortOption = new Option<int>("--target-port") { Description = "Target port", DefaultValueFactory = _ => 443 };
        var sniOption = new Option<string>("--fake-sni") { Description = "Fake SNI domain to spoof", DefaultValueFactory = _ => "bing.com" };
        var strategyOption = new Option<string>("--strategy") { Description = "Evasion strategy: fragment, seq, ttl, combined", DefaultValueFactory = _ => "fragment" };
        var ttlOption = new Option<short>("--ttl") { Description = "TTL for decoy packets (TTL strategy)", DefaultValueFactory = _ => (short)8 };
        var interfaceOption = new Option<string>("--interface") { Description = "Network interface name (SEQ strategy)" };

        rootCommand.Options.Add(listenOption);
        rootCommand.Options.Add(ipOption);
        rootCommand.Options.Add(targetPortOption);
        rootCommand.Options.Add(sniOption);
        rootCommand.Options.Add(strategyOption);
        rootCommand.Options.Add(ttlOption);
        rootCommand.Options.Add(interfaceOption);

        rootCommand.SetAction(async (ParseResult parseResult, CancellationToken ct) =>
        {
            var listenStr = parseResult.GetValue(listenOption)!;
            string listenIp = "0.0.0.0";
            int listenPort = 1080;
            
            if (listenStr.Contains(':'))
            {
                var parts = listenStr.Split(':');
                listenIp = parts[0];
                int.TryParse(parts[1], out listenPort);
            }
            else
            {
                int.TryParse(listenStr, out listenPort);
            }

            var config = new ProxyConfig
            {
                ListenIp = listenIp,
                ListenPort = listenPort,
                WhitelistedIp = parseResult.GetValue(ipOption)!,
                TargetPort = parseResult.GetValue(targetPortOption),
                FakeSniDomain = parseResult.GetValue(sniOption)!,
                DecoyTtl = parseResult.GetValue(ttlOption),
                NetworkInterfaceName = parseResult.GetValue(interfaceOption) ?? ""
            };

            string strategy = parseResult.GetValue(strategyOption)!;
            switch (strategy.ToLower())
            {
                case "combined": config.EnableCombinedStrategy = true; break;
                case "seq": config.EnableSeqInjection = true; break;
                case "ttl": config.EnableTtlSpoof = true; break;
                default: config.EnableTlsFrag = true; break;
            }

            Console.WriteLine($"Starting Proxy on {config.ListenIp}:{config.ListenPort}...");
            Console.WriteLine($"Target: {config.WhitelistedIp}:{config.TargetPort}");
            Console.WriteLine($"Strategy: {strategy}");
            Console.WriteLine($"Spoof SNI: {config.FakeSniDomain}");

            var proxy = new ProxyServer(config);
            await proxy.StartAsync(ct);
        });

        return await rootCommand.Parse(args).InvokeAsync();
    }
}
