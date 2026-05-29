using System;

namespace Prism.Config;

public class ProxyConfig
{
    public string ListenIp { get; set; } = "0.0.0.0";
    public int ListenPort { get; set; } = 1080;
    
    // Upstream connection details
    public string WhitelistedIp { get; set; } = "1.1.1.1";
    public int TargetPort { get; set; } = 443;
    
    // Feature toggles
    public bool EnableSeqInjection { get; set; } = false;
    public bool EnableTlsFrag { get; set; } = false;
    public bool EnableTtlSpoof { get; set; } = false;
    public bool EnableFakeClientHello { get; set; } = false;
    public bool EnableCombinedStrategy { get; set; } = false;

    // Parameters
    public string FakeSniDomain { get; set; } = "bing.com";
    public short DecoyTtl { get; set; } = 8;
    public string NetworkInterfaceName { get; set; } = "";
}
