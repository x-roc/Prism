# Prism

Prism is an advanced DPI (Deep Packet Inspection) evasion proxy tool written in C#. It allows you to bypass internet filtering by deploying sophisticated traffic obfuscation strategies exactly at the client tier.

## Features & Strategies
The proxy offers four main traffic obfuscation mechanics:
1. **fragment** (`--strategy fragment`): Breaks the local TLS `ClientHello` payload into small packet sizes. This successfully bypasses primitive packet inspection nodes by scattering the TLS record header and the Server Name (SNI) across multiple TCP fragments.
2. **seq** (`--strategy seq`): Transmits a decoy `ClientHello` (with a fake, whitelisted SNI like `bing.com`) using TCP Out-of-Window Sequence Numbers. The firewall sees and permits the fake packet, while the actual proxy server rejects it and expects the true payload.
3. **ttl** (`--strategy ttl`): Transmits a decoy `ClientHello` over standard TCP with an intentionally short Time-to-Live (TTL). This packet reaches the inspection firewall, but gets dropped natively by standard routing before it reaches the real proxy.
4. **combined** (`--strategy combined`): Unifies the three variants (Sequence Injection, TTL Limiting, and TLS fragmentation) for maximum bypassing strength against active probing and passive heuristics systems.

## Prerequisites
- .NET 10.0 SDK (for building only).
- To execute raw packet injections (`seq` or `combined`), **Prism requires root/Administrator privileges**.
- `libpcap` installed on your target machine (`apt install libpcap-dev` on Debian/Ubuntu).

## Usage Guide
First, build the project:

```bash
cd /path/to/Prism
sudo dotnet publish -c Release -r linux-x64 --self-contained true
```

Then run the binary directly:

```bash
sudo ./bin/Release/net10.0/linux-x64/Prism --strategy combined --listen 0.0.0.0:40443 --ip 45.130.125.76 --target-port 443 --fake-sni chatgpt.com --ttl 8
```

### CLI Arguments
* `--listen` : Endpoint to listen on. Format `IP:Port` or just `Port` (Defaults to `0.0.0.0:1080`).
* `--strategy` : DPI Evasion strategy. Accepts `fragment`, `seq`, `ttl`, `combined` (Defaults to `fragment`).
* `--ip` : Target whitelisted upstream proxy IP (Defaults to `1.1.1.1`).
* `--target-port` : Target upstream port (Defaults to `443`).
* `--fake-sni` : Decoy domain sent to trick SNI inspection (Defaults to `bing.com`).
* `--ttl` : Custom limit for the `ttl`/`combined` injected decoy packets (Defaults to `8`).
* `--interface` : Optional forced network interface name for SharpPcap packet injection.

## Project Structure
* `Strategies/`: Contains individual mechanics implementing the `IDpiEvasionStrategy`.
* `Config/ProxyConfig.cs`: Proxy mapping objects.
* `ProxyServer.cs`: Barebone asynchronous socket listener managing local/remote lifecycle mapping arrays.
