using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Prism.Config;
using Prism.Strategies;

namespace Prism;

public class ProxyServer
{
    private readonly ProxyConfig _config;
    private readonly IDpiEvasionStrategy? _strategy;

    public ProxyServer(ProxyConfig config)
    {
        _config = config;

        // Factory to choose strategy based on config
        if (_config.EnableCombinedStrategy)
            _strategy = new CombinedStrategy();
        else if (_config.EnableSeqInjection)
            _strategy = new SeqInjector();
        else if (_config.EnableTlsFrag)
            _strategy = new TlsFragmenter();
        else if (_config.EnableTtlSpoof)
            _strategy = new TtlSpoofer();
        else if (_config.EnableFakeClientHello)
            _strategy = new FakeClientHelloStrategy();
        else
            _strategy = null; 
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        IPAddress address = IPAddress.TryParse(_config.ListenIp, out var parsedAddress) ? parsedAddress : IPAddress.Any;
        TcpListener listener = new(address, _config.ListenPort);
        listener.Start();
        Console.WriteLine($"[ProxyServer] Started listening on {address}:{_config.ListenPort}");

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var clientSocket = await listener.AcceptSocketAsync(cancellationToken);
                _ = HandleClientAsync(clientSocket, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("[ProxyServer] Shutdown requested.");
        }
        finally
        {
            listener.Stop();
        }
    }

    // A simplified SOCKS5 / Transparent TCP handling. 
    // For demonstration, assuming transparent proxy where the target IP and PORT are provided statically 
    // OR we just read the first ClientHello and extract the target SNI.
    private async Task HandleClientAsync(Socket clientSocket, CancellationToken cancellationToken)
    {
        try
        {
            // Read initial payload from client (Expecting ClientHello)
            byte[] buffer = new byte[8192];
            int bytesRead = await clientSocket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken);
            if (bytesRead <= 0) return;

            byte[] clientHello = new byte[bytesRead];
            Array.Copy(buffer, clientHello, bytesRead);

            // TODO: Extract target destination from SNI or a SOCKS5 handshake. 
            // For now, let's hardcode a target to continue evasion demonstration, or expect it resolved externally.
            // As a local proxy, either handle SOCKS5 or act as transparent proxy fetching SO_ORIGINAL_DST.
            
            // Connecting to the user-specified whitelisted IP
            var targetHost = _config.WhitelistedIp; 
            var targetPort = _config.TargetPort; 

            using Socket serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await serverSocket.ConnectAsync(targetHost, targetPort, cancellationToken);

            if (_strategy != null && clientHello[0] == 0x16) // If TLS Handshake
            {
                await _strategy.ApplyAsync(clientSocket, serverSocket, clientHello, _config, cancellationToken);
            }
            else
            {
                await serverSocket.SendAsync(clientHello, SocketFlags.None, cancellationToken);
            }

            // Relay remaining traffic between client and server
            var clientToServer = RelayAsync(clientSocket, serverSocket, cancellationToken);
            var serverToClient = RelayAsync(serverSocket, clientSocket, cancellationToken);

            await Task.WhenAny(clientToServer, serverToClient);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ProxyServer] Error handling client: {ex.Message}");
        }
        finally
        {
            clientSocket.Close();
        }
    }

    private async Task RelayAsync(Socket from, Socket to, CancellationToken cancellationToken)
    {
        var buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(32768); // 32KB buffer for efficiency
        try
        {
            while (true)
            {
                int read = await from.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None, cancellationToken);
                if (read == 0) break;
                await to.SendAsync(new ArraySegment<byte>(buffer, 0, read), SocketFlags.None, cancellationToken);
            }
        }
        catch
        {
            // Ignore socket disconnects
        }
        finally
        {
            System.Buffers.ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
