using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Prism.Config;

namespace Prism.Strategies;

public class TtlSpoofer : IDpiEvasionStrategy
{
    public async Task ApplyAsync(Socket clientSocket, Socket serverSocket, byte[] clientHello, ProxyConfig config, CancellationToken cancellationToken)
    {
        Console.WriteLine($"[TtlSpoofer] Applying TTL Spoofing. Decoy TTL = {config.DecoyTtl}");

        // Generate fake client hello
        byte[] fakeSniPacket = TlsParser.CreateFakeClientHello(clientHello, config.FakeSniDomain);

        // Save original TTL
        int originalTtl = Convert.ToInt32(serverSocket.GetSocketOption(SocketOptionLevel.IP, SocketOptionName.IpTimeToLive) ?? 64);

        // 1. Send fake packet with low TTL
        serverSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.IpTimeToLive, (int)config.DecoyTtl);
        await serverSocket.SendAsync(fakeSniPacket, SocketFlags.None, cancellationToken);

        // Restore TTL and send real packet
        serverSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.IpTimeToLive, originalTtl);
        await serverSocket.SendAsync(clientHello, SocketFlags.None, cancellationToken);
    }
}
