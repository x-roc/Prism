using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Prism.Config;

namespace Prism.Strategies;

public class FakeClientHelloStrategy : IDpiEvasionStrategy
{
    public async Task ApplyAsync(Socket clientSocket, Socket serverSocket, byte[] clientHello, ProxyConfig config, CancellationToken cancellationToken)
    {
        Console.WriteLine($"[FakeClientHello] Sending fake SNI {config.FakeSniDomain} before real ClientHello.");

        byte[] fakeSniPacket = TlsParser.CreateFakeClientHello(clientHello, config.FakeSniDomain);

        // 1. Send the fake Client Hello
        await serverSocket.SendAsync(fakeSniPacket, SocketFlags.None, cancellationToken);
        
        // 2. Wait a very brief moment to ensure they travel in separate segments if needed 
        // (though sending back-to-back will usually put them in one segment if Nagle is on, or multiple if off)
        await Task.Delay(10, cancellationToken);

        // 3. Send the real Client Hello
        await serverSocket.SendAsync(clientHello, SocketFlags.None, cancellationToken);
    }
}
