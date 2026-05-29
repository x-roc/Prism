using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Prism.Config;

namespace Prism.Strategies;

public interface IDpiEvasionStrategy
{
    /// <summary>
    /// Apply the DPI evasion strategy on the given stream or socket.
    /// </summary>
    Task ApplyAsync(Socket clientSocket, Socket serverSocket, byte[] clientHello, ProxyConfig config, CancellationToken cancellationToken);
}
