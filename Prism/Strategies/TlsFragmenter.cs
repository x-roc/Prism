using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Prism.Config;

namespace Prism.Strategies;

public class TlsFragmenter : IDpiEvasionStrategy
{
    public async Task ApplyAsync(Socket clientSocket, Socket serverSocket, byte[] clientHello, ProxyConfig config, CancellationToken cancellationToken)
    {
        Console.WriteLine("[TlsFragmenter] Applying TLS Record-Layer Fragmentation.");

        // A simple fragmentation: take the ClientHello and split it at the record layer.
        // Modern TLS 1.0+ records have a 5-byte header:
        // Byte 0: Content Type (22 = Handshake)
        // Byte 1-2: Version (e.g., 03 01 or 03 03)
        // Byte 3-4: Length (uint16)
        
        if (clientHello.Length <= 5 || clientHello[0] != 0x16)
        {
            // Not a valid TLS handshake or too short, send as is
            await serverSocket.SendAsync(clientHello, SocketFlags.None, cancellationToken);
            return;
        }

        // Split the payload into chunks (e.g., first chunk of 10 bytes, rest in second chunk)
        int fragmentOffset = 15; // arbitrary offset, just enough to split SNI or early parts
        if (clientHello.Length > 5 + fragmentOffset)
        {
            byte[] header = new byte[5];
            Array.Copy(clientHello, 0, header, 0, 5);

            int payloadLen = (header[3] << 8) | header[4];

            // Record 1
            int len1 = fragmentOffset;
            byte[] record1 = new byte[5 + len1];
            Array.Copy(header, 0, record1, 0, 5);
            record1[3] = (byte)(len1 >> 8);
            record1[4] = (byte)(len1 & 0xFF);
            Array.Copy(clientHello, 5, record1, 5, len1);

            // Record 2
            int len2 = clientHello.Length - 5 - fragmentOffset;
            byte[] record2 = new byte[5 + len2];
            Array.Copy(header, 0, record2, 0, 5);
            record2[3] = (byte)(len2 >> 8);
            record2[4] = (byte)(len2 & 0xFF);
            Array.Copy(clientHello, 5 + fragmentOffset, record2, 5, len2);

            // Send parts using the stream
            await serverSocket.SendAsync(record1, SocketFlags.None, cancellationToken);
            await serverSocket.SendAsync(record2, SocketFlags.None, cancellationToken);
        }
        else
        {
            await serverSocket.SendAsync(clientHello, SocketFlags.None, cancellationToken);
        }
    }
}
