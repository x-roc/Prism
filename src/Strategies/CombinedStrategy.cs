using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Prism.Config;
using SharpPcap;
using PacketDotNet;

namespace Prism.Strategies;

public class CombinedStrategy : IDpiEvasionStrategy
{
    private static readonly object _pcapLock = new object();
    private static ILiveDevice? _cachedDevice = null;
    private static bool _deviceInitialized = false;

    public async Task ApplyAsync(Socket clientSocket, Socket serverSocket, byte[] clientHello, ProxyConfig config, CancellationToken cancellationToken)
    {
        Console.WriteLine("[CombinedStrategy] Applying Combined Evasion (Seq + TTL + Frag).");

        byte[] fakeSniPacket = TlsParser.CreateFakeClientHello(clientHello, config.FakeSniDomain);

        // 1 & 2. Seq Injector + TTL Spoofer via Raw Sockets
        try
        {
            var localEndpoint = (IPEndPoint)serverSocket.LocalEndPoint!;
            var remoteEndpoint = (IPEndPoint)serverSocket.RemoteEndPoint!;

            if (!_deviceInitialized)
            {
                lock (_pcapLock)
                {
                    if (!_deviceInitialized)
                    {
                        var devices = CaptureDeviceList.Instance;
                        
                        if (!string.IsNullOrEmpty(config.NetworkInterfaceName))
                        {
                            _cachedDevice = devices.FirstOrDefault(d => d.Name == config.NetworkInterfaceName);
                        }

                        if (_cachedDevice == null)
                        {
                            foreach (var d in devices)
                            {
                                if (d.MacAddress != null && d is SharpPcap.LibPcap.LibPcapLiveDevice lpd)
                                {
                                    if (lpd.Addresses.Any(a => a.Addr?.ipAddress?.Equals(localEndpoint.Address) == true))
                                    {
                                        _cachedDevice = d;
                                        break;
                                    }
                                }
                            }
                        }

                        if (_cachedDevice != null)
                        {
                            // Open once globally to avoid huge overhead of repeated Open/Close
                            _cachedDevice.Open(DeviceModes.None, 1);
                        }
                        _deviceInitialized = true;
                    }
                }
            }

            if (_cachedDevice != null)
            {
                lock (_pcapLock)
                {
                    var destMac = new System.Net.NetworkInformation.PhysicalAddress(new byte[] { 0, 0, 0, 0, 0, 0 });
                    var ethernetPacket = new EthernetPacket(_cachedDevice.MacAddress, destMac, EthernetType.IPv4);

                    var ipPacket = new IPv4Packet(localEndpoint.Address, remoteEndpoint.Address);
                    // Combine TTL Spoofer logic here!
                    ipPacket.TimeToLive = (int)config.DecoyTtl;
                    
                    uint outOfWindowSeq = 2000000000;
                    
                    var tcpPacket = new TcpPacket((ushort)localEndpoint.Port, (ushort)remoteEndpoint.Port)
                    {
                        SequenceNumber = outOfWindowSeq,
                        AcknowledgmentNumber = 0,
                        WindowSize = 65535,
                        Flags = 0x18, // PSH + ACK
                        PayloadData = fakeSniPacket
                    };
                    
                    ipPacket.PayloadPacket = tcpPacket;
                    ethernetPacket.PayloadPacket = ipPacket;

                    ipPacket.UpdateIPChecksum();
                    tcpPacket.UpdateTcpChecksum();

                    _cachedDevice.SendPacket(ethernetPacket);
                }
            }
            else
            {
                Console.WriteLine("[CombinedStrategy] Could not find interface for Seq Injector.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[CombinedStrategy] Seq/TTL Injection skipped/failed: {ex.Message}");
        }

        // 3. TLS Fragmenter logic
        try
        {
            if (clientHello.Length <= 5 || clientHello[0] != 0x16)
            {
                await serverSocket.SendAsync(clientHello, SocketFlags.None, cancellationToken);
                return;
            }

            int fragmentOffset = 15;
            if (clientHello.Length > 5 + fragmentOffset)
            {
                byte[] header = new byte[5];
                Array.Copy(clientHello, 0, header, 0, 5);

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

                await serverSocket.SendAsync(record1, SocketFlags.None, cancellationToken);
                await serverSocket.SendAsync(record2, SocketFlags.None, cancellationToken);
                Console.WriteLine("[CombinedStrategy] Fragmented real ClientHello sent.");
            }
            else
            {
                await serverSocket.SendAsync(clientHello, SocketFlags.None, cancellationToken);
                Console.WriteLine("[CombinedStrategy] Unfragmented real ClientHello sent (too short).");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[CombinedStrategy] Fragmenter failed: {ex.Message}");
            await serverSocket.SendAsync(clientHello, SocketFlags.None, cancellationToken);
        }
    }
}
