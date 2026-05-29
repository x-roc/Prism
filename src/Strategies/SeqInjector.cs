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

public class SeqInjector : IDpiEvasionStrategy
{
    private static readonly object _pcapLock = new object();
    private static ILiveDevice? _cachedDevice = null;
    private static bool _deviceInitialized = false;

    public async Task ApplyAsync(Socket clientSocket, Socket serverSocket, byte[] clientHello, ProxyConfig config, CancellationToken cancellationToken)
    {
        Console.WriteLine("[SeqInjector] Applying TCP Sequence Injection.");

        try
        {
            byte[] fakeSniPacket = TlsParser.CreateFakeClientHello(clientHello, config.FakeSniDomain);

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
                                    if (lpd.Addresses.Any(a => a.Addr != null && a.Addr.ipAddress != null && a.Addr.ipAddress.Equals(localEndpoint.Address)))
                                    {
                                        _cachedDevice = d;
                                        break;
                                    }
                                }
                            }
                        }
                        if (_cachedDevice != null)
                        {
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
                Console.WriteLine("[SeqInjector] Injected decoy packet successfully.");
            }
            else
            {
                Console.WriteLine("[SeqInjector] Could not determine network interface. Falling back to sending real ClientHello.");
                await serverSocket.SendAsync(clientHello, SocketFlags.None, cancellationToken);
                return;
            }

            await serverSocket.SendAsync(clientHello, SocketFlags.None, cancellationToken);
        }
        catch (Exception outerEx)
        {
            Console.WriteLine($"[SeqInjector] Fatal error during injection strategy: {outerEx}");
            await serverSocket.SendAsync(clientHello, SocketFlags.None, cancellationToken);
        }
    }
}
