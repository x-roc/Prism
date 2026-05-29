using System;
using System.Text;

namespace Prism;

public static class TlsParser
{
    /// <summary>
    /// Very basic logic to create a fake ClientHello by replacing the SNI extension in the raw packet.
    /// A robust implementation should parse the TLS records and Extensions sequentially.
    /// For demonstration, we just use a predefined minimal ClientHello with the target fake SNI.
    /// </summary>
    public static byte[] CreateFakeClientHello(byte[] originalClientHello, string fakeSni)
    {
        // To properly spoof the SNI, you should reconstruct a valid ClientHello. 
        // For simplicity in this implementation, we return a hardcoded valid TLS 1.2 ClientHello
        // referencing the false SNI.
        
        byte[] sniBytes = Encoding.ASCII.GetBytes(fakeSni);
        int sniLen = sniBytes.Length;

        // Construct server name extension
        byte[] sniExt = new byte[9 + sniLen];
        sniExt[0] = 0x00; sniExt[1] = 0x00; // Extension type: Server Name (0x0000)
        sniExt[2] = (byte)((sniLen + 5) >> 8); sniExt[3] = (byte)((sniLen + 5) & 0xFF); // Extension length
        sniExt[4] = (byte)((sniLen + 3) >> 8); sniExt[5] = (byte)((sniLen + 3) & 0xFF); // Server Name list length
        sniExt[6] = 0x00; // Server Name Type: host_name
        sniExt[7] = (byte)(sniLen >> 8); sniExt[8] = (byte)(sniLen & 0xFF); // Host_name length
        Array.Copy(sniBytes, 0, sniExt, 9, sniLen);

        // Boilerplate ClientHello template (just for decoy evasion)
        byte[] decoyTemplate = new byte[] {
            0x16, // Content Type: Handshake
            0x03, 0x01, // Version: TLS 1.0 (Record Layer)
            0x00, 0x00, // Length placeholder
            
            0x01, // Handshake Type: Client Hello
            0x00, 0x00, 0x00, // Handshake Length placeholder
            
            0x03, 0x03, // Version: TLS 1.2 (Handshake Protocol)
            // Random (32 bytes)...
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
            
            0x00, // Session ID Length
            0x00, 0x02, 0x13, 0x01, // Cipher Suites Length (2) + TLS_AES_128_GCM_SHA256
            0x01, 0x00, // Compression Methods Length (1) + null
            
            // Extensions placeholder
        };

        int extLength = sniExt.Length; // You might add supported versions, key share etc.

        int handshakeLength = decoyTemplate.Length - 5 + 2 + extLength - 4; // Minus header (5), minus handshake header (4), plus Extension length bytes (2)
        int recordLength = handshakeLength + 4;

        byte[] finalPacket = new byte[5 + recordLength];
        
        // Copy headers up to Handshake Type
        Array.Copy(decoyTemplate, 0, finalPacket, 0, decoyTemplate.Length);

        // Fill Lengths
        finalPacket[3] = (byte)(recordLength >> 8);
        finalPacket[4] = (byte)(recordLength & 0xFF);
        
        finalPacket[6] = (byte)(handshakeLength >> 16);
        finalPacket[7] = (byte)(handshakeLength >> 8);
        finalPacket[8] = (byte)(handshakeLength & 0xFF);
        
        // Extension length field
        int extStart = decoyTemplate.Length;
        finalPacket[extStart] = (byte)(extLength >> 8);
        finalPacket[extStart + 1] = (byte)(extLength & 0xFF);
        
        // Copy Extension
        Array.Copy(sniExt, 0, finalPacket, extStart + 2, sniExt.Length);
        
        return finalPacket;
    }
}
