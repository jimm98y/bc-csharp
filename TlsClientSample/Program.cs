
using Org.BouncyCastle.Tls;
using System.Net.Sockets;
using TlsClientSample;

MockTlsClient client = new MockTlsClient(null);
TcpClient tcp = new TcpClient("127.0.0.1", 8888);
TlsClientProtocol protocol = new TlsClientProtocol(tcp.GetStream());
protocol.Connect(client);

while(true)
{
    await Task.Delay(1000);
}

protocol.Close();
