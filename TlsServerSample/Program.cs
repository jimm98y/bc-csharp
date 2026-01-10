using Org.BouncyCastle.Tls;
using SharpSRTP.DTLS;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using TlsServerSample;

var ecdsaCertificate = DtlsCertificateUtils.GenerateCertificate("WebRTC", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30), false);

TcpListener tcp = new TcpListener(IPAddress.Any, 8888);
tcp.Start(); 

while(true)
{
    var ss = tcp.AcceptTcpClient();
    var clientTask = Task.Run(() =>
    {
        var server = new MockTlsServer(ecdsaCertificate.Certificate, ecdsaCertificate.PrivateKey);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(ss.GetStream());
        serverProtocol.Accept(server);

        using (var stream = serverProtocol.Stream)
        {
            stream.Write(Encoding.UTF8.GetBytes("Server hello!"));
            stream.Flush();
        }
    });
}
