using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace TlsClientSample
{
    public class MockTlsClient
        : DefaultTlsClient
    {
        internal TlsSession m_session;

        internal MockTlsClient(TlsSession session)
            : base(new BcTlsCrypto())
        {
            this.m_session = session;
        }

        protected override IList<ProtocolName> GetProtocolNames()
        {
            var protocolNames = new List<ProtocolName>();
            protocolNames.Add(ProtocolName.Http_1_1);
            protocolNames.Add(ProtocolName.Http_2_Tls);
            return protocolNames;
        }

        public override TlsSession GetSessionToResume()
        {
            return m_session;
        }

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message,
            Exception cause)
        {
            TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
            output.WriteLine("TLS client raised alert: " + AlertLevel.GetText(alertLevel)
                + ", " + AlertDescription.GetText(alertDescription));
            if (message != null)
            {
                output.WriteLine("> " + message);
            }
            if (cause != null)
            {
                output.WriteLine(cause);
            }
        }

        public override void NotifyAlertReceived(short alertLevel, short alertDescription)
        {
            TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
            output.WriteLine("TLS client received alert: " + AlertLevel.GetText(alertLevel)
                + ", " + AlertDescription.GetText(alertDescription));
        }

        public override IDictionary<int, byte[]> GetClientExtensions()
        {
            if (m_context.SecurityParameters.ClientRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            var clientExtensions = TlsExtensionsUtilities.EnsureExtensionsInitialised(
                base.GetClientExtensions());

            {  }
            return clientExtensions;
        }

        public override void NotifyServerVersion(ProtocolVersion serverVersion)
        {
            base.NotifyServerVersion(serverVersion);

            Console.WriteLine("TLS client negotiated version " + serverVersion);
        }

        public override TlsAuthentication GetAuthentication()
        {
            return new MyTlsAuthentication(m_context);
        }

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            ProtocolName protocolName = m_context.SecurityParameters.ApplicationProtocol;
            if (protocolName != null)
            {
                Console.WriteLine("Client ALPN: " + protocolName.GetUtf8Decoding());
            }

            TlsSession newSession = m_context.Session;
            if (newSession != null)
            {
                if (newSession.IsResumable)
                {
                    byte[] newSessionID = newSession.SessionID;
                    string hex = ToHexString(newSessionID);

                    if (m_session != null && Arrays.AreEqual(m_session.SessionID, newSessionID))
                    {
                        Console.WriteLine("Client resumed session: " + hex);
                    }
                    else
                    {
                        Console.WriteLine("Client established session: " + hex);
                    }

                    this.m_session = newSession;
                }

                byte[] tlsServerEndPoint = m_context.ExportChannelBinding(ChannelBinding.tls_server_end_point);
                if (null != tlsServerEndPoint)
                {
                    Console.WriteLine("Client 'tls-server-end-point': " + ToHexString(tlsServerEndPoint));
                }

                byte[] tlsUnique = m_context.ExportChannelBinding(ChannelBinding.tls_unique);
                Console.WriteLine("Client 'tls-unique': " + ToHexString(tlsUnique));

                byte[] tlsExporter = m_context.ExportChannelBinding(ChannelBinding.tls_exporter);
                Console.WriteLine("Client 'tls-exporter': " + ToHexString(tlsExporter));
            }
        }

        public override void ProcessServerExtensions(IDictionary<int, byte[]> serverExtensions)
        {
            if (m_context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            base.ProcessServerExtensions(serverExtensions);
        }

        protected virtual string ToHexString(byte[] data)
        {
            return data == null ? "(null)" : Hex.ToHexString(data);
        }

        internal class MyTlsAuthentication
            : TlsAuthentication
        {
            private readonly TlsContext m_context;

            internal MyTlsAuthentication(TlsContext context)
            {
                this.m_context = context;
            }

            public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest)
            {
                return null;
            }

            public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {
            }
        };
    }
}
