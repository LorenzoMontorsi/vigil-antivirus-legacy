using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using BcCert = Org.BouncyCastle.X509.X509Certificate;
using BcCertParser = Org.BouncyCastle.X509.X509CertificateParser;

namespace Vigil.Engine
{
    /// <summary>
    /// Client HTTPS minimo con TLS 1.2/1.3 di BouncyCastle, indipendente da SChannel: su Windows XP
    /// il sistema arriva al massimo a TLS 1.0, che i server di oggi rifiutano.
    ///
    /// Il certificato del server si verifica qui, sempre con BouncyCastle (XP non sa verificare le
    /// firme ECDSA): catena, date, nome del server; le radici fidate sono quelle di Mozilla (incluse
    /// nel programma, da curl.se/ca) più quelle del sistema.
    /// </summary>
    public static class Https
    {
        public const string UserAgent = "VigilLegacy/" + ScanEngine.Version + " (+antivirus open source per Windows legacy)";

        public sealed class Response
        {
            public int Status;
            public string Url;
            public Dictionary<string, string> Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            public byte[] Body;
        }

        public sealed class HttpException : Exception
        {
            public int Status { get; private set; }
            public HttpException(int status, string message) : base(message) { Status = status; }
        }

        /// <summary>GET con redirezioni; eccezione se lo stato finale non è 2xx.</summary>
        public static Response Get(string url, long maxBytes, IDictionary<string, string> headers = null, int timeoutMs = 300000)
        {
            for (int hop = 0; hop < 6; hop++)
            {
                var r = Request(new Uri(url), maxBytes, headers, timeoutMs);
                if (r.Status >= 300 && r.Status < 400 && r.Headers.ContainsKey("Location"))
                {
                    url = new Uri(new Uri(url), r.Headers["Location"]).AbsoluteUri;
                    continue;
                }
                if (r.Status < 200 || r.Status >= 300)
                    throw new HttpException(r.Status, "il server ha risposto " + r.Status);
                return r;
            }
            throw new IOException("troppe redirezioni");
        }

        static Response Request(Uri uri, long maxBytes, IDictionary<string, string> headers, int timeoutMs)
        {
            bool tls = uri.Scheme == Uri.UriSchemeHttps;
            if (!tls && uri.Scheme != Uri.UriSchemeHttp)
                throw new ArgumentException("indirizzo non supportato: " + uri);
            using (var tcp = new TcpClient())
            {
                tcp.ReceiveTimeout = tcp.SendTimeout = timeoutMs;
                tcp.Connect(uri.Host, uri.Port);
                Stream s = tcp.GetStream();
                TlsClientProtocol protocol = null;
                try
                {
                    if (tls)
                    {
                        protocol = new TlsClientProtocol(s);
                        protocol.Connect(new Client(uri.Host));
                        s = protocol.Stream;
                    }
                    var req = new StringBuilder();
                    req.Append("GET ").Append(uri.PathAndQuery).Append(" HTTP/1.1\r\n");
                    req.Append("Host: ").Append(uri.IsDefaultPort ? uri.Host : uri.Host + ":" + uri.Port).Append("\r\n");
                    req.Append("User-Agent: ").Append(UserAgent).Append("\r\n");
                    req.Append("Accept-Encoding: identity\r\nConnection: close\r\n");
                    if (headers != null)
                        foreach (var h in headers)
                            req.Append(h.Key).Append(": ").Append(h.Value).Append("\r\n");
                    req.Append("\r\n");
                    var b = Encoding.ASCII.GetBytes(req.ToString());
                    s.Write(b, 0, b.Length);
                    s.Flush();
                    return ReadResponse(s, uri, maxBytes);
                }
                finally
                {
                    if (protocol != null)
                        try { protocol.Close(); } catch { }
                }
            }
        }

        static Response ReadResponse(Stream s, Uri uri, long maxBytes)
        {
            var r = new Response { Url = uri.AbsoluteUri };
            var status = ReadLine(s);
            var parts = status.Split(' ');
            if (parts.Length < 2 || !parts[0].StartsWith("HTTP/") || !int.TryParse(parts[1], out r.Status))
                throw new IOException("risposta HTTP non valida");
            string line;
            while ((line = ReadLine(s)).Length > 0)
            {
                int c = line.IndexOf(':');
                if (c > 0) r.Headers[line.Substring(0, c).Trim()] = line.Substring(c + 1).Trim();
            }
            var body = new MemoryStream();
            string te, cl;
            if (r.Headers.TryGetValue("Transfer-Encoding", out te) && te.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                while (true)
                {
                    var size = ReadLine(s).Split(';')[0].Trim();
                    long n = Convert.ToInt64(size, 16);
                    if (n == 0) break;
                    Copy(s, body, n, maxBytes);
                    ReadLine(s);
                }
            }
            else if (r.Headers.TryGetValue("Content-Length", out cl))
                Copy(s, body, long.Parse(cl), maxBytes);
            else
                Copy(s, body, -1, maxBytes);
            r.Body = body.ToArray();
            return r;
        }

        static void Copy(Stream from, MemoryStream to, long n, long maxBytes)
        {
            var buf = new byte[65536];
            while (n != 0)
            {
                int want = n < 0 ? buf.Length : (int)Math.Min(buf.Length, n);
                int got;
                try { got = from.Read(buf, 0, want); }
                catch (TlsNoCloseNotifyException) { got = 0; }
                if (got <= 0)
                {
                    if (n < 0) return;
                    throw new IOException("download interrotto");
                }
                if (to.Length + got > maxBytes)
                    throw new IOException("file troppo grande");
                to.Write(buf, 0, got);
                if (n > 0) n -= got;
            }
        }

        static string ReadLine(Stream s)
        {
            var b = new List<byte>();
            int x;
            while ((x = s.ReadByte()) >= 0 && x != '\n')
            {
                if (x != '\r') b.Add((byte)x);
                if (b.Count > 16384) throw new IOException("intestazione HTTP troppo lunga");
            }
            return Encoding.ASCII.GetString(b.ToArray());
        }

        sealed class Client : DefaultTlsClient
        {
            readonly string host;

            public Client(string host) : base(new BcTlsCrypto(new SecureRandom()))
            {
                this.host = host;
            }

            protected override IList GetSniServerNames()
            {
                return new ArrayList { new ServerName(NameType.host_name, Encoding.ASCII.GetBytes(host)) };
            }

            public override TlsAuthentication GetAuthentication()
            {
                return new Auth(host);
            }
        }

        sealed class Auth : ServerOnlyTlsAuthentication
        {
            readonly string host;
            public Auth(string host) { this.host = host; }

            public override void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {
                var list = serverCertificate.Certificate.GetCertificateList();
                var parser = new BcCertParser();
                var chain = new List<BcCert>();
                foreach (var c in list)
                    chain.Add(parser.ReadCertificate(c.GetEncoded()));
                string why = CertValidator.Validate(chain, host, DateTime.UtcNow);
                if (why != null)
                    throw new TlsFatalAlert(AlertDescription.bad_certificate, new IOException("certificato di " + host + " non valido: " + why));
            }
        }
    }

    /// <summary>Verifica di una catena di certificati del server (con BouncyCastle).</summary>
    public static class CertValidator
    {
        static readonly object gate = new object();
        static List<BcCert> anchors;

        /// <summary>Radici fidate: Mozilla (risorsa inclusa) e archivio "Root" del sistema.</summary>
        public static List<BcCert> Anchors
        {
            get
            {
                lock (gate)
                {
                    if (anchors != null) return anchors;
                    var list = new List<BcCert>();
                    var parser = new BcCertParser();
                    using (var s = typeof(CertValidator).Assembly.GetManifestResourceStream("Vigil.Engine.Resources.cacert.pem"))
                    using (var r = new StreamReader(s, Encoding.ASCII))
                    {
                        var pem = r.ReadToEnd();
                        int at = 0;
                        while ((at = pem.IndexOf("-----BEGIN CERTIFICATE-----", at, StringComparison.Ordinal)) >= 0)
                        {
                            int end = pem.IndexOf("-----END CERTIFICATE-----", at, StringComparison.Ordinal);
                            if (end < 0) break;
                            var b64 = pem.Substring(at + 27, end - at - 27);
                            try { list.Add(parser.ReadCertificate(Convert.FromBase64String(b64))); } catch { }
                            at = end;
                        }
                    }
                    try
                    {
                        var store = new System.Security.Cryptography.X509Certificates.X509Store(
                            System.Security.Cryptography.X509Certificates.StoreName.Root,
                            System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine);
                        store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);
                        foreach (var c in store.Certificates)
                            try { list.Add(parser.ReadCertificate(c.RawData)); } catch { }
                        store.Close();
                    }
                    catch { }
                    anchors = list;
                    return anchors;
                }
            }
        }

        /// <summary>null se la catena è valida per <paramref name="host"/>, altrimenti il motivo.</summary>
        public static string Validate(IList<BcCert> chain, string host, DateTime nowUtc, IList<BcCert> trusted = null)
        {
            if (chain.Count == 0) return "nessun certificato";
            trusted = trusted ?? Anchors;
            var leaf = chain[0];
            if (!MatchesHost(leaf, host)) return "è intestato a un altro nome";

            for (int i = 0; i < chain.Count; i++)
            {
                var c = chain[i];
                if (nowUtc < c.NotBefore.ToUniversalTime() || nowUtc > c.NotAfter.ToUniversalTime())
                    return "scaduto o non ancora valido (" + c.SubjectDN + ")";
                if (i > 0 && c.GetBasicConstraints() < 0)
                    return "un certificato intermedio non è un'autorità";
                // Il certificato è esso stesso una radice fidata (stesso soggetto e chiave)?
                foreach (var a in trusted)
                    if (a.SubjectDN.Equivalent(c.SubjectDN) && a.GetPublicKey().Equals(c.GetPublicKey()))
                        return null;
                // Emesso da una radice fidata?
                foreach (var a in trusted)
                    if (a.SubjectDN.Equivalent(c.IssuerDN) && Verifies(c, a))
                        return null;
                // Altrimenti deve essere firmato dal successivo della catena.
                if (i + 1 >= chain.Count) return "emesso da un'autorità non fidata";
                if (!chain[i + 1].SubjectDN.Equivalent(c.IssuerDN) || !Verifies(c, chain[i + 1]))
                    return "catena interrotta";
            }
            return "emesso da un'autorità non fidata";
        }

        static bool Verifies(BcCert c, BcCert issuer)
        {
            try
            {
                c.Verify(issuer.GetPublicKey());
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static bool MatchesHost(BcCert cert, string host)
        {
            host = host.TrimEnd('.').ToLowerInvariant();
            var names = new List<string>();
            var san = cert.GetSubjectAlternativeNames();
            if (san != null)
                foreach (IList e in san)
                    if (e.Count >= 2 && Convert.ToInt32(e[0]) == 2) // dNSName
                        names.Add(Convert.ToString(e[1]));
            if (names.Count == 0)
                foreach (var cn in cert.SubjectDN.GetValueList(Org.BouncyCastle.Asn1.X509.X509Name.CN))
                    names.Add(Convert.ToString(cn));
            foreach (var n in names)
            {
                var p = n.TrimEnd('.').ToLowerInvariant();
                if (p == host) return true;
                if (p.StartsWith("*.") && host.EndsWith(p.Substring(1)) && host.IndexOf('.') == host.Length - p.Length + 1)
                    return true;
            }
            return false;
        }
    }
}
