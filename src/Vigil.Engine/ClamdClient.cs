using System;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace Vigil.Engine
{
    /// <summary>
    /// Client minimale per il demone <c>clamd</c> di ClamAV (protocollo TCP, comando INSTREAM).
    /// Ogni chiamata apre una connessione: clamd gestisce le richieste in parallelo
    /// (<c>MaxThreads</c>), quindi più worker possono usarlo contemporaneamente.
    /// </summary>
    public sealed class ClamdClient
    {
        const int Chunk = 1 << 20;

        public string Host { get; private set; }
        public int Port { get; private set; }
        public int TimeoutMs { get; set; }

        public ClamdClient(string host = "127.0.0.1", int port = 3310)
        {
            Host = host;
            Port = port;
            TimeoutMs = 120000;
        }

        TcpClient Connect()
        {
            var c = new TcpClient();
            var ar = c.BeginConnect(Host, Port, null, null);
            if (!ar.AsyncWaitHandle.WaitOne(3000))
            {
                c.Close();
                throw new IOException("clamd non risponde su " + Host + ":" + Port);
            }
            c.EndConnect(ar);
            c.ReceiveTimeout = TimeoutMs;
            c.SendTimeout = TimeoutMs;
            return c;
        }

        string Command(string cmd)
        {
            using (var c = Connect())
            {
                var s = c.GetStream();
                var b = Encoding.ASCII.GetBytes("z" + cmd + "\0");
                s.Write(b, 0, b.Length);
                return ReadReply(s);
            }
        }

        /// <summary>true se il demone risponde (firme caricate).</summary>
        public bool Ping()
        {
            try
            {
                return Command("PING") == "PONG";
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>Es. "ClamAV 1.5.2/27800/Sun Nov  1 09:00:00 2026".</summary>
        public string Version()
        {
            return Command("VERSION");
        }

        /// <summary>Ricarica le firme dal disco (dopo un aggiornamento).</summary>
        public string Reload()
        {
            return Command("RELOAD");
        }

        public void Shutdown()
        {
            using (var c = Connect())
            {
                var b = Encoding.ASCII.GetBytes("zSHUTDOWN\0");
                c.GetStream().Write(b, 0, b.Length);
            }
        }

        /// <summary>Nome della minaccia, oppure null se pulito. Eccezione se clamd dà errore.</summary>
        public string Scan(byte[] data)
        {
            using (var c = Connect())
            {
                var s = c.GetStream();
                var cmd = Encoding.ASCII.GetBytes("zINSTREAM\0");
                s.Write(cmd, 0, cmd.Length);
                for (int off = 0; off < data.Length; off += Chunk)
                {
                    int n = Math.Min(Chunk, data.Length - off);
                    s.Write(BigEndian(n), 0, 4);
                    s.Write(data, off, n);
                }
                s.Write(BigEndian(0), 0, 4);
                return ParseReply(ReadReply(s));
            }
        }

        static byte[] BigEndian(int n)
        {
            return new[] { (byte)(n >> 24), (byte)(n >> 16), (byte)(n >> 8), (byte)n };
        }

        static string ReadReply(Stream s)
        {
            var ms = new MemoryStream();
            var buf = new byte[4096];
            int r;
            while ((r = s.Read(buf, 0, buf.Length)) > 0)
                ms.Write(buf, 0, r);
            return Encoding.UTF8.GetString(ms.ToArray()).TrimEnd('\0', '\n');
        }

        /// <summary>"stream: OK" → null; "stream: Nome FOUND" → "Nome"; altrimenti eccezione.</summary>
        public static string ParseReply(string reply)
        {
            var body = reply.StartsWith("stream: ") ? reply.Substring(8) : reply;
            if (body == "OK")
                return null;
            if (body.EndsWith(" FOUND"))
                return body.Substring(0, body.Length - 6);
            throw new IOException("ClamAV: " + body);
        }
    }
}
