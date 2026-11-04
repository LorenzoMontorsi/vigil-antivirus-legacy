using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

// Agente di prova per la VM Windows XP, dove non c'è OpenSSH: esegue comandi e copia file
// per conto dello script sull'host (tests\vm\xp.ps1). Solo per la VM di prova, in rete NAT:
// richiede il token scritto nel CD di installazione, generato a ogni creazione della VM.
//
// Protocollo (una connessione per richiesta):
//   token\n  EXEC\n <comando cmd.exe>\n          → codice di uscita\n + output
//   token\n  PUT\n  <percorso>\n <lunghezza>\n <byte> → "ok"
//   token\n  GET\n  <percorso>\n                → lunghezza\n + byte
static class VmAgent
{
    const int Port = 7799;
    static string token;

    static void Main(string[] args)
    {
        token = File.ReadAllText(args.Length > 0 ? args[0] : Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "token.txt")).Trim();
        var l = new TcpListener(IPAddress.Any, Port);
        l.Start();
        while (true)
        {
            var c = l.AcceptTcpClient();
            new Thread(() => Serve(c)) { IsBackground = true }.Start();
        }
    }

    static string ReadLine(Stream s)
    {
        var b = new MemoryStream();
        int x;
        while ((x = s.ReadByte()) >= 0 && x != '\n')
            if (x != '\r') b.WriteByte((byte)x);
        return Encoding.UTF8.GetString(b.ToArray());
    }

    static void Write(Stream s, string text)
    {
        var b = Encoding.UTF8.GetBytes(text);
        s.Write(b, 0, b.Length);
    }

    static void Serve(TcpClient c)
    {
        using (c)
        using (var s = c.GetStream())
        {
            try
            {
                if (ReadLine(s) != token) return;
                var op = ReadLine(s);
                if (op == "EXEC")
                {
                    var cmd = ReadLine(s);
                    var psi = new ProcessStartInfo("cmd.exe", "/c " + cmd)
                    {
                        UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true,
                    };
                    var sb = new StringBuilder();
                    using (var p = Process.Start(psi))
                    {
                        p.OutputDataReceived += (o, e) => { if (e.Data != null) lock (sb) sb.AppendLine(e.Data); };
                        p.ErrorDataReceived += (o, e) => { if (e.Data != null) lock (sb) sb.AppendLine(e.Data); };
                        p.BeginOutputReadLine();
                        p.BeginErrorReadLine();
                        p.WaitForExit();
                        p.WaitForExit(2000);
                        Write(s, p.ExitCode + "\n" + sb);
                    }
                }
                else if (op == "PUT")
                {
                    var path = ReadLine(s);
                    long n = long.Parse(ReadLine(s));
                    Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)));
                    using (var f = File.Create(path))
                    {
                        var buf = new byte[65536];
                        while (n > 0)
                        {
                            int r = s.Read(buf, 0, (int)Math.Min(buf.Length, n));
                            if (r <= 0) throw new EndOfStreamException();
                            f.Write(buf, 0, r);
                            n -= r;
                        }
                    }
                    Write(s, "ok");
                }
                else if (op == "GET")
                {
                    var data = File.ReadAllBytes(ReadLine(s));
                    Write(s, data.Length + "\n");
                    s.Write(data, 0, data.Length);
                }
            }
            catch (Exception e)
            {
                try { Write(s, "-1\nagente: " + e.Message); } catch { }
            }
        }
    }
}
