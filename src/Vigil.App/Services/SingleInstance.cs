using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;

namespace Vigil.App.Services
{
    /// <summary>
    /// Una sola istanza per utente. Le successive inviano la propria riga di comando
    /// alla prima attraverso una named pipe (disponibile da .NET 3.5, anche su XP) e terminano.
    /// </summary>
    public sealed class SingleInstance : IDisposable
    {
        readonly Mutex mutex;
        readonly string pipeName;
        public bool IsFirst { get; private set; }

        /// <summary>Argomenti ricevuti da un'altra istanza (su un thread di lavoro).</summary>
        public event Action<string[]> ArgsReceived;

        public SingleInstance(string id)
        {
            // Nome per utente: su un PC condiviso ognuno ha il suo Vigil.
            var user = (Environment.UserDomainName + "." + Environment.UserName).Replace('\\', '.');
            pipeName = id + "." + user;
            bool created;
            mutex = new Mutex(true, @"Local\" + pipeName, out created);
            IsFirst = created;
            if (IsFirst)
                new Thread(Listen) { IsBackground = true, Name = "Vigil istanza" }.Start();
        }

        /// <summary>Invia gli argomenti all'istanza già aperta. false se non risponde.</summary>
        public bool Forward(string[] args)
        {
            for (int attempt = 0; attempt < 10; attempt++)
            {
                try
                {
                    using (var c = new NamedPipeClientStream(".", pipeName, PipeDirection.Out))
                    {
                        c.Connect(1000);
                        var w = new StreamWriter(c, new UTF8Encoding(false));
                        w.Write(string.Join("\n", args));
                        w.Flush();
                        return true;
                    }
                }
                catch (Exception)
                {
                    // Più istanze lanciate insieme (selezione multipla): la pipe è occupata, si riprova.
                    Thread.Sleep(150);
                }
            }
            return false;
        }

        void Listen()
        {
            while (true)
            {
                try
                {
                    using (var s = new NamedPipeServerStream(pipeName, PipeDirection.In, 1))
                    {
                        s.WaitForConnection();
                        string text;
                        using (var r = new StreamReader(s, Encoding.UTF8))
                            text = r.ReadToEnd();
                        var h = ArgsReceived;
                        if (h != null)
                            h(text.Length == 0 ? new string[0] : text.Split('\n'));
                    }
                }
                catch (Exception)
                {
                    Thread.Sleep(500);
                }
            }
        }

        public void Dispose()
        {
            if (IsFirst)
            {
                try { mutex.ReleaseMutex(); } catch (Exception) { }
            }
            mutex.Close();
        }
    }
}
