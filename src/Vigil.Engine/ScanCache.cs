using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Vigil.Engine
{
    /// <summary>
    /// Cache delle scansioni: un file già trovato pulito, non modificato da allora
    /// e controllato con le stesse firme, non viene rianalizzato.
    ///
    /// La "generazione" identifica l'insieme di firme e opzioni: se cambia
    /// (aggiornamento firme, opzioni diverse) la cache riparte da zero.
    ///
    /// Limite noto: si basa su dimensione e data di modifica. Un attaccante che
    /// modifica un file mantenendo identiche dimensione e data lo farebbe saltare;
    /// la scansione completa con "ignora cache" resta il controllo definitivo.
    /// </summary>
    public sealed class ScanCache
    {
        static readonly byte[] Magic = Encoding.ASCII.GetBytes("VIGILC01");

        struct Entry
        {
            public long Size, MTime;
        }

        readonly string file;
        readonly Dictionary<string, Entry> map;
        readonly object gate = new object();
        bool dirty;

        public string Generation { get; private set; }

        public ScanCache(string file, string generation)
        {
            this.file = file;
            Generation = generation;
            map = Read(file, generation) ?? new Dictionary<string, Entry>();
        }

        public int Count
        {
            get { lock (gate) return map.Count; }
        }

        static string Key(string path)
        {
            return path.ToLowerInvariant();
        }

        public bool IsClean(FileInfo fi)
        {
            Entry e;
            lock (gate)
                return map.TryGetValue(Key(fi.FullName), out e) && e.Size == fi.Length && e.MTime == fi.LastWriteTimeUtc.Ticks;
        }

        public void MarkClean(FileInfo fi)
        {
            lock (gate)
            {
                map[Key(fi.FullName)] = new Entry { Size = fi.Length, MTime = fi.LastWriteTimeUtc.Ticks };
                dirty = true;
            }
        }

        public void Forget(string path)
        {
            lock (gate)
                dirty |= map.Remove(Key(path));
        }

        public void Clear()
        {
            lock (gate)
            {
                map.Clear();
                dirty = false;
            }
            if (File.Exists(file))
                File.Delete(file);
        }

        public void Save()
        {
            byte[] bytes;
            lock (gate)
            {
                if (!dirty)
                    return;
                dirty = false;
                var ms = new MemoryStream();
                var w = new BinaryWriter(ms, Encoding.UTF8);
                w.Write(Magic);
                w.Write(Generation);
                w.Write((long)map.Count);
                foreach (var kv in map)
                {
                    w.Write(kv.Key);
                    w.Write(kv.Value.Size);
                    w.Write(kv.Value.MTime);
                }
                w.Flush();
                bytes = ms.ToArray();
            }
            FileUtil.WriteAtomic(file, bytes);
        }

        static Dictionary<string, Entry> Read(string file, string generation)
        {
            try
            {
                if (!File.Exists(file))
                    return null;
                using (var r = new BinaryReader(File.OpenRead(file), Encoding.UTF8))
                {
                    var magic = r.ReadBytes(Magic.Length);
                    for (int i = 0; i < Magic.Length; i++)
                        if (magic.Length != Magic.Length || magic[i] != Magic[i])
                            return null;
                    if (r.ReadString() != generation)
                        return null;
                    long n = r.ReadInt64();
                    var map = new Dictionary<string, Entry>((int)Math.Min(n, 1000000));
                    for (long i = 0; i < n; i++)
                    {
                        var k = r.ReadString();
                        map[k] = new Entry { Size = r.ReadInt64(), MTime = r.ReadInt64() };
                    }
                    return map;
                }
            }
            catch (Exception)
            {
                return null; // cache rovinata: si riparte da zero
            }
        }
    }
}
