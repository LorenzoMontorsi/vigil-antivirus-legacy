using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography;

namespace Vigil.Engine
{
    [DataContract]
    public sealed class QuarantineItem
    {
        [DataMember(Name = "id")] public string Id { get; set; }
        [DataMember(Name = "original_path")] public string OriginalPath { get; set; }
        [DataMember(Name = "threat")] public string Threat { get; set; }

        /// <summary>Motore che l'ha rilevato ("clamav", "hash", "pattern", "heuristics").</summary>
        [DataMember(Name = "source")] public string Source { get; set; }

        [DataMember(Name = "sha256")] public string Sha256 { get; set; }
        [DataMember(Name = "size")] public long Size { get; set; }
        [DataMember(Name = "quarantined_at")] public long QuarantinedAt { get; set; }
    }

    public sealed class QuarantineException : Exception
    {
        public QuarantineException(string message) : base(message) { }
    }

    /// <summary>
    /// Quarantena: i file pericolosi vengono cifrati e spostati in un deposito.
    ///
    /// Cifrare il contenuto (AES-256-CBC + HMAC-SHA256) serve a neutralizzarlo: il file
    /// non è eseguibile né riconoscibile dagli altri antivirus, e l'HMAC garantisce che
    /// un ripristino restituisca esattamente l'originale. La chiave è per-installazione
    /// e sta nel deposito stesso: lo scopo non è la segretezza ma l'isolamento.
    /// (RijndaelManaged perché AesCryptoServiceProvider non esiste su XP.)
    ///
    /// Struttura del deposito:
    ///   key.bin     64 byte: chiave AES + chiave HMAC
    ///   &lt;id&gt;.vq     "VQ1" + IV (16) + contenuto cifrato + HMAC (32)
    ///   &lt;id&gt;.json   metadati (percorso originale, minaccia, …)
    /// </summary>
    public sealed class Quarantine
    {
        public const long MaxSize = 512L * 1024 * 1024;
        static readonly byte[] Magic = { (byte)'V', (byte)'Q', (byte)'1' };

        readonly byte[] encKey = new byte[32], macKey = new byte[32];
        public string Dir { get; private set; }

        public Quarantine(string dir)
        {
            Dir = dir;
            Directory.CreateDirectory(dir);
            var keyPath = Path.Combine(dir, "key.bin");
            byte[] key;
            if (File.Exists(keyPath))
            {
                key = File.ReadAllBytes(keyPath);
                if (key.Length != 64)
                    throw new QuarantineException("chiave della quarantena non valida");
            }
            else
            {
                key = new byte[64];
                using (var rng = new RNGCryptoServiceProvider())
                    rng.GetBytes(key);
                File.WriteAllBytes(keyPath, key);
            }
            Buffer.BlockCopy(key, 0, encKey, 0, 32);
            Buffer.BlockCopy(key, 32, macKey, 0, 32);
        }

        string BlobPath(string id) { return Path.Combine(Dir, id + ".vq"); }
        string MetaPath(string id) { return Path.Combine(Dir, id + ".json"); }

        /// <summary>
        /// Isola un file: lo cifra nel deposito e poi elimina l'originale.
        /// Se l'originale non si può eliminare, la quarantena viene annullata.
        /// </summary>
        public QuarantineItem Add(string path, string threat, string source)
        {
            byte[] data;
            try
            {
                var fi = new FileInfo(path);
                if (fi.Length > MaxSize)
                    throw new QuarantineException("file troppo grande per la quarantena (oltre 512 MB)");
                data = File.ReadAllBytes(path);
            }
            catch (IOException e) { throw Translate(e); }
            catch (UnauthorizedAccessException) { throw AccessDenied(); }

            var id = NewId();
            var item = new QuarantineItem
            {
                Id = id,
                OriginalPath = Path.GetFullPath(path),
                Threat = threat,
                Source = source,
                Sha256 = Hashing.ToHex(Hashing.Sha256(data)),
                Size = data.Length,
                QuarantinedAt = FileUtil.NowUnix(),
            };
            FileUtil.WriteAtomic(BlobPath(id), Encrypt(data));
            Json.Save(MetaPath(id), item);

            try
            {
                RemoveForced(path);
            }
            catch (Exception e)
            {
                // Annulla: niente copie in quarantena di file rimasti al loro posto.
                TryDelete(BlobPath(id));
                TryDelete(MetaPath(id));
                if (e is IOException) throw Translate((IOException)e);
                if (e is UnauthorizedAccessException) throw AccessDenied();
                throw;
            }
            return item;
        }

        public List<QuarantineItem> List()
        {
            var items = new List<QuarantineItem>();
            foreach (var f in Directory.GetFiles(Dir, "*.json"))
            {
                var item = Json.Load<QuarantineItem>(f);
                if (item != null && ValidId(item.Id) && File.Exists(BlobPath(item.Id)))
                    items.Add(item);
            }
            return items.OrderByDescending(i => i.QuarantinedAt).ToList();
        }

        public QuarantineItem Get(string id)
        {
            var item = ValidId(id) ? Json.Load<QuarantineItem>(MetaPath(id)) : null;
            if (item == null)
                throw new QuarantineException("elemento non trovato in quarantena");
            return item;
        }

        /// <summary>Ripristina un file (nel percorso originale se target è null). Non sovrascrive mai.</summary>
        public string Restore(string id, string target = null)
        {
            var item = Get(id);
            var dest = target ?? item.OriginalPath;
            if (File.Exists(dest) || Directory.Exists(dest))
                throw new QuarantineException("esiste già un file in " + dest);
            var data = Decrypt(File.ReadAllBytes(BlobPath(id)));
            if (data == null || Hashing.ToHex(Hashing.Sha256(data)) != item.Sha256)
                throw new QuarantineException("elemento in quarantena danneggiato: impossibile ripristinarlo");
            var parent = Path.GetDirectoryName(dest);
            if (!string.IsNullOrEmpty(parent))
                Directory.CreateDirectory(parent);
            // CreateNew: fallisce se nel frattempo è comparso un file con quel nome.
            using (var f = new FileStream(dest, FileMode.CreateNew, FileAccess.Write))
                f.Write(data, 0, data.Length);
            Delete(id);
            return dest;
        }

        public void Delete(string id)
        {
            if (!ValidId(id))
                throw new QuarantineException("elemento non trovato in quarantena");
            bool a = TryDelete(MetaPath(id)), b = TryDelete(BlobPath(id));
            if (!a && !b)
                throw new QuarantineException("elemento non trovato in quarantena");
        }

        byte[] Encrypt(byte[] plain)
        {
            using (var aes = new RijndaelManaged { KeySize = 256, BlockSize = 128, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 })
            {
                aes.Key = encKey;
                aes.GenerateIV();
                byte[] cipher;
                using (var enc = aes.CreateEncryptor())
                    cipher = enc.TransformFinalBlock(plain, 0, plain.Length);
                var blob = new byte[Magic.Length + 16 + cipher.Length + 32];
                Buffer.BlockCopy(Magic, 0, blob, 0, Magic.Length);
                Buffer.BlockCopy(aes.IV, 0, blob, Magic.Length, 16);
                Buffer.BlockCopy(cipher, 0, blob, Magic.Length + 16, cipher.Length);
                using (var mac = new HMACSHA256(macKey))
                {
                    var tag = mac.ComputeHash(blob, 0, blob.Length - 32);
                    Buffer.BlockCopy(tag, 0, blob, blob.Length - 32, 32);
                }
                return blob;
            }
        }

        /// <summary>null se il contenuto è stato alterato o non è un elemento valido.</summary>
        byte[] Decrypt(byte[] blob)
        {
            int head = Magic.Length + 16;
            if (blob.Length < head + 16 + 32 || blob[0] != Magic[0] || blob[1] != Magic[1] || blob[2] != Magic[2])
                return null;
            using (var mac = new HMACSHA256(macKey))
            {
                var tag = mac.ComputeHash(blob, 0, blob.Length - 32);
                int diff = 0;
                for (int i = 0; i < 32; i++)
                    diff |= tag[i] ^ blob[blob.Length - 32 + i];
                if (diff != 0)
                    return null;
            }
            using (var aes = new RijndaelManaged { KeySize = 256, BlockSize = 128, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 })
            {
                aes.Key = encKey;
                var iv = new byte[16];
                Buffer.BlockCopy(blob, Magic.Length, iv, 0, 16);
                aes.IV = iv;
                using (var dec = aes.CreateDecryptor())
                    return dec.TransformFinalBlock(blob, head, blob.Length - head - 32);
            }
        }

        static string NewId()
        {
            var b = new byte[8];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(b);
            return DateTime.UtcNow.ToString("yyyyMMddHHmmss") + "-" + Hashing.ToHex(b);
        }

        static bool ValidId(string id)
        {
            return !string.IsNullOrEmpty(id) && id.Length <= 64 && id.All(c => char.IsLetterOrDigit(c) || c == '-');
        }

        static void RemoveForced(string path)
        {
            var attr = File.GetAttributes(path);
            if ((attr & FileAttributes.ReadOnly) != 0)
                File.SetAttributes(path, attr & ~FileAttributes.ReadOnly);
            File.Delete(path);
        }

        static bool TryDelete(string path)
        {
            try
            {
                if (!File.Exists(path))
                    return false;
                File.Delete(path);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        static QuarantineException AccessDenied()
        {
            return new QuarantineException("accesso negato: il file è protetto (prova ad avviare Vigil come amministratore)");
        }

        static QuarantineException Translate(IOException e)
        {
            int code = System.Runtime.InteropServices.Marshal.GetHRForException(e) & 0xFFFF;
            if (code == 32 || code == 33)
                return new QuarantineException("il file è in uso: chiudi il programma che lo usa e riprova");
            if (e is FileNotFoundException)
                return new QuarantineException("file non trovato");
            return new QuarantineException(e.Message);
        }
    }
}
