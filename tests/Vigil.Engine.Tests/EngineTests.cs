using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading;
using NUnit.Framework;
using Vigil.Engine;

namespace Vigil.Engine.Tests
{
    public class EngineTests
    {
        // Spezzata in due, come nel motore, perché il sorgente non contenga la sequenza intera.
        static readonly string EicarText = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR" + "-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        static byte[] Eicar { get { return Encoding.ASCII.GetBytes(EicarText); } }

        string dir;

        [SetUp]
        public void SetUp()
        {
            dir = Path.Combine(Path.GetTempPath(), "vigil-test-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
        }

        [TearDown]
        public void TearDown()
        {
            try { Directory.Delete(dir, true); } catch (Exception) { }
        }

        [Test]
        public void DetectsEicarInMemory()
        {
            var v = new ScanEngine().ScanBytes(Eicar, "eicar.com", new ScanOptions());
            Assert.AreEqual(VerdictKind.Infected, v.Kind);
            Assert.AreEqual("EICAR_Test_File", v.Threat);
        }

        [Test]
        public void CleanDataIsClean()
        {
            Assert.AreEqual(VerdictKind.Clean, new ScanEngine().ScanBytes(Encoding.ASCII.GetBytes("ciao mondo"), "nota.txt", new ScanOptions()).Kind);
        }

        [Test]
        public void HashSignatureMatches()
        {
            var data = Encoding.ASCII.GetBytes("finto malware di prova");
            var sha = Hashing.ToHex(Hashing.Sha256(data));
            var e = new ScanEngine();
            e.AddHashList("# commento\n" + sha + " Test.Hash.Sample\nnon-un-hash\n", "test.txt");
            Assert.AreEqual(1, e.HashSignatures);
            Assert.AreEqual(1, e.Warnings.Count);
            var v = e.ScanBytes(data, "x.bin", new ScanOptions());
            Assert.AreEqual("Test.Hash.Sample", v.Threat);
            Assert.AreEqual(DetectionSource.Hash, v.Source);
        }

        [Test]
        public void Sha256IsCorrect()
        {
            Assert.AreEqual("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", Hashing.ToHex(Hashing.Sha256(Encoding.ASCII.GetBytes("abc"))));
        }

        static byte[] MakeZip(params Tuple<string, byte[]>[] entries)
        {
            var ms = new MemoryStream();
            using (var z = new ZipArchive(ms, ZipArchiveMode.Create, true))
            {
                foreach (var e in entries)
                {
                    using (var s = z.CreateEntry(e.Item1).Open())
                        s.Write(e.Item2, 0, e.Item2.Length);
                }
            }
            return ms.ToArray();
        }

        [Test]
        public void FindsThreatInNestedZip()
        {
            var inner = MakeZip(Tuple.Create("leggimi.txt", Encoding.ASCII.GetBytes("ciao")), Tuple.Create("payload.com", Eicar));
            var outer = MakeZip(Tuple.Create("doc/info.txt", Encoding.ASCII.GetBytes("niente")), Tuple.Create("doc/allegato.zip", inner));
            var e = new ScanEngine();
            var v = e.ScanBytes(outer, "posta.zip", new ScanOptions());
            Assert.AreEqual("EICAR_Test_File", v.Threat);
            Assert.AreEqual("doc/allegato.zip › payload.com", v.Location);
            Assert.AreEqual(VerdictKind.Clean, e.ScanBytes(outer, "posta.zip", new ScanOptions { ScanArchives = false }).Kind);
        }

        [Test]
        public void ZipBombIsNotExtracted()
        {
            var zeros = new byte[5 * 1024 * 1024];
            var zip = MakeZip(Tuple.Create("zeri.bin", zeros));
            var z = ZipReader.Open(zip, 10);
            Assert.IsNotNull(z);
            Assert.IsNull(z.Extract(z.Entries[0], 1024 * 1024), "oltre il limite non si estrae");
            Assert.AreEqual(zeros.Length, z.Extract(z.Entries[0], 10 * 1024 * 1024).Length);
        }

        [Test]
        public void SuspiciousNameIsReported()
        {
            var e = new ScanEngine();
            var mz = Encoding.ASCII.GetBytes("MZ");
            Assert.AreEqual(VerdictKind.Suspicious, e.ScanBytes(mz, @"C:\Users\x\Downloads\fattura.pdf.exe", new ScanOptions()).Kind);
            Assert.AreEqual(VerdictKind.Clean, e.ScanBytes(mz, "fattura.pdf.exe", new ScanOptions { Heuristics = false }).Kind);
            Assert.IsNull(Heuristics.Analyze(new byte[0], "setup.1.2.exe"));
            Assert.IsNull(Heuristics.Analyze(new byte[0], "archivio.tar.gz"));
            Assert.IsNotNull(Heuristics.Analyze(new byte[0], "invoice\u202Efdp.exe"));
        }

        [Test]
        public void EntropyBounds()
        {
            Assert.AreEqual(0.0, Heuristics.Entropy(new byte[100], 0, 100));
            var all = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
            Assert.AreEqual(8.0, Heuristics.Entropy(all, 0, 256), 1e-9);
        }

        [Test]
        public void ParsesRealPeFile()
        {
            // Un eseguibile vero qualsiasi: notepad di sistema.
            var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
            var pe = PeFile.TryParse(File.ReadAllBytes(path));
            Assert.IsNotNull(pe);
            Assert.That(pe.Sections.Any(s => s.Name == ".text"));
            Assert.That(pe.Imports.Count, Is.GreaterThan(10));
            Assert.IsNull(PeFile.TryParse(Encoding.ASCII.GetBytes("MZ non sono un PE")));
        }

        [Test]
        public void MicrosoftSignatureIsVerified()
        {
            // notepad.exe è firmato tramite catalogo: serve anche la verifica dei cataloghi.
            var notepad = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
            StringAssert.StartsWith("Microsoft ", Trust.Signer(notepad));
            var fake = Path.Combine(dir, "falso.exe");
            File.WriteAllBytes(fake, File.ReadAllBytes(notepad).Take(4096).ToArray());
            Assert.IsNull(Trust.Signer(fake));
        }

        [Test]
        public void ScansTreeRespectingExclusions()
        {
            Directory.CreateDirectory(Path.Combine(dir, @"sub\skipme"));
            File.WriteAllText(Path.Combine(dir, "a.txt"), "pulito");
            File.WriteAllBytes(Path.Combine(dir, @"sub\b.com"), Eicar);
            File.WriteAllBytes(Path.Combine(dir, @"sub\skipme\c.com"), Eicar);
            File.WriteAllBytes(Path.Combine(dir, @"sub\d.iso"), Eicar);
            var opts = new ScanOptions();
            opts.Exclusions.Paths.Add(Path.Combine(dir, "sub", "skipme"));
            opts.Exclusions.Extensions.Add("iso");
            var threats = new System.Collections.Generic.List<string>();
            var summary = Scanner.ScanPaths(new ScanEngine(), new[] { dir }, opts, CancellationToken.None, (r, s) =>
            {
                if (r.IsInfected) threats.Add(r.Path);
            });
            Assert.AreEqual(2, summary.Scanned);
            Assert.AreEqual(1, summary.Infected);
            CollectionAssert.AreEqual(new[] { Path.Combine(dir, @"sub\b.com") }, threats);
        }

        [Test]
        public void CancelledScanTerminates()
        {
            for (int i = 0; i < 6000; i++)
                File.WriteAllText(Path.Combine(dir, i + ".txt"), "x");
            var cts = new CancellationTokenSource();
            var summary = Scanner.ScanPaths(new ScanEngine(), new[] { dir }, new ScanOptions { Threads = 1 }, cts.Token, (r, s) =>
            {
                if (s.Scanned == 10) cts.Cancel();
            });
            Assert.IsTrue(summary.Cancelled);
            Assert.Less(summary.Scanned, 6000);
        }

        [Test]
        public void ExclusionsMatchFoldersAndExtensions()
        {
            var ex = new Exclusions();
            ex.Paths.Add(@"C:\Dev\Build\");
            ex.Extensions.Add(".ISO");
            Assert.IsTrue(ex.IsExcluded(@"c:\dev\build", true));
            Assert.IsTrue(ex.IsExcluded(@"C:\Dev\Build\out\a.exe", false));
            Assert.IsFalse(ex.IsExcluded(@"C:\Dev\BuildTools\a.exe", false));
            Assert.IsTrue(ex.IsExcluded(@"D:\img\win.iso", false));
            Assert.IsFalse(ex.IsExcluded(@"D:\folder.iso", true));
        }

        [Test]
        public void CacheRoundtripAndGeneration()
        {
            var f = Path.Combine(dir, "a.txt");
            File.WriteAllText(f, "ciao");
            var cacheFile = Path.Combine(dir, "cache.bin");
            var c = new ScanCache(cacheFile, "g1");
            Assert.IsFalse(c.IsClean(new FileInfo(f)));
            c.MarkClean(new FileInfo(f));
            c.Save();
            Assert.IsTrue(new ScanCache(cacheFile, "g1").IsClean(new FileInfo(f)));
            Assert.AreEqual(0, new ScanCache(cacheFile, "g2").Count, "firme diverse: si riparte da zero");
            File.WriteAllText(f, "ciao mondo");
            Assert.IsFalse(c.IsClean(new FileInfo(f)));
        }

        [Test]
        public void QuarantineRoundtrip()
        {
            var q = new Quarantine(Path.Combine(dir, "vault"));
            var f = Path.Combine(dir, "virus.com");
            File.WriteAllBytes(f, Eicar);
            File.SetAttributes(f, FileAttributes.ReadOnly);
            var item = q.Add(f, "EICAR_Test_File", "pattern");
            Assert.IsFalse(File.Exists(f));
            Assert.AreEqual(1, q.List().Count);
            // Il deposito non contiene il file in chiaro.
            var blob = File.ReadAllBytes(Path.Combine(q.Dir, item.Id + ".vq"));
            Assert.IsFalse(Encoding.ASCII.GetString(blob).Contains("EICAR"));
            Assert.AreEqual(f, q.Restore(item.Id));
            CollectionAssert.AreEqual(Eicar, File.ReadAllBytes(f));
            Assert.AreEqual(0, q.List().Count);
        }

        [Test]
        public void QuarantineRejectsTamperingAndNeverOverwrites()
        {
            var q = new Quarantine(Path.Combine(dir, "vault"));
            var f = Path.Combine(dir, "x.bin");
            File.WriteAllText(f, "contenuto");
            var item = q.Add(f, "T", "hash");
            File.WriteAllText(f, "nuovo file con lo stesso nome");
            Assert.Throws<QuarantineException>(() => q.Restore(item.Id));
            File.Delete(f);
            var blobPath = Path.Combine(q.Dir, item.Id + ".vq");
            var blob = File.ReadAllBytes(blobPath);
            blob[blob.Length / 2] ^= 1;
            File.WriteAllBytes(blobPath, blob);
            Assert.Throws<QuarantineException>(() => q.Restore(item.Id));
            Assert.Throws<QuarantineException>(() => q.Get(@"..\..\evil"));
        }

        [Test]
        public void LockedFileIsRolledBack()
        {
            var q = new Quarantine(Path.Combine(dir, "vault"));
            var f = Path.Combine(dir, "aperto.bin");
            File.WriteAllText(f, "in uso");
            using (new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.Read))
                Assert.Throws<QuarantineException>(() => q.Add(f, "T", "hash"));
            Assert.IsTrue(File.Exists(f));
            Assert.AreEqual(0, q.List().Count);
        }

        [Test]
        public void ClamdRepliesAreParsed()
        {
            Assert.IsNull(ClamdClient.ParseReply("stream: OK"));
            Assert.AreEqual("Win.Test.EICAR_HDB-1", ClamdClient.ParseReply("stream: Win.Test.EICAR_HDB-1 FOUND"));
            Assert.Throws<IOException>(() => ClamdClient.ParseReply("INSTREAM size limit exceeded. ERROR"));
        }
    }
}
