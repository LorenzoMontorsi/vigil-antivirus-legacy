using System;
using NUnit.Framework;
using Vigil.Engine;

namespace Vigil.Engine.Tests
{
    public class FeedsTests
    {
        [Test]
        public void ParsesMalwareBazaarRows()
        {
            var csv = "################\n# MalwareBazaar recent\n" +
                "\"2026-11-02 10:00:00\", \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\", \"m\", \"s\", \"r\", \"x.exe\", \"exe\", \"application/x-dosexec\", \"AgentTesla\", \"n/a\"\n" +
                "\"2026-11-02 10:00:01\", \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\", \"m\", \"s\", \"r\", \"a, b.doc\", \"doc\", \"x\", \"n/a\", \"n/a\"\n" +
                "\"bad\", \"nothex\"\n";
            var rows = Feeds.ParseCsv(csv);
            Assert.AreEqual(2, rows.Count);
            Assert.AreEqual(new string('a', 64), rows[0].Key);
            Assert.AreEqual("MalwareBazaar.AgentTesla", rows[0].Value);
            Assert.AreEqual("MalwareBazaar.Generic", rows[1].Value);
        }

        [TestCase("abc-DEF_123", true)]
        [TestCase("", false)]
        [TestCase("a/b", false)]
        [TestCase("chiave con spazi", false)]
        public void ValidatesKeys(string key, bool ok)
        {
            Assert.AreEqual(ok, Feeds.IsValidKey(key));
        }
    }

    /// <summary>Prove con server veri: servono Internet e badssl.com.</summary>
    [Category("Network")]
    public class HttpsTests
    {
        [TestCase("https://mb-api.abuse.ch/")]
        [TestCase("https://github.com/")]
        [TestCase("https://ecc256.badssl.com/")]
        [TestCase("https://tls-v1-2.badssl.com:1012/")]
        public void ConnectsWithValidCertificate(string url)
        {
            try
            {
                var r = Https.Get(url, 8 * 1024 * 1024);
                Assert.That(r.Body.Length, Is.GreaterThan(0));
            }
            catch (Https.HttpException e)
            {
                // Una risposta HTTP qualsiasi vuol dire che TLS e certificato sono andati bene.
                Assert.That(e.Status, Is.GreaterThanOrEqualTo(400));
            }
        }

        [TestCase("https://expired.badssl.com/")]
        [TestCase("https://wrong.host.badssl.com/")]
        [TestCase("https://self-signed.badssl.com/")]
        [TestCase("https://untrusted-root.badssl.com/")]
        public void RejectsBadCertificate(string url)
        {
            var e = Assert.Catch(() => Https.Get(url, 1024 * 1024));
            StringAssert.Contains("certificat", e.ToString());
        }
    }
}
