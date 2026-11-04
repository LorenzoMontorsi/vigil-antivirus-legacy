using NUnit.Framework;
using Vigil.Engine;

namespace Vigil.Engine.Tests
{
    public class ThreatInfoTests
    {
        [TestCase("Win.Trojan.Agent-1234567-0", "Trojan:Win/Agent", "Trojan · Windows · famiglia Agent")]
        [TestCase("Doc.Downloader.Emotet-9876543-0", "Downloader:Doc/Emotet", "Downloader (scarica altro malware) · documento Word · famiglia Emotet")]
        [TestCase("Win.Ransomware.WannaCry-6313787-0", "Ransomware:Win/WannaCry", null)]
        [TestCase("PUA.Win.Packer.Upx-1", "PUA:Win/Upx", null)]
        [TestCase("Html.Phishing.Bank-1", "Phishing:Html/Bank", null)]
        [TestCase("Win.Test.EICAR_HDB-1", "Test:Win/EICAR_HDB", null)]
        [TestCase("EICAR_Test_File", "Test:Multi/EICAR", "File di prova (innocuo) · famiglia EICAR")]
        [TestCase("Heuristics.Broken.Executable", "Heuristics:Multi/Executable", null)]
        [TestCase("Trojan.Win32.Generic", "Trojan:Win/Generic", "Trojan · Windows")]
        [TestCase("AgentTesla", "Malware:Multi/AgentTesla", null)]
        [TestCase("Vigil.Test.FintoScript", "Test:Multi/FintoScript", null)]
        public void ParsesSignatureNames(string name, string display, string description)
        {
            var t = ThreatInfo.Parse(name);
            Assert.AreEqual(display, t.Display);
            if (description != null)
                Assert.AreEqual(description, t.Description);
        }
    }
}
