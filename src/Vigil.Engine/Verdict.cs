using System.Collections.Generic;

namespace Vigil.Engine
{
    public enum VerdictKind
    {
        Clean,
        Infected,
        Suspicious,
        Skipped,
        Error,
    }

    /// <summary>Motore che ha prodotto il rilevamento.</summary>
    public enum DetectionSource
    {
        None,
        Hash,
        Pattern,
        Clamav,
        Heuristics,
    }

    /// <summary>Esito dell'analisi di un file (o di dati in memoria).</summary>
    public sealed class Verdict
    {
        public VerdictKind Kind { get; private set; }

        /// <summary>Nome della minaccia (solo <see cref="VerdictKind.Infected"/>).</summary>
        public string Threat { get; private set; }

        public DetectionSource Source { get; private set; }

        /// <summary>Descrizione della firma, se presente.</summary>
        public string Description { get; private set; }

        /// <summary>Percorso dentro l'archivio, se la minaccia è in un file compresso.</summary>
        public string Location { get; private set; }

        /// <summary>Punteggio euristico (solo <see cref="VerdictKind.Suspicious"/>).</summary>
        public int Score { get; private set; }

        /// <summary>Motivi del sospetto, oppure il messaggio di errore / del salto.</summary>
        public IList<string> Reasons { get; private set; }

        public string Message
        {
            get { return Reasons.Count > 0 ? Reasons[0] : ""; }
        }

        Verdict(VerdictKind kind)
        {
            Kind = kind;
            Reasons = new string[0];
        }

        public static readonly Verdict Clean = new Verdict(VerdictKind.Clean);

        public static Verdict Infected(string threat, DetectionSource source, string description = null, string location = null)
        {
            return new Verdict(VerdictKind.Infected) { Threat = threat, Source = source, Description = description, Location = location };
        }

        public static Verdict Suspicious(int score, IList<string> reasons)
        {
            return new Verdict(VerdictKind.Suspicious) { Score = score, Reasons = reasons, Source = DetectionSource.Heuristics };
        }

        public static Verdict Skipped(string reason)
        {
            return new Verdict(VerdictKind.Skipped) { Reasons = new[] { reason } };
        }

        public static Verdict Error(string message)
        {
            return new Verdict(VerdictKind.Error) { Reasons = new[] { message } };
        }

        /// <summary>Copia con la posizione nell'archivio (per i rilevamenti dentro gli ZIP).</summary>
        internal Verdict WithLocation(string location)
        {
            return Infected(Threat, Source, Description, location);
        }

        public bool IsDetection
        {
            get { return Kind == VerdictKind.Infected || Kind == VerdictKind.Suspicious; }
        }

        public override string ToString()
        {
            switch (Kind)
            {
                case VerdictKind.Infected:
                    return "Infetto: " + Threat + (Location != null ? " (in " + Location + ")" : "");
                case VerdictKind.Suspicious:
                    return "Sospetto (" + Score + "): " + string.Join("; ", Reasons);
                case VerdictKind.Skipped:
                    return "Saltato: " + Message;
                case VerdictKind.Error:
                    return "Errore: " + Message;
                default:
                    return "Pulito";
            }
        }
    }

    public sealed class ScanResult
    {
        public string Path { get; set; }
        public long Size { get; set; }
        public string Sha256 { get; set; }
        public Verdict Verdict { get; set; }

        /// <summary>Risultato preso dalla cache: il file non è stato riletto.</summary>
        public bool Cached { get; set; }

        /// <summary>Firmatario Authenticode valido, se verificato.</summary>
        public string Signer { get; set; }

        public bool IsInfected
        {
            get { return Verdict.Kind == VerdictKind.Infected; }
        }
    }
}
