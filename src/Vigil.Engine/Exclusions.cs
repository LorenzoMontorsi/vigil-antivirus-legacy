using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;

namespace Vigil.Engine
{
    /// <summary>
    /// Elementi da non scansionare.
    /// <c>Paths</c>: cartelle o file (una cartella esclude tutto il suo contenuto).
    /// <c>Extensions</c>: estensioni, con o senza punto, senza distinzione di maiuscole.
    /// </summary>
    [DataContract]
    public sealed class Exclusions
    {
        [DataMember(Name = "paths")]
        public List<string> Paths { get; set; }

        [DataMember(Name = "extensions")]
        public List<string> Extensions { get; set; }

        public Exclusions()
        {
            Paths = new List<string>();
            Extensions = new List<string>();
        }

        [OnDeserialized]
        void Fix(StreamingContext _)
        {
            Paths = Paths ?? new List<string>();
            Extensions = Extensions ?? new List<string>();
        }

        public bool IsExcluded(string path, bool isDir)
        {
            var p = Normalize(path);
            foreach (var raw in Paths)
            {
                var ex = Normalize(raw);
                if (ex.Length == 0)
                    continue;
                if (p == ex || (p.Length > ex.Length && p.StartsWith(ex, StringComparison.Ordinal) && p[ex.Length] == '\\'))
                    return true;
            }
            if (isDir)
                return false;
            var ext = System.IO.Path.GetExtension(path);
            if (string.IsNullOrEmpty(ext))
                return false;
            ext = ext.TrimStart('.');
            return Extensions.Any(e => string.Equals(e.Trim().TrimStart('.'), ext, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>Windows: separatori uniformi, niente barra finale, senza distinzione di maiuscole.</summary>
        static string Normalize(string s)
        {
            return (s ?? "").Trim().Replace('/', '\\').TrimEnd('\\').ToLowerInvariant();
        }

        public Exclusions Clone()
        {
            return new Exclusions { Paths = new List<string>(Paths), Extensions = new List<string>(Extensions) };
        }
    }
}
