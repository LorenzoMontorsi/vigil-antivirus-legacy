using System;
using System.IO;
using System.Runtime.Serialization.Json;
using System.Text;

namespace Vigil.Engine
{
    /// <summary>JSON con DataContractJsonSerializer (presente in .NET 4.0, niente dipendenze).</summary>
    public static class Json
    {
        public static string Serialize<T>(T value)
        {
            var ser = new DataContractJsonSerializer(typeof(T));
            using (var ms = new MemoryStream())
            {
                ser.WriteObject(ms, value);
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }

        public static T Deserialize<T>(string text) where T : class
        {
            var ser = new DataContractJsonSerializer(typeof(T));
            using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(text)))
                return (T)ser.ReadObject(ms);
        }

        /// <summary>Legge un file JSON; null se manca o è rovinato.</summary>
        public static T Load<T>(string path) where T : class
        {
            try
            {
                return File.Exists(path) ? Deserialize<T>(File.ReadAllText(path, Encoding.UTF8)) : null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>Scrittura atomica: file temporaneo e poi sostituzione.</summary>
        public static void Save<T>(string path, T value)
        {
            FileUtil.WriteAtomic(path, Encoding.UTF8.GetBytes(Serialize(value)));
        }
    }

    public static class FileUtil
    {
        public static void WriteAtomic(string path, byte[] data)
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
            var tmp = path + ".tmp";
            File.WriteAllBytes(tmp, data);
            if (File.Exists(path))
                File.Replace(tmp, path, null, true);
            else
                File.Move(tmp, path);
        }

        public static long NowUnix()
        {
            return (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
        }

        public static DateTime FromUnix(long t)
        {
            return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(t).ToLocalTime();
        }
    }
}
