using System.Diagnostics;
using System.Reflection;

namespace HKMP.Whitelist.Security
{
    internal static class AntiTamperGuard
    {
        public static bool IsDebuggerDetected()
        {
            try
            {
                if (Debugger.IsAttached)
                {
                    return true;
                }

                if (Debugger.IsLogging())
                {
                    return true;
                }

                return false;
            }
            catch
            {
                return true;
            }
        }

        public static string GetExecutingAssemblyPath()
        {
            try
            {
                Assembly assembly =
                    Assembly.GetExecutingAssembly();

                return assembly == null
                    ? ""
                    : assembly.Location ?? "";
            }
            catch
            {
                return "";
            }
        }

        public static string ComputeSelfHash()
        {
            string path =
                GetExecutingAssemblyPath();

            if (string.IsNullOrEmpty(path))
            {
                return null;
            }

            try
            {
                return HashUtil.Sha256File(
                    path);
            }
            catch
            {
                return null;
            }
        }
    }
}