using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Modding;

namespace HKMP.Whitelist.Core
{
    internal sealed class LoadedModInfo
    {
        public IMod Mod { get; set; }

        public Assembly Assembly { get; set; }

        public string ModId { get; set; }

        public string Version { get; set; }
    }

    internal static class LoadedModDiscovery
    {
        public static IReadOnlyList<LoadedModInfo> GetLoadedMods(
            out List<string> failures)
        {
            failures =
                new List<string>();

            List<LoadedModInfo> result =
                new List<LoadedModInfo>();

            IEnumerable<IMod> mods;

            try
            {
                mods =
                    ModHooks.GetAllMods(
                        true,
                        false);
            }
            catch (Exception ex)
            {
                failures.Add(
                    "MOD_ENUMERATION_FAILED:" +
                    ex.GetType().Name);

                return result;
            }

            if (mods == null)
            {
                failures.Add(
                    "MOD_ENUMERATION_RETURNED_NULL");

                return result;
            }

            foreach (IMod mod in mods)
            {
                if (mod == null)
                {
                    continue;
                }

                Assembly assembly =
                    null;

                try
                {
                    assembly =
                        mod.GetType().Assembly;
                }
                catch (Exception ex)
                {
                    failures.Add(
                        "MOD_ASSEMBLY_UNAVAILABLE:" +
                        SafeModName(mod) +
                        ":" +
                        ex.GetType().Name);
                }

                string modId =
                    SafeModName(
                        mod);

                string version =
                    SafeModVersion(
                        mod);

                if (string.IsNullOrWhiteSpace(modId) &&
                    assembly != null)
                {
                    try
                    {
                        modId =
                            assembly.GetName().Name;
                    }
                    catch
                    {
                    }
                }

                if (string.IsNullOrWhiteSpace(version) &&
                    assembly != null)
                {
                    try
                    {
                        AssemblyName name =
                            assembly.GetName();

                        if (name != null &&
                            name.Version != null)
                        {
                            version =
                                name.Version.ToString();
                        }
                    }
                    catch
                    {
                    }
                }

                result.Add(
                    new LoadedModInfo
                    {
                        Mod = mod,
                        Assembly = assembly,
                        ModId = modId,
                        Version = version
                    });
            }

            return result
                .Where(
                    x => x != null)
                .OrderBy(
                    x => x.ModId ?? "",
                    StringComparer.OrdinalIgnoreCase)
                .ThenBy(
                    x => GetAssemblyName(x.Assembly) ?? "",
                    StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        public static LoadedModInfo FindByAssembly(
            IEnumerable<LoadedModInfo> mods,
            Assembly assembly)
        {
            if (mods == null ||
                assembly == null)
            {
                return null;
            }

            foreach (LoadedModInfo item in mods)
            {
                if (item == null ||
                    item.Assembly == null)
                {
                    continue;
                }

                if (ReferenceEquals(
                    item.Assembly,
                    assembly))
                {
                    return item;
                }
            }

            string fullName =
                GetAssemblyFullName(
                    assembly);

            if (string.IsNullOrWhiteSpace(fullName))
            {
                return null;
            }

            foreach (LoadedModInfo item in mods)
            {
                if (item == null ||
                    item.Assembly == null)
                {
                    continue;
                }

                if (string.Equals(
                    fullName,
                    GetAssemblyFullName(item.Assembly),
                    StringComparison.Ordinal))
                {
                    return item;
                }
            }

            return null;
        }

        private static string SafeModName(
            IMod mod)
        {
            try
            {
                return mod == null
                    ? null
                    : mod.GetName();
            }
            catch
            {
                return null;
            }
        }

        private static string SafeModVersion(
            IMod mod)
        {
            try
            {
                return mod == null
                    ? null
                    : mod.GetVersion();
            }
            catch
            {
                return null;
            }
        }

        private static string GetAssemblyName(
            Assembly assembly)
        {
            try
            {
                return assembly == null
                    ? null
                    : assembly.GetName().Name;
            }
            catch
            {
                return null;
            }
        }

        private static string GetAssemblyFullName(
            Assembly assembly)
        {
            try
            {
                return assembly == null
                    ? null
                    : assembly.FullName;
            }
            catch
            {
                return null;
            }
        }
    }
}
