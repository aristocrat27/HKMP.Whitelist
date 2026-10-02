using HKMP.Whitelist.Security;
using HKMP.Whitelist.Shared;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace HKMP.Whitelist.Client
{
    internal sealed class HarmonyPatchEvidence
    {
        public string Owner { get; set; }

        public string OwnerAssemblyFullName { get; set; }

        public string OwnerAssemblyName { get; set; }

        public string OwnerAssemblyVersion { get; set; }

        public string OwnerAssemblyLocation { get; set; }

        public string OwnerAssemblySha256 { get; set; }

        public string Target { get; set; }

        public string TargetDeclaringType { get; set; }

        public string TargetMethod { get; set; }

        public string PatchKind { get; set; }

        public int Priority { get; set; }

        public string[] Before { get; set; }

        public string[] After { get; set; }

        public bool OwnerMatchesHostBaseline { get; set; }

        public bool OwnerHasPhysicalLocation { get; set; }

        public string Status { get; set; }
    }

    internal sealed class HarmonyProviderResult
    {
        public bool Complete { get; set; } = true;

        public bool HarmonyAvailable { get; set; }

        public List<HarmonyPatchEvidence> Patches { get; } =
            new List<HarmonyPatchEvidence>();

        public List<HarmonyPatchEvidence> UnknownOwnerPatches { get; } =
            new List<HarmonyPatchEvidence>();

        public List<HarmonyPatchEvidence> UnresolvedTargetPatches { get; } =
            new List<HarmonyPatchEvidence>();

        public List<string> IntegrityFailures { get; } =
            new List<string>();

        public List<string> Errors { get; } =
            new List<string>();
    }

    internal static class HarmonyProvider
    {
        public static HarmonyProviderResult Scan(
            HostBaseline baseline)
        {
            HarmonyProviderResult result =
                new HarmonyProviderResult();

            Type harmonyType =
                FindHarmonyType();

            if (harmonyType == null)
            {
                result.Complete = false;
                result.HarmonyAvailable = false;

                result.Errors.Add(
                    "HarmonyLib.Harmony was not found in the current AppDomain.");

                return result;
            }

            result.HarmonyAvailable = true;

            MethodInfo getAllPatchedMethods =
                harmonyType.GetMethod(
                    "GetAllPatchedMethods",
                    BindingFlags.Public |
                    BindingFlags.Static);

            MethodInfo getPatchInfo =
                harmonyType.GetMethod(
                    "GetPatchInfo",
                    BindingFlags.Public |
                    BindingFlags.Static);

            if (getAllPatchedMethods == null)
            {
                result.Complete = false;

                result.Errors.Add(
                    "Harmony.GetAllPatchedMethods() is unavailable.");

                return result;
            }

            if (getPatchInfo == null)
            {
                result.Complete = false;

                result.Errors.Add(
                    "Harmony.GetPatchInfo() is unavailable.");

                return result;
            }

            IEnumerable patchedMethods;

            try
            {
                patchedMethods =
                    getAllPatchedMethods.Invoke(
                        null,
                        null) as IEnumerable;
            }
            catch (Exception ex)
            {
                result.Complete = false;

                result.Errors.Add(
                    "Harmony patch enumeration failed: " +
                    GetExceptionName(ex));

                return result;
            }

            if (patchedMethods == null)
            {
                return result;
            }

            foreach (object methodObject in patchedMethods)
            {
                MethodBase targetMethod =
                    methodObject as MethodBase;

                if (targetMethod == null)
                {
                    result.Complete = false;

                    result.Errors.Add(
                        "Harmony returned an invalid patched-method entry.");

                    continue;
                }

                object patchInfo;

                try
                {
                    patchInfo =
                        getPatchInfo.Invoke(
                            null,
                            new object[]
                            {
                                targetMethod
                            });
                }
                catch (Exception ex)
                {
                    result.Complete = false;

                    result.Errors.Add(
                        "Harmony.GetPatchInfo failed for " +
                        SafeMethodName(targetMethod) +
                        ": " +
                        GetExceptionName(ex));

                    continue;
                }

                if (patchInfo == null)
                {
                    continue;
                }

                ScanPatchCollection(
                    baseline,
                    targetMethod,
                    patchInfo,
                    "Prefixes",
                    "Prefix",
                    result);

                ScanPatchCollection(
                    baseline,
                    targetMethod,
                    patchInfo,
                    "Postfixes",
                    "Postfix",
                    result);

                ScanPatchCollection(
                    baseline,
                    targetMethod,
                    patchInfo,
                    "Transpilers",
                    "Transpiler",
                    result);

                ScanPatchCollection(
                    baseline,
                    targetMethod,
                    patchInfo,
                    "Finalizers",
                    "Finalizer",
                    result);
            }

            return result;
        }

        private static void ScanPatchCollection(
            HostBaseline baseline,
            MethodBase targetMethod,
            object patchInfo,
            string collectionName,
            string patchKind,
            HarmonyProviderResult result)
        {
            object collection =
                GetPropertyOrField(
                    patchInfo,
                    collectionName);

            if (collection == null)
            {
                return;
            }

            IEnumerable enumerable =
                collection as IEnumerable;

            if (enumerable == null ||
                collection is string)
            {
                return;
            }

            foreach (object patch in enumerable)
            {
                if (patch == null)
                {
                    continue;
                }

                HarmonyPatchEvidence evidence =
                    BuildPatchEvidence(
                        baseline,
                        targetMethod,
                        patch,
                        patchKind);

                result.Patches.Add(
                    evidence);

                if (!evidence.OwnerMatchesHostBaseline)
                {
                    result.UnknownOwnerPatches.Add(
                        evidence);
                }

                if (string.IsNullOrEmpty(
                        evidence.Target))
                {
                    result.UnresolvedTargetPatches.Add(
                        evidence);
                }
            }
        }

        private static HarmonyPatchEvidence BuildPatchEvidence(
            HostBaseline baseline,
            MethodBase targetMethod,
            object patch,
            string patchKind)
        {
            MethodBase ownerMethod =
                GetPatchMethod(
                    patch);

            Assembly ownerAssembly =
                SafeGetAssembly(
                    ownerMethod);

            string ownerLocation =
                SafeAssemblyLocation(
                    ownerAssembly);

            string ownerHash =
                ComputeOwnerHash(
                    ownerLocation);

            string ownerFullName =
                SafeAssemblyFullName(
                    ownerAssembly);

            string ownerAssemblyName =
                SafeAssemblyName(
                    ownerAssembly);

            string ownerAssemblyVersion =
                SafeAssemblyVersion(
                    ownerAssembly);

            string ownerId =
                GetString(
                    patch,
                    "owner");

            if (string.IsNullOrEmpty(ownerId) &&
                ownerMethod != null)
            {
                ownerId =
                    ownerAssemblyName;
            }

            string target =
                SafeTargetName(
                    targetMethod);

            bool hasLocation =
                !string.IsNullOrEmpty(
                    ownerLocation) &&
                File.Exists(
                    ownerLocation);

            bool ownerMatches =
                MatchesHostBaseline(
                    baseline,
                    ownerAssembly,
                    ownerLocation,
                    ownerHash);

            return new HarmonyPatchEvidence
            {
                Owner =
                    string.IsNullOrEmpty(ownerId)
                        ? "<unknown-owner>"
                        : ownerId,

                OwnerAssemblyFullName =
                    ownerFullName,

                OwnerAssemblyName =
                    ownerAssemblyName,

                OwnerAssemblyVersion =
                    ownerAssemblyVersion,

                OwnerAssemblyLocation =
                    ownerLocation,

                OwnerAssemblySha256 =
                    ownerHash,

                Target =
                    target,

                TargetDeclaringType =
                    SafeDeclaringTypeName(
                        targetMethod),

                TargetMethod =
                    SafeMethodOnlyName(
                        targetMethod),

                PatchKind =
                    patchKind,

                Priority =
                    GetInt32(
                        patch,
                        "priority"),

                Before =
                    GetStringArray(
                        patch,
                        "before"),

                After =
                    GetStringArray(
                        patch,
                        "after"),

                OwnerMatchesHostBaseline =
                    ownerMatches,

                OwnerHasPhysicalLocation =
                    hasLocation,

                Status =
                    BuildStatus(
                        ownerMatches,
                        hasLocation,
                        target)
            };
        }

        private static string BuildStatus(
            bool ownerMatchesBaseline,
            bool hasLocation,
            string target)
        {
            if (!hasLocation)
            {
                return "OWNER_LOCATION_UNAVAILABLE";
            }

            if (!ownerMatchesBaseline)
            {
                return "UNKNOWN_OWNER";
            }

            if (string.IsNullOrEmpty(target))
            {
                return "TARGET_UNRESOLVED";
            }

            return "OBSERVED";
        }

        private static bool MatchesHostBaseline(
            HostBaseline baseline,
            Assembly assembly,
            string location,
            string hash)
        {
            if (baseline == null ||
                baseline.Artifacts == null ||
                assembly == null ||
                string.IsNullOrEmpty(location) ||
                string.IsNullOrEmpty(hash))
            {
                return false;
            }

            string fullName =
                SafeAssemblyFullName(
                    assembly);

            string assemblyName =
                SafeAssemblyName(
                    assembly);

            string assemblyVersion =
                SafeAssemblyVersion(
                    assembly);

            string relativePath =
                NormalizeRelativePath(
                    location);

            string fileName =
                SafeFileName(
                    location);

            long fileSize =
                GetFileSize(
                    location);

            foreach (BaselineArtifact artifact in baseline.Artifacts)
            {
                if (artifact == null)
                {
                    continue;
                }

                if (!artifact.IsLoaded)
                {
                    continue;
                }

                if (!string.Equals(
                        artifact.FileName,
                        fileName,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!PathsEqual(
                        artifact.RelativePath,
                        relativePath))
                {
                    continue;
                }

                if (artifact.FileSize != fileSize)
                {
                    continue;
                }

                if (!string.Equals(
                        artifact.Sha256,
                        hash,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!string.Equals(
                        artifact.AssemblyFullName,
                        fullName,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!string.Equals(
                        artifact.AssemblyName,
                        assemblyName,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!string.Equals(
                        artifact.AssemblyVersion,
                        assemblyVersion,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                return true;
            }

            return false;
        }

        private static Type FindHarmonyType()
        {
            Type harmonyType =
                Type.GetType(
                    "HarmonyLib.Harmony, 0Harmony",
                    false);

            if (harmonyType != null)
            {
                return harmonyType;
            }

            harmonyType =
                Type.GetType(
                    "HarmonyLib.Harmony",
                    false);

            if (harmonyType != null)
            {
                return harmonyType;
            }

            Assembly[] assemblies;

            try
            {
                assemblies =
                    AppDomain.CurrentDomain.GetAssemblies();
            }
            catch
            {
                return null;
            }

            foreach (Assembly assembly in assemblies)
            {
                if (assembly == null)
                {
                    continue;
                }

                try
                {
                    harmonyType =
                        assembly.GetType(
                            "HarmonyLib.Harmony",
                            false);
                }
                catch
                {
                    harmonyType = null;
                }

                if (harmonyType != null)
                {
                    return harmonyType;
                }
            }

            return null;
        }

        private static MethodBase GetPatchMethod(
            object patch)
        {
            object value =
                GetPropertyOrField(
                    patch,
                    "PatchMethod");

            MethodBase method =
                value as MethodBase;

            if (method != null)
            {
                return method;
            }

            value =
                GetPropertyOrField(
                    patch,
                    "method");

            method =
                value as MethodBase;

            if (method != null)
            {
                return method;
            }

            return null;
        }

        private static object GetPropertyOrField(
            object instance,
            string name)
        {
            if (instance == null ||
                string.IsNullOrEmpty(name))
            {
                return null;
            }

            Type type =
                instance.GetType();

            try
            {
                PropertyInfo property =
                    type.GetProperty(
                        name,
                        BindingFlags.Public |
                        BindingFlags.NonPublic |
                        BindingFlags.Instance |
                        BindingFlags.Static);

                if (property != null)
                {
                    return property.GetValue(
                        instance,
                        null);
                }
            }
            catch
            {
            }

            try
            {
                FieldInfo field =
                    type.GetField(
                        name,
                        BindingFlags.Public |
                        BindingFlags.NonPublic |
                        BindingFlags.Instance |
                        BindingFlags.Static);

                if (field != null)
                {
                    return field.GetValue(
                        instance);
                }
            }
            catch
            {
            }

            return null;
        }

        private static string GetString(
            object instance,
            string name)
        {
            object value =
                GetPropertyOrField(
                    instance,
                    name);

            return value == null
                ? ""
                : value.ToString();
        }

        private static int GetInt32(
            object instance,
            string name)
        {
            object value =
                GetPropertyOrField(
                    instance,
                    name);

            if (value == null)
            {
                return 0;
            }

            try
            {
                return Convert.ToInt32(
                    value);
            }
            catch
            {
                return 0;
            }
        }

        private static string[] GetStringArray(
            object instance,
            string name)
        {
            object value =
                GetPropertyOrField(
                    instance,
                    name);

            if (value == null)
            {
                return new string[0];
            }

            string[] direct =
                value as string[];

            if (direct != null)
            {
                return direct;
            }

            IEnumerable enumerable =
                value as IEnumerable;

            if (enumerable == null ||
                value is string)
            {
                return new string[0];
            }

            List<string> result =
                new List<string>();

            foreach (object item in enumerable)
            {
                if (item == null)
                {
                    continue;
                }

                string text =
                    item.ToString();

                if (!string.IsNullOrEmpty(text))
                {
                    result.Add(
                        text);
                }
            }

            return result.ToArray();
        }

        private static Assembly SafeGetAssembly(
            MethodBase method)
        {
            if (method == null)
            {
                return null;
            }

            try
            {
                if (method.DeclaringType == null)
                {
                    return null;
                }

                return method.DeclaringType.Assembly;
            }
            catch
            {
                return null;
            }
        }

        private static string SafeAssemblyLocation(
            Assembly assembly)
        {
            if (assembly == null)
            {
                return "";
            }

            try
            {
                return assembly.Location ?? "";
            }
            catch
            {
                return "";
            }
        }

        private static string SafeAssemblyFullName(
            Assembly assembly)
        {
            if (assembly == null)
            {
                return "<unknown>";
            }

            try
            {
                return assembly.FullName ?? "<unknown>";
            }
            catch
            {
                return "<unknown>";
            }
        }

        private static string SafeAssemblyName(
            Assembly assembly)
        {
            if (assembly == null)
            {
                return "";
            }

            try
            {
                AssemblyName name =
                    assembly.GetName();

                return name == null
                    ? ""
                    : name.Name ?? "";
            }
            catch
            {
                return "";
            }
        }

        private static string SafeAssemblyVersion(
            Assembly assembly)
        {
            if (assembly == null)
            {
                return "";
            }

            try
            {
                AssemblyName name =
                    assembly.GetName();

                if (name == null ||
                    name.Version == null)
                {
                    return "";
                }

                return name.Version.ToString();
            }
            catch
            {
                return "";
            }
        }

        private static string SafeMethodName(
            MethodBase method)
        {
            if (method == null)
            {
                return "<unknown-method>";
            }

            try
            {
                string declaringType =
                    method.DeclaringType == null
                        ? ""
                        : method.DeclaringType.FullName;

                if (string.IsNullOrEmpty(
                        declaringType))
                {
                    return method.Name ?? "<unknown-method>";
                }

                return declaringType +
                       "." +
                       (method.Name ?? "<unknown-method>");
            }
            catch
            {
                return "<unknown-method>";
            }
        }

        private static string SafeDeclaringTypeName(
            MethodBase method)
        {
            if (method == null ||
                method.DeclaringType == null)
            {
                return "";
            }

            try
            {
                return method.DeclaringType.FullName ?? "";
            }
            catch
            {
                return "";
            }
        }

        private static string SafeMethodOnlyName(
            MethodBase method)
        {
            if (method == null)
            {
                return "";
            }

            try
            {
                return method.Name ?? "";
            }
            catch
            {
                return "";
            }
        }

        private static string SafeTargetName(
            MethodBase method)
        {
            if (method == null)
            {
                return "";
            }

            try
            {
                string declaringType =
                    method.DeclaringType == null
                        ? ""
                        : method.DeclaringType.FullName;

                if (string.IsNullOrEmpty(
                        declaringType))
                {
                    return method.Name ?? "";
                }

                return declaringType +
                       "." +
                       (method.Name ?? "");
            }
            catch
            {
                return "";
            }
        }

        private static string ComputeOwnerHash(
            string location)
        {
            if (string.IsNullOrEmpty(location) ||
                !File.Exists(location))
            {
                return "";
            }

            try
            {
                return HashUtil.Sha256File(
                    location);
            }
            catch
            {
                return "";
            }
        }

        private static long GetFileSize(
            string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return 0;
            }

            try
            {
                return new FileInfo(path).Length;
            }
            catch
            {
                return 0;
            }
        }

        private static string SafeFileName(
            string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return "";
            }

            try
            {
                return Path.GetFileName(
                    path) ?? "";
            }
            catch
            {
                return "";
            }
        }

        private static string NormalizeRelativePath(
            string fullPath)
        {
            if (string.IsNullOrEmpty(fullPath))
            {
                return "";
            }

            try
            {
                string root =
                    AppDomain.CurrentDomain.BaseDirectory;

                string full =
                    Path.GetFullPath(
                        fullPath);

                string basePath =
                    Path.GetFullPath(
                        root)
                    .TrimEnd(
                        Path.DirectorySeparatorChar,
                        Path.AltDirectorySeparatorChar);

                if (full.StartsWith(
                        basePath +
                        Path.DirectorySeparatorChar,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return full
                        .Substring(
                            basePath.Length + 1)
                        .Replace(
                            '\\',
                            '/');
                }

                if (full.StartsWith(
                        basePath +
                        Path.AltDirectorySeparatorChar,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return full
                        .Substring(
                            basePath.Length + 1)
                        .Replace(
                            '\\',
                            '/');
                }

                return NormalizePath(
                    full);
            }
            catch
            {
                return NormalizePath(
                    fullPath);
            }
        }

        private static string NormalizePath(
            string path)
        {
            return (path ?? "")
                .Replace(
                    '\\',
                    '/')
                .TrimStart('/');
        }

        private static bool PathsEqual(
            string first,
            string second)
        {
            return string.Equals(
                NormalizePath(first),
                NormalizePath(second),
                StringComparison.OrdinalIgnoreCase);
        }

        private static string GetExceptionName(
            Exception ex)
        {
            if (ex == null)
            {
                return "UnknownException";
            }

            if (ex.InnerException != null)
            {
                return ex.InnerException.GetType().Name;
            }

            return ex.GetType().Name;
        }
    }
}