using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using UnityEngine;
using HKMP.Whitelist.Core;

namespace HKMP.Whitelist.Core
{
    internal static class GamePathResolver
    {
        public static bool TryResolve(
            string configuredRoot,
            out string gameRoot,
            out string failureReason)
        {
            HostReadinessResult readiness =
                GetHostReadiness(
                    configuredRoot);

            gameRoot =
                readiness.GameRoot;

            failureReason =
                readiness.IsReady
                    ? null
                    : BuildFailureReason(
                        readiness);

            return readiness.IsReady;
        }

        public static HostReadinessResult GetHostReadiness(
            string configuredRoot)
        {
            HostReadinessResult result =
                new HostReadinessResult
                {
                    ExecutionMode =
                        HostExecutionMode.Unsupported
                };

            bool unityAvailable = false;
            bool isPlaying = false;
            string dataPath = null;

            try
            {
                isPlaying =
                    Application.isPlaying;

                dataPath =
                    Application.dataPath;

                unityAvailable =
                    !string.IsNullOrWhiteSpace(
                        dataPath);
            }
            catch
            {
                unityAvailable = false;
            }

            Assembly[] assemblies =
                GetLoadedAssemblies();

            result.LoadedAssemblyCount =
                assemblies.Length;

            bool assemblyCSharpLoaded =
                ContainsAssembly(
                    assemblies,
                    "Assembly-CSharp");

            bool hkmpLoaded =
                ContainsAssembly(
                    assemblies,
                    "HKMP");

            bool whitelistLoaded =
                ContainsAssembly(
                    assemblies,
                    "HKMP.Whitelist");

            if (!unityAvailable)
            {
                result.ExecutionMode =
                    HostExecutionMode.StandaloneServer;

                result.IsUnityGameProcess =
                    false;

                result.SetFailure(
                    "HOST_EXECUTION_MODE_UNSUPPORTED",
                    "The Whitelist server is not running inside a playable Hollow Knight Unity process.");

                return result;
            }

            if (!assemblyCSharpLoaded)
            {
                result.ExecutionMode =
                    isPlaying
                        ? HostExecutionMode.InGameHost
                        : HostExecutionMode.Unsupported;

                result.IsUnityGameProcess =
                    false;

                result.SetFailure(
                    isPlaying
                        ? "ASSEMBLY_CSHARP_UNAVAILABLE"
                        : "HOST_EXECUTION_MODE_UNSUPPORTED",
                    isPlaying
                        ? "The Hollow Knight Assembly-CSharp assembly is not loaded in the Unity process."
                        : "The current Unity process is not recognized as a Hollow Knight game context because Assembly-CSharp is not loaded.");

                return result;
            }

            result.ExecutionMode =
                HostExecutionMode.InGameHost;

            result.IsUnityGameProcess =
                true;

            if (!isPlaying)
            {
                result.AddWarning(
                    "Unity is initialized but Application.isPlaying is false; readiness is being evaluated from the actual Hollow Knight runtime layout and loaded game assembly state.");
            }

            foreach (string candidate in
                     GetInGameCandidates(
                         configuredRoot,
                         dataPath))
            {
                string resolved =
                    FindGameRoot(
                        candidate);

                if (!string.IsNullOrWhiteSpace(resolved))
                {
                    result.GameRoot =
                        resolved;

                    break;
                }
            }

            if (string.IsNullOrWhiteSpace(
                    result.GameRoot))
            {
                result.SetFailure(
                    "GAME_ROOT_UNAVAILABLE",
                    "No valid Hollow Knight game root could be resolved from the Unity game context.");

                return result;
            }

            result.ManagedRoot =
                Path.Combine(
                    result.GameRoot,
                    "hollow_knight_Data",
                    "Managed");

            result.AssemblyCSharpPath =
                Path.Combine(
                    result.ManagedRoot,
                    "Assembly-CSharp.dll");

            try
            {
                result.AssemblyCSharpPresent =
                    Directory.Exists(
                        result.ManagedRoot) &&
                    File.Exists(
                        result.AssemblyCSharpPath);
            }
            catch
            {
                result.AssemblyCSharpPresent =
                    false;
            }

            if (!result.AssemblyCSharpPresent)
            {
                result.SetFailure(
                    "ASSEMBLY_CSHARP_UNAVAILABLE",
                    result.AssemblyCSharpPath);
            }

            result.HkmpAssemblyPath =
                FindLoadedAssemblyPath(
                    assemblies,
                    "HKMP");

            result.HkmpAssemblyPresent =
                hkmpLoaded;

            if (!result.HkmpAssemblyPresent)
            {
                result.SetFailure(
                    "HKMP_RUNTIME_UNAVAILABLE",
                    "The HKMP assembly is not loaded in the Hollow Knight process.");
            }
            else if (!IsPathWithin(
                         result.GameRoot,
                         result.HkmpAssemblyPath))
            {
                result.AddWarning(
                    "HKMP assembly is loaded from outside the resolved game root: " +
                    (result.HkmpAssemblyPath ?? "<unknown>"));
            }

            result.WhitelistAssemblyPath =
                GetCurrentWhitelistAssemblyPath();

            result.WhitelistAssemblyPresent =
                whitelistLoaded &&
                !string.IsNullOrWhiteSpace(
                    result.WhitelistAssemblyPath) &&
                File.Exists(
                    result.WhitelistAssemblyPath);

            if (!result.WhitelistAssemblyPresent)
            {
                result.SetFailure(
                    "WHITELIST_ASSEMBLY_UNAVAILABLE",
                    "HKMP.Whitelist is not loaded from a readable assembly file.");
            }
            else if (!IsPathWithin(
                         result.GameRoot,
                         result.WhitelistAssemblyPath))
            {
                result.AddWarning(
                    "HKMP.Whitelist assembly is loaded from outside the resolved game root: " +
                    result.WhitelistAssemblyPath);
            }

            return result;
        }

        private static IEnumerable<string> GetInGameCandidates(
            string configuredRoot,
            string dataPath)
        {
            HashSet<string> seen =
                new HashSet<string>(
                    StringComparer.OrdinalIgnoreCase);

            if (!string.IsNullOrWhiteSpace(
                    configuredRoot) &&
                seen.Add(
                    configuredRoot))
            {
                yield return configuredRoot;
            }

            if (!string.IsNullOrWhiteSpace(
                    dataPath) &&
                seen.Add(
                    dataPath))
            {
                yield return dataPath;
            }

            string assemblyPath = null;

            try
            {
                assemblyPath =
                    typeof(GamePathResolver)
                        .Assembly
                        .Location;
            }
            catch
            {
            }

            if (!string.IsNullOrWhiteSpace(
                    assemblyPath) &&
                seen.Add(
                    assemblyPath))
            {
                yield return assemblyPath;
            }
        }

        private static Assembly[] GetLoadedAssemblies()
        {
            try
            {
                return
                    AppDomain.CurrentDomain
                        .GetAssemblies()
                        .Where(
                            assembly =>
                                assembly != null)
                        .ToArray();
            }
            catch
            {
                return new Assembly[0];
            }
        }

        private static bool ContainsAssembly(
            IEnumerable<Assembly> assemblies,
            string simpleName)
        {
            if (assemblies == null ||
                string.IsNullOrWhiteSpace(simpleName))
            {
                return false;
            }

            foreach (Assembly assembly in assemblies)
            {
                try
                {
                    if (assembly != null &&
                        string.Equals(
                            assembly.GetName().Name,
                            simpleName,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
                catch
                {
                }
            }

            return false;
        }

        private static string FindLoadedAssemblyPath(
            IEnumerable<Assembly> assemblies,
            string simpleName)
        {
            if (assemblies == null ||
                string.IsNullOrWhiteSpace(simpleName))
            {
                return null;
            }

            foreach (Assembly assembly in assemblies)
            {
                try
                {
                    if (assembly == null ||
                        !string.Equals(
                            assembly.GetName().Name,
                            simpleName,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    string location =
                        assembly.Location;

                    if (string.IsNullOrWhiteSpace(location))
                    {
                        return null;
                    }

                    return NormalizeFullPath(location);
                }
                catch
                {
                    return null;
                }
            }

            return null;
        }

        private static string GetCurrentWhitelistAssemblyPath()
        {
            try
            {
                string location =
                    typeof(GamePathResolver)
                        .Assembly
                        .Location;

                if (string.IsNullOrWhiteSpace(location))
                {
                    return null;
                }

                return NormalizeFullPath(location);
            }
            catch
            {
                return null;
            }
        }

        private static string FindGameRoot(
            string candidate)
        {
            string current =
                NormalizeFullPath(
                    candidate);

            if (string.IsNullOrWhiteSpace(current))
            {
                return null;
            }

            try
            {
                if (File.Exists(current))
                {
                    current =
                        Path.GetDirectoryName(
                            current);
                }
            }
            catch
            {
                return null;
            }

            for (
                int depth = 0;
                depth < 12 &&
                !string.IsNullOrWhiteSpace(current);
                depth++)
            {
                if (IsGameRoot(current))
                {
                    return current;
                }

                DirectoryInfo parent;

                try
                {
                    parent =
                        Directory.GetParent(
                            current);
                }
                catch
                {
                    return null;
                }

                if (parent == null)
                {
                    return null;
                }

                string next =
                    NormalizeFullPath(
                        parent.FullName);

                if (string.Equals(
                        current,
                        next,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return null;
                }

                current =
                    next;
            }

            return null;
        }

        private static bool IsGameRoot(
            string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            string managed =
                Path.Combine(
                    path,
                    "hollow_knight_Data",
                    "Managed");

            string assembly =
                Path.Combine(
                    managed,
                    "Assembly-CSharp.dll");

            try
            {
                return
                    Directory.Exists(
                        managed) &&
                    File.Exists(
                        assembly);
            }
            catch
            {
                return false;
            }
        }

        internal static bool IsPathWithin(
            string root,
            string path)
        {
            string normalizedRoot =
                NormalizeFullPath(
                    root);

            string normalizedPath =
                NormalizeFullPath(
                    path);

            if (string.IsNullOrWhiteSpace(
                    normalizedRoot) ||
                string.IsNullOrWhiteSpace(
                    normalizedPath))
            {
                return false;
            }

            if (string.Equals(
                    normalizedRoot,
                    normalizedPath,
                    StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            string prefix =
                normalizedRoot.TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar) +
                Path.DirectorySeparatorChar;

            return
                normalizedPath.StartsWith(
                    prefix,
                    StringComparison.OrdinalIgnoreCase);
        }

        private static string BuildFailureReason(
            HostReadinessResult readiness)
        {
            if (readiness == null)
            {
                return
                    "HOST_READINESS_RESULT_UNAVAILABLE";
            }

            string code =
                readiness.FailureCode ??
                "HOST_READINESS_FAILED";

            string details =
                readiness.FailureDetails;

            return
                string.IsNullOrWhiteSpace(
                    details)
                    ? code
                    : code + ":" + details;
        }

        private static string NormalizeFullPath(
            string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return null;
            }

            try
            {
                return
                    Path.GetFullPath(
                        path)
                        .TrimEnd(
                            Path.DirectorySeparatorChar,
                            Path.AltDirectorySeparatorChar);
            }
            catch
            {
                return null;
            }
        }
    }
}
