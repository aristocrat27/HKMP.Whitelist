using HKMP.Whitelist.Security;
using HKMP.Whitelist.Shared;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading;

namespace HKMP.Whitelist.Client
{
    internal sealed class RuntimeAssemblyEvidence
    {
        public DateTime TimestampUtc { get; set; }

        public string EventType { get; set; }

        public string FullName { get; set; }

        public string AssemblyName { get; set; }

        public string AssemblyVersion { get; set; }

        public string Location { get; set; }

        public string RelativePath { get; set; }

        public string FileName { get; set; }

        public long FileSize { get; set; }

        public string Sha256 { get; set; }

        public bool IsDynamic { get; set; }

        public bool HasPhysicalLocation { get; set; }

        public bool MatchesHostBaseline { get; set; }

        public bool WasLoadedInBaseline { get; set; }

        public string Status { get; set; }

        public string Error { get; set; }
    }

    internal sealed class RuntimeProviderResult
    {
        public bool Complete { get; set; } = true;

        public DateTime TimestampUtc { get; set; }

        public int AssemblyCount { get; set; }

        public int NewAssemblyCount { get; set; }

        public int MismatchCount { get; set; }

        public List<RuntimeAssemblyEvidence> Events { get; } =
            new List<RuntimeAssemblyEvidence>();

        public List<RuntimeAssemblyEvidence> Mismatches { get; } =
            new List<RuntimeAssemblyEvidence>();

        public List<string> Errors { get; } =
            new List<string>();
    }

    internal sealed class RuntimeProvider : IDisposable
    {
        private readonly object _sync =
            new object();

        private readonly HostBaseline _baseline;

        private readonly TimeSpan _scanInterval;

        private readonly HashSet<string> _seenAssemblyKeys =
            new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

        private Timer _timer;

        private bool _started;

        private bool _disposed;

        private int _scanInProgress;

        public event Action<RuntimeAssemblyEvidence> AssemblyObserved;

        public event Action<RuntimeProviderResult> ScanCompleted;

        public bool IsRunning
        {
            get
            {
                lock (_sync)
                {
                    return _started && !_disposed;
                }
            }
        }

        public TimeSpan ScanInterval
        {
            get
            {
                return _scanInterval;
            }
        }

        public RuntimeProvider(
            HostBaseline baseline,
            TimeSpan scanInterval)
        {
            if (baseline == null)
            {
                throw new ArgumentNullException(
                    nameof(baseline));
            }

            if (scanInterval <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(scanInterval));
            }

            _baseline =
                baseline;

            _scanInterval =
                scanInterval;
        }

        public RuntimeProvider(
            HostBaseline baseline)
            : this(
                baseline,
                TimeSpan.FromSeconds(30))
        {
        }

        public void Start()
        {
            lock (_sync)
            {
                if (_disposed)
                {
                    throw new ObjectDisposedException(
                        nameof(RuntimeProvider));
                }

                if (_started)
                {
                    return;
                }

                _started = true;

                AppDomain.CurrentDomain.AssemblyLoad +=
                    OnAssemblyLoad;

                _timer =
                    new Timer(
                        TimerCallback,
                        null,
                        _scanInterval,
                        _scanInterval);
            }

            ForceScan();
        }

        public void Stop()
        {
            Timer timerToDispose = null;

            lock (_sync)
            {
                if (!_started)
                {
                    return;
                }

                _started = false;

                AppDomain.CurrentDomain.AssemblyLoad -=
                    OnAssemblyLoad;

                timerToDispose =
                    _timer;

                _timer = null;
            }

            if (timerToDispose != null)
            {
                timerToDispose.Dispose();
            }
        }

        public RuntimeProviderResult ForceScan()
        {
            if (_disposed)
            {
                return CreateDisposedResult();
            }

            if (Interlocked.Exchange(
                    ref _scanInProgress,
                    1) != 0)
            {
                RuntimeProviderResult skipped =
                    new RuntimeProviderResult
                    {
                        Complete = false,
                        TimestampUtc = DateTime.UtcNow,
                        AssemblyCount =
                            SafeGetAssemblyCount()
                    };

                skipped.Errors.Add(
                    "A runtime scan was already in progress.");

                return skipped;
            }

            RuntimeProviderResult result =
                new RuntimeProviderResult
                {
                    Complete = true,
                    TimestampUtc = DateTime.UtcNow
                };

            try
            {
                Assembly[] assemblies =
                    AppDomain.CurrentDomain.GetAssemblies();

                if (assemblies == null)
                {
                    result.Complete = false;

                    result.Errors.Add(
                        "AppDomain returned a null assembly list.");

                    return result;
                }

                result.AssemblyCount =
                    assemblies.Length;

                foreach (Assembly assembly in assemblies)
                {
                    if (assembly == null)
                    {
                        result.Complete = false;

                        result.Errors.Add(
                            "AppDomain returned a null assembly entry.");

                        continue;
                    }

                    RuntimeAssemblyEvidence evidence =
                        InspectAssembly(
                            assembly);

                    string assemblyKey =
                        BuildAssemblyKey(
                            evidence);

                    bool firstObservation;

                    lock (_sync)
                    {
                        firstObservation =
                            _seenAssemblyKeys.Add(
                                assemblyKey);
                    }

                    if (firstObservation)
                    {
                        result.NewAssemblyCount++;

                        if (IsRuntimeInteresting(
                                evidence))
                        {
                            result.Events.Add(
                                evidence);

                            RaiseAssemblyObserved(
                                evidence);
                        }
                    }

                    if (!evidence.MatchesHostBaseline)
                    {
                        result.MismatchCount++;

                        if (!result.Mismatches.Contains(
                                evidence))
                        {
                            result.Mismatches.Add(
                                evidence);
                        }

                        if (!result.Events.Contains(
                                evidence))
                        {
                            result.Events.Add(
                                evidence);

                            RaiseAssemblyObserved(
                                evidence);
                        }
                    }

                    if (!evidence.HasPhysicalLocation ||
                        evidence.IsDynamic ||
                        string.IsNullOrEmpty(
                            evidence.Sha256))
                    {
                        result.Complete = false;
                    }

                    if (!string.IsNullOrEmpty(
                            evidence.Error))
                    {
                        result.Complete = false;

                        result.Errors.Add(
                            evidence.Error);
                    }
                }

                return result;
            }
            catch (Exception ex)
            {
                result.Complete = false;

                result.Errors.Add(
                    "Runtime assembly scan failed: " +
                    GetExceptionName(ex));

                return result;
            }
            finally
            {
                Interlocked.Exchange(
                    ref _scanInProgress,
                    0);

                RaiseScanCompleted(
                    result);
            }
        }

        public void Dispose()
        {
            bool shouldStop;

            lock (_sync)
            {
                if (_disposed)
                {
                    return;
                }

                shouldStop =
                    _started;
            }

            if (shouldStop)
            {
                Stop();
            }

            lock (_sync)
            {
                _disposed = true;

                _seenAssemblyKeys.Clear();

                AssemblyObserved = null;
                ScanCompleted = null;
            }
        }

        private void OnAssemblyLoad(
            object sender,
            AssemblyLoadEventArgs args)
        {
            if (args == null ||
                args.LoadedAssembly == null)
            {
                return;
            }

            lock (_sync)
            {
                if (!_started || _disposed)
                {
                    return;
                }
            }

            RuntimeAssemblyEvidence evidence =
                InspectAssembly(
                    args.LoadedAssembly);

            string key =
                BuildAssemblyKey(
                    evidence);

            bool firstObservation;

            lock (_sync)
            {
                firstObservation =
                    _seenAssemblyKeys.Add(
                        key);
            }

            if (!firstObservation)
            {
                return;
            }

            RaiseAssemblyObserved(
                evidence);
        }

        private void TimerCallback(
            object state)
        {
            lock (_sync)
            {
                if (!_started ||
                    _disposed)
                {
                    return;
                }
            }

            ForceScan();
        }

        private RuntimeAssemblyEvidence InspectAssembly(
            Assembly assembly)
        {
            RuntimeAssemblyEvidence evidence =
                new RuntimeAssemblyEvidence
                {
                    TimestampUtc =
                        DateTime.UtcNow,

                    EventType =
                        "AssemblyObserved",

                    FullName =
                        SafeAssemblyFullName(
                            assembly),

                    AssemblyName =
                        SafeAssemblyName(
                            assembly),

                    AssemblyVersion =
                        SafeAssemblyVersion(
                            assembly),

                    Location =
                        SafeAssemblyLocation(
                            assembly),

                    IsDynamic =
                        SafeIsDynamic(
                            assembly),

                    Status =
                        "UNKNOWN"
                };

            if (evidence.IsDynamic)
            {
                evidence.HasPhysicalLocation =
                    false;

                evidence.Status =
                    "DYNAMIC_ASSEMBLY";

                evidence.Error =
                    "Dynamic assembly has no verifiable disk artifact.";

                evidence.MatchesHostBaseline =
                    false;

                return evidence;
            }

            if (string.IsNullOrEmpty(
                    evidence.Location))
            {
                evidence.HasPhysicalLocation =
                    false;

                evidence.Status =
                    "LOCATION_UNAVAILABLE";

                evidence.Error =
                    "Assembly location is unavailable.";

                evidence.MatchesHostBaseline =
                    false;

                return evidence;
            }

            try
            {
                evidence.Location =
                    Path.GetFullPath(
                        evidence.Location);
            }
            catch
            {
            }

            evidence.HasPhysicalLocation =
                File.Exists(
                    evidence.Location);

            if (!evidence.HasPhysicalLocation)
            {
                evidence.Status =
                    "FILE_NOT_FOUND";

                evidence.Error =
                    "Assembly location does not point to an existing file.";

                evidence.MatchesHostBaseline =
                    false;

                return evidence;
            }

            evidence.FileName =
                SafeFileName(
                    evidence.Location);

            evidence.RelativePath =
                NormalizeRelativePath(
                    evidence.Location);

            try
            {
                FileInfo fileInfo =
                    new FileInfo(
                        evidence.Location);

                evidence.FileSize =
                    fileInfo.Length;
            }
            catch (Exception ex)
            {
                evidence.Status =
                    "FILE_METADATA_ERROR";

                evidence.Error =
                    "Assembly file metadata could not be read: " +
                    GetExceptionName(ex);

                evidence.MatchesHostBaseline =
                    false;

                return evidence;
            }

            try
            {
                evidence.Sha256 =
                    HashUtil.Sha256File(
                        evidence.Location);
            }
            catch (Exception ex)
            {
                evidence.Status =
                    "HASH_ERROR";

                evidence.Error =
                    "Assembly file hash could not be computed: " +
                    GetExceptionName(ex);

                evidence.MatchesHostBaseline =
                    false;

                return evidence;
            }

            evidence.MatchesHostBaseline =
                MatchesHostBaseline(
                    _baseline,
                    assembly,
                    evidence.Location,
                    evidence.RelativePath,
                    evidence.FileName,
                    evidence.FileSize,
                    evidence.Sha256,
                    out bool wasLoadedInBaseline);

            evidence.WasLoadedInBaseline =
                wasLoadedInBaseline;

            if (evidence.MatchesHostBaseline)
            {
                evidence.Status =
                    "BASELINE_MATCH";
            }
            else if (wasLoadedInBaseline)
            {
                evidence.EventType =
                    "AssemblyBaselineMismatch";

                evidence.Status =
                    "BASELINE_MISMATCH";
            }
            else
            {
                evidence.EventType =
                    "AssemblyUnknown";

                evidence.Status =
                    "UNKNOWN_ASSEMBLY";
            }

            return evidence;
        }

        private static bool MatchesHostBaseline(
            HostBaseline baseline,
            Assembly assembly,
            string location,
            string relativePath,
            string fileName,
            long fileSize,
            string sha256,
            out bool wasLoadedInBaseline)
        {
            wasLoadedInBaseline =
                false;

            if (baseline == null ||
                baseline.Artifacts == null ||
                assembly == null)
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

            foreach (BaselineArtifact artifact in baseline.Artifacts)
            {
                if (artifact == null)
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
                        sha256,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!artifact.IsLoaded)
                {
                    wasLoadedInBaseline =
                        false;

                    continue;
                }

                wasLoadedInBaseline =
                    true;

                if (!string.IsNullOrEmpty(
                        artifact.AssemblyLocation) &&
                    !PathsEqual(
                        NormalizeRelativePath(
                            artifact.AssemblyLocation),
                        relativePath))
                {
                    return false;
                }

                return true;
            }

            return false;
        }

        private static bool IsRuntimeInteresting(
            RuntimeAssemblyEvidence evidence)
        {
            if (evidence == null)
            {
                return false;
            }

            if (evidence.IsDynamic ||
                !evidence.HasPhysicalLocation)
            {
                return true;
            }

            if (!evidence.MatchesHostBaseline)
            {
                return true;
            }

            if (!evidence.WasLoadedInBaseline)
            {
                return true;
            }

            return false;
        }

        private static string BuildAssemblyKey(
            RuntimeAssemblyEvidence evidence)
        {
            if (evidence == null)
            {
                return "<null>";
            }

            return
                (evidence.FullName ?? "") +
                "|" +
                (evidence.Location ?? "") +
                "|" +
                (evidence.Sha256 ?? "");
        }

        private static bool SafeIsDynamic(
            Assembly assembly)
        {
            if (assembly == null)
            {
                return true;
            }

            try
            {
                return assembly.IsDynamic;
            }
            catch
            {
                return true;
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

                if (name == null)
                {
                    return "";
                }

                return name.Name ?? "";
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

        private void RaiseAssemblyObserved(
            RuntimeAssemblyEvidence evidence)
        {
            Action<RuntimeAssemblyEvidence> handler;

            lock (_sync)
            {
                if (_disposed)
                {
                    return;
                }

                handler =
                    AssemblyObserved;
            }

            if (handler == null)
            {
                return;
            }

            try
            {
                handler(evidence);
            }
            catch
            {
            }
        }

        private void RaiseScanCompleted(
            RuntimeProviderResult result)
        {
            Action<RuntimeProviderResult> handler;

            lock (_sync)
            {
                if (_disposed)
                {
                    return;
                }

                handler =
                    ScanCompleted;
            }

            if (handler == null)
            {
                return;
            }

            try
            {
                handler(result);
            }
            catch
            {
            }
        }

        private static int SafeGetAssemblyCount()
        {
            try
            {
                Assembly[] assemblies =
                    AppDomain.CurrentDomain.GetAssemblies();

                return assemblies == null
                    ? 0
                    : assemblies.Length;
            }
            catch
            {
                return 0;
            }
        }

        private RuntimeProviderResult CreateDisposedResult()
        {
            RuntimeProviderResult result =
                new RuntimeProviderResult
                {
                    Complete = false,
                    TimestampUtc =
                        DateTime.UtcNow,
                    AssemblyCount =
                        0
                };

            result.Errors.Add(
                "RuntimeProvider is disposed.");

            return result;
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