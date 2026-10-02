using HKMP.Whitelist.Security;
using System;
using System.Collections.Generic;
using System.IO;

namespace HKMP.Whitelist.Client
{
    internal enum SaveObservationKind
    {
        InitialSnapshot,
        SaveLoaded,
        SaveBeforeWrite,
        SaveAfterWrite,
        SlotChanged,
        Poll,
        ExpectedMutation,
        UnexpectedExternalChange,
        FileUnavailable,
        HashError
    }

    internal sealed class SaveSnapshot
    {
        public string SlotId { get; internal set; }

        public string Path { get; internal set; }

        public long FileSize { get; internal set; }

        public DateTime LastWriteTimeUtc { get; internal set; }

        public string Sha256 { get; internal set; }

        public DateTime CapturedAtUtc { get; internal set; }

        public bool FileExists { get; internal set; }
    }

    internal sealed class SaveIntegrityEvidence
    {
        public DateTime TimestampUtc { get; internal set; }

        public string SlotId { get; internal set; }

        public string Path { get; internal set; }

        public SaveObservationKind Kind { get; internal set; }

        public bool FileExists { get; internal set; }

        public long FileSize { get; internal set; }

        public DateTime LastWriteTimeUtc { get; internal set; }

        public string Sha256 { get; internal set; }

        public bool ChangedFromPrevious { get; internal set; }

        public bool ExpectedMutation { get; internal set; }

        public bool UnexpectedChange
        {
            get
            {
                return ChangedFromPrevious &&
                       !ExpectedMutation;
            }
        }

        public string Error { get; internal set; }
    }

    internal sealed class SaveIntegrityResult
    {
        public DateTime TimestampUtc { get; internal set; }

        public bool Complete { get; internal set; } = true;

        public bool Changed { get; internal set; }

        public bool UnexpectedChange { get; internal set; }

        public SaveIntegrityEvidence Evidence { get; internal set; }

        public List<string> Errors { get; } =
            new List<string>();
    }

    internal sealed class SaveIntegrityProvider : IDisposable
    {
        private readonly object _gate =
            new object();

        private readonly Dictionary<string, SaveSnapshot>
            _snapshots =
                new Dictionary<string, SaveSnapshot>(
                    StringComparer.OrdinalIgnoreCase);

        private readonly HashSet<string>
            _expectedMutations =
                new HashSet<string>(
                    StringComparer.OrdinalIgnoreCase);

        private bool _disposed;

        private bool _enabled = true;

        public event Action<SaveIntegrityEvidence>
            EvidenceObserved;

        public event Action<SaveIntegrityEvidence>
            UnexpectedChangeDetected;

        public bool Enabled
        {
            get
            {
                lock (_gate)
                {
                    return _enabled &&
                           !_disposed;
                }
            }
            set
            {
                lock (_gate)
                {
                    if (_disposed)
                    {
                        return;
                    }

                    _enabled = value;
                }
            }
        }

        public int SnapshotCount
        {
            get
            {
                lock (_gate)
                {
                    return _snapshots.Count;
                }
            }
        }

        public void CaptureInitialSnapshot(
            string slotId,
            string savePath)
        {
            Observe(
                slotId,
                savePath,
                SaveObservationKind.InitialSnapshot,
                false);
        }

        public SaveIntegrityResult NotifySaveLoaded(
            string slotId,
            string savePath)
        {
            return Observe(
                slotId,
                savePath,
                SaveObservationKind.SaveLoaded,
                true);
        }

        public SaveIntegrityResult BeginExpectedSave(
            string slotId,
            string savePath)
        {
            if (!CanUse())
            {
                return DisabledResult();
            }

            string key =
                BuildKey(
                    slotId,
                    savePath);

            lock (_gate)
            {
                _expectedMutations.Add(
                    key);
            }

            return Observe(
                slotId,
                savePath,
                SaveObservationKind.SaveBeforeWrite,
                true);
        }

        public SaveIntegrityResult CompleteExpectedSave(
            string slotId,
            string savePath)
        {
            if (!CanUse())
            {
                return DisabledResult();
            }

            string key =
                BuildKey(
                    slotId,
                    savePath);

            SaveIntegrityResult result =
                Observe(
                    slotId,
                    savePath,
                    SaveObservationKind.SaveAfterWrite,
                    true);

            lock (_gate)
            {
                _expectedMutations.Remove(
                    key);
            }

            return result;
        }

        public SaveIntegrityResult NotifySlotChanged(
            string slotId,
            string savePath)
        {
            return Observe(
                slotId,
                savePath,
                SaveObservationKind.SlotChanged,
                true);
        }

        public SaveIntegrityResult NotifyExpectedMutation(
            string slotId,
            string savePath)
        {
            return Observe(
                slotId,
                savePath,
                SaveObservationKind.ExpectedMutation,
                true);
        }

        public SaveIntegrityResult CheckNow(
            string slotId,
            string savePath)
        {
            bool expected =
                IsExpectedMutation(
                    slotId,
                    savePath);

            return Observe(
                slotId,
                savePath,
                SaveObservationKind.Poll,
                expected);
        }

        public bool TryGetSnapshot(
            string slotId,
            string savePath,
            out SaveSnapshot snapshot)
        {
            snapshot = null;

            if (!CanUse())
            {
                return false;
            }

            string key =
                BuildKey(
                    slotId,
                    savePath);

            lock (_gate)
            {
                SaveSnapshot existing;

                if (!_snapshots.TryGetValue(
                        key,
                        out existing) ||
                    existing == null)
                {
                    return false;
                }

                snapshot =
                    CloneSnapshot(
                        existing);

                return true;
            }
        }

        public void ClearSnapshot(
            string slotId,
            string savePath)
        {
            if (string.IsNullOrWhiteSpace(
                    slotId) &&
                string.IsNullOrWhiteSpace(
                    savePath))
            {
                return;
            }

            string key =
                BuildKey(
                    slotId,
                    savePath);

            lock (_gate)
            {
                if (_disposed)
                {
                    return;
                }

                _snapshots.Remove(
                    key);

                _expectedMutations.Remove(
                    key);
            }
        }

        public void ClearAll()
        {
            lock (_gate)
            {
                if (_disposed)
                {
                    return;
                }

                _snapshots.Clear();
                _expectedMutations.Clear();
            }
        }

        public void Dispose()
        {
            lock (_gate)
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;

                _snapshots.Clear();
                _expectedMutations.Clear();

                EvidenceObserved = null;
                UnexpectedChangeDetected = null;
            }
        }

        private SaveIntegrityResult Observe(
            string slotId,
            string savePath,
            SaveObservationKind kind,
            bool expectedMutation)
        {
            SaveIntegrityResult result =
                new SaveIntegrityResult
                {
                    TimestampUtc =
                        DateTime.UtcNow
                };

            if (!CanUse())
            {
                result.Complete = false;

                result.Errors.Add(
                    "SaveIntegrityProvider is disabled or disposed.");

                return result;
            }

            if (string.IsNullOrWhiteSpace(
                    slotId))
            {
                result.Complete = false;

                result.Errors.Add(
                    "Save slot identifier is empty.");
            }

            if (string.IsNullOrWhiteSpace(
                    savePath))
            {
                result.Complete = false;

                result.Errors.Add(
                    "Save path is empty.");
            }

            if (!result.Complete)
            {
                return result;
            }

            string normalizedPath;

            try
            {
                normalizedPath =
                    Path.GetFullPath(
                        savePath);
            }
            catch (Exception ex)
            {
                result.Complete = false;

                result.Errors.Add(
                    "Save path could not be normalized: " +
                    GetExceptionName(ex));

                return result;
            }

            string key =
                BuildKey(
                    slotId,
                    normalizedPath);

            bool mutationExpected =
                expectedMutation ||
                IsExpectedMutation(
                    slotId,
                    normalizedPath);

            SaveSnapshot previous =
                null;

            lock (_gate)
            {
                SaveSnapshot stored;

                if (_snapshots.TryGetValue(
                        key,
                        out stored) &&
                    stored != null)
                {
                    previous =
                        CloneSnapshot(
                            stored);
                }
            }

            SaveSnapshot current =
                ReadSnapshot(
                    slotId,
                    normalizedPath,
                    result);

            SaveIntegrityEvidence evidence =
                new SaveIntegrityEvidence
                {
                    TimestampUtc =
                        DateTime.UtcNow,

                    SlotId =
                        slotId,

                    Path =
                        normalizedPath,

                    Kind =
                        kind,

                    ExpectedMutation =
                        mutationExpected
                };

            if (current == null)
            {
                evidence.FileExists = false;

                evidence.Error =
                    result.Errors.Count > 0
                        ? result.Errors[0]
                        : "Save snapshot could not be obtained.";

                result.Evidence =
                    evidence;

                RaiseEvidence(
                    evidence);

                return result;
            }

            evidence.FileExists =
                current.FileExists;

            evidence.FileSize =
                current.FileSize;

            evidence.LastWriteTimeUtc =
                current.LastWriteTimeUtc;

            evidence.Sha256 =
                current.Sha256;

            bool changed =
                HasMeaningfulChange(
                    previous,
                    current);

            evidence.ChangedFromPrevious =
                changed;

            result.Changed =
                changed;

            result.UnexpectedChange =
                changed &&
                !mutationExpected;

            result.Evidence =
                evidence;

            lock (_gate)
            {
                if (!_disposed)
                {
                    _snapshots[key] =
                        CloneSnapshot(
                            current);
                }
            }

            RaiseEvidence(
                evidence);

            if (result.UnexpectedChange)
            {
                RaiseUnexpectedChange(
                    evidence);
            }

            return result;
        }

        private static SaveSnapshot ReadSnapshot(
            string slotId,
            string path,
            SaveIntegrityResult result)
        {
            SaveSnapshot snapshot =
                new SaveSnapshot
                {
                    SlotId =
                        slotId,

                    Path =
                        path,

                    CapturedAtUtc =
                        DateTime.UtcNow,

                    FileExists =
                        false
                };

            try
            {
                if (!File.Exists(path))
                {
                    return snapshot;
                }

                FileInfo info =
                    new FileInfo(
                        path);

                snapshot.FileExists =
                    true;

                snapshot.FileSize =
                    info.Length;

                snapshot.LastWriteTimeUtc =
                    info.LastWriteTimeUtc;
            }
            catch (Exception ex)
            {
                result.Complete = false;

                result.Errors.Add(
                    "Save metadata could not be read: " +
                    GetExceptionName(ex));

                return null;
            }

            try
            {
                snapshot.Sha256 =
                    HashUtil.Sha256File(
                        path);
            }
            catch (Exception ex)
            {
                result.Complete = false;

                result.Errors.Add(
                    "Save SHA-256 could not be computed: " +
                    GetExceptionName(ex));

                return null;
            }

            if (string.IsNullOrEmpty(
                    snapshot.Sha256))
            {
                result.Complete = false;

                result.Errors.Add(
                    "Save SHA-256 is unavailable.");

                return null;
            }

            try
            {
                FileInfo afterHash =
                    new FileInfo(
                        path);

                if (afterHash.Length !=
                    snapshot.FileSize ||
                    afterHash.LastWriteTimeUtc !=
                    snapshot.LastWriteTimeUtc)
                {
                    result.Complete = false;

                    result.Errors.Add(
                        "Save file changed while being hashed.");

                    return null;
                }
            }
            catch (Exception ex)
            {
                result.Complete = false;

                result.Errors.Add(
                    "Save metadata could not be rechecked: " +
                    GetExceptionName(ex));

                return null;
            }

            return snapshot;
        }

        private bool IsExpectedMutation(
            string slotId,
            string savePath)
        {
            string key =
                BuildKey(
                    slotId,
                    savePath);

            lock (_gate)
            {
                if (_disposed)
                {
                    return false;
                }

                return _expectedMutations.Contains(
                    key);
            }
        }

        private bool CanUse()
        {
            lock (_gate)
            {
                return _enabled &&
                       !_disposed;
            }
        }

        private static bool HasMeaningfulChange(
            SaveSnapshot previous,
            SaveSnapshot current)
        {
            if (current == null)
            {
                return true;
            }

            if (previous == null)
            {
                return false;
            }

            if (previous.FileExists !=
                current.FileExists)
            {
                return true;
            }

            if (!current.FileExists)
            {
                return false;
            }

            if (previous.FileSize !=
                current.FileSize)
            {
                return true;
            }

            if (previous.LastWriteTimeUtc !=
                current.LastWriteTimeUtc)
            {
                return true;
            }

            return !string.Equals(
                previous.Sha256,
                current.Sha256,
                StringComparison.OrdinalIgnoreCase);
        }

        private static SaveSnapshot CloneSnapshot(
            SaveSnapshot source)
        {
            if (source == null)
            {
                return null;
            }

            return new SaveSnapshot
            {
                SlotId =
                    source.SlotId,

                Path =
                    source.Path,

                FileSize =
                    source.FileSize,

                LastWriteTimeUtc =
                    source.LastWriteTimeUtc,

                Sha256 =
                    source.Sha256,

                CapturedAtUtc =
                    source.CapturedAtUtc,

                FileExists =
                    source.FileExists
            };
        }

        private static string BuildKey(
            string slotId,
            string savePath)
        {
            string slot =
                (slotId ?? "").Trim();

            string path =
                (savePath ?? "").Trim();

            return
                slot +
                "|" +
                path;
        }

        private void RaiseEvidence(
            SaveIntegrityEvidence evidence)
        {
            Action<SaveIntegrityEvidence> handler;

            lock (_gate)
            {
                if (_disposed)
                {
                    return;
                }

                handler =
                    EvidenceObserved;
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

        private void RaiseUnexpectedChange(
            SaveIntegrityEvidence evidence)
        {
            Action<SaveIntegrityEvidence> handler;

            lock (_gate)
            {
                if (_disposed)
                {
                    return;
                }

                handler =
                    UnexpectedChangeDetected;
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

        private SaveIntegrityResult DisabledResult()
        {
            SaveIntegrityResult result =
                new SaveIntegrityResult
                {
                    TimestampUtc =
                        DateTime.UtcNow,

                    Complete = false
                };

            result.Errors.Add(
                "SaveIntegrityProvider is disabled or disposed.");

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