using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using HKMP.Whitelist.Shared;
using Newtonsoft.Json;

namespace HKMP.Whitelist.Core
{
    public sealed class ViolationStore
    {
        private readonly object _sync =
            new object();

        private readonly Dictionary<string, ObservedViolation> _violations =
            new Dictionary<string, ObservedViolation>(
                StringComparer.OrdinalIgnoreCase);

        private readonly string _persistencePath;
        private readonly string _legacyPersistencePath;

        public ViolationStore(
            string persistencePath = null,
            string legacyPersistencePath = null)
        {
            _persistencePath =
                NormalizeOptional(
                    persistencePath);

            _legacyPersistencePath =
                NormalizeOptional(
                    legacyPersistencePath);
        }

        public int Count
        {
            get
            {
                lock (_sync)
                {
                    return _violations.Count;
                }
            }
        }

        public IReadOnlyCollection<ObservedViolation> Violations
        {
            get
            {
                lock (_sync)
                {
                    return new ReadOnlyCollection<ObservedViolation>(
                        _violations.Values
                            .Select(
                                Clone)
                            .ToList());
                }
            }
        }

        public ObservedViolation Record(
            ObservedViolation violation)
        {
            if (violation == null)
            {
                return null;
            }

            string key =
                BuildKey(
                    violation);

            lock (_sync)
            {
                ObservedViolation existing;

                if (!_violations.TryGetValue(
                    key,
                    out existing))
                {
                    NormalizeViolation(
                        violation);

                    _violations.Add(
                        key,
                        violation);

                    PersistAll();

                    return violation;
                }

                string previousSessionId =
                    existing.LastSessionId;

                existing.RegisterObservation(
                    violation.LastSeenUtc,
                    violation.PlayerIdentityKey,
                    violation.DisplayName);

                if (string.IsNullOrWhiteSpace(
                    existing.FirstSessionId))
                {
                    existing.FirstSessionId =
                        FirstNonEmpty(
                            violation.FirstSessionId,
                            violation.SessionId);
                }

                string currentSessionId =
                    FirstNonEmpty(
                        violation.SessionId,
                        violation.LastSessionId);

                if (!string.IsNullOrWhiteSpace(
                    currentSessionId))
                {
                    existing.LastSessionId =
                        currentSessionId;

                    existing.SessionId =
                        currentSessionId;

                    if (string.IsNullOrWhiteSpace(
                            previousSessionId))
                    {
                        existing.SessionCount =
                            Math.Max(
                                1,
                                existing.SessionCount);
                    }
                    else if (!string.Equals(
                                 previousSessionId,
                                 currentSessionId,
                                 StringComparison.OrdinalIgnoreCase))
                    {
                        if (existing.SessionCount <= 0)
                        {
                            existing.SessionCount = 1;
                        }

                        existing.SessionCount++;
                    }
                }

                existing.ModId =
                    CopyIfPresent(
                        existing.ModId,
                        violation.ModId);

                existing.ArtifactId =
                    CopyIfPresent(
                        existing.ArtifactId,
                        violation.ArtifactId);

                existing.FileName =
                    CopyIfPresent(
                        existing.FileName,
                        violation.FileName);

                existing.Path =
                    CopyIfPresent(
                        existing.Path,
                        violation.Path);

                existing.Version =
                    CopyIfPresent(
                        existing.Version,
                        violation.Version);

                existing.AssemblyFullName =
                    CopyIfPresent(
                        existing.AssemblyFullName,
                        violation.AssemblyFullName);

                existing.Sha256 =
                    CopyIfPresent(
                        existing.Sha256,
                        violation.Sha256);

                if (violation.Severity >
                    existing.Severity)
                {
                    existing.Severity =
                        violation.Severity;
                }

                if (violation.Classification !=
                    ViolationClassification.Unknown)
                {
                    existing.Classification =
                        violation.Classification;
                }

                if (!string.IsNullOrWhiteSpace(
                    violation.Notes))
                {
                    existing.Notes =
                        violation.Notes;
                }

                if (!string.IsNullOrWhiteSpace(
                    violation.FirstPlayer) &&
                    string.IsNullOrWhiteSpace(
                        existing.FirstPlayer))
                {
                    existing.FirstPlayer =
                        violation.FirstPlayer;
                }

                if (!string.IsNullOrWhiteSpace(
                    violation.LastPlayer))
                {
                    existing.LastPlayer =
                        violation.LastPlayer;
                }

                PersistAll();

                return existing;
            }
        }

        public bool TryGet(
            string observationId,
            out ObservedViolation violation)
        {
            violation = null;

            if (string.IsNullOrWhiteSpace(
                observationId))
            {
                return false;
            }

            lock (_sync)
            {
                ObservedViolation found =
                    _violations.Values.FirstOrDefault(
                        item =>
                            string.Equals(
                                item.ObservationId,
                                observationId.Trim(),
                                StringComparison.OrdinalIgnoreCase));

                if (found == null)
                {
                    return false;
                }

                violation =
                    Clone(
                        found);

                return true;
            }
        }

        public IReadOnlyList<ObservedViolation> FindByPlayer(
            string playerIdentityKey)
        {
            if (string.IsNullOrWhiteSpace(
                playerIdentityKey))
            {
                return EmptyResult();
            }

            string normalized =
                playerIdentityKey.Trim();

            lock (_sync)
            {
                return new ReadOnlyCollection<ObservedViolation>(
                    _violations.Values
                        .Where(
                            item =>
                                string.Equals(
                                    item.PlayerIdentityKey,
                                    normalized,
                                    StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(
                                    item.FirstPlayer,
                                    normalized,
                                    StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(
                                    item.LastPlayer,
                                    normalized,
                                    StringComparison.OrdinalIgnoreCase))
                        .Select(
                            Clone)
                        .ToList());
            }
        }

        public IReadOnlyList<ObservedViolation> FindBySha256(
            string sha256)
        {
            if (string.IsNullOrWhiteSpace(
                sha256))
            {
                return EmptyResult();
            }

            string normalized =
                sha256.Trim();

            lock (_sync)
            {
                return new ReadOnlyCollection<ObservedViolation>(
                    _violations.Values
                        .Where(
                            item =>
                                string.Equals(
                                    item.Sha256,
                                    normalized,
                                    StringComparison.OrdinalIgnoreCase))
                        .Select(
                            Clone)
                        .ToList());
            }
        }

        public IReadOnlyList<ObservedViolation> FindByType(
            ViolationType violationType)
        {
            lock (_sync)
            {
                return new ReadOnlyCollection<ObservedViolation>(
                    _violations.Values
                        .Where(
                            item =>
                                item.ViolationType ==
                                violationType)
                        .Select(
                            Clone)
                        .ToList());
            }
        }

        public bool SetClassification(
            string observationId,
            ViolationClassification classification)
        {
            ObservedViolation violation;

            if (!TryGetInternal(
                observationId,
                out violation))
            {
                return false;
            }

            lock (_sync)
            {
                ObservedViolation stored;

                if (!_violations.TryGetValue(
                    BuildKey(
                        violation),
                    out stored) ||
                    stored == null)
                {
                    return false;
                }

                stored.SetClassification(
                    classification);

                PersistAll();

                return true;
            }
        }

        public void Clear(
            bool deletePersistenceFile)
        {
            lock (_sync)
            {
                _violations.Clear();

                if (deletePersistenceFile &&
                    !string.IsNullOrWhiteSpace(
                        _persistencePath))
                {
                    try
                    {
                        if (File.Exists(
                            _persistencePath))
                        {
                            File.Delete(
                                _persistencePath);
                        }
                    }
                    catch
                    {
                    }
                }
            }
        }

        public void Load()
        {
            lock (_sync)
            {
                _violations.Clear();

                if (TryLoadIndex(
                    _persistencePath))
                {
                    return;
                }

                if (!TryLoadLegacyJsonl())
                {
                    return;
                }

                PersistAll();
            }
        }

        private bool TryLoadIndex(
            string path)
        {
            if (string.IsNullOrWhiteSpace(path) ||
                !File.Exists(path))
            {
                return false;
            }

            try
            {
                string json =
                    File.ReadAllText(
                        path);

                if (string.IsNullOrWhiteSpace(json))
                {
                    return false;
                }

                List<ObservedViolation> values =
                    JsonConvert.DeserializeObject<List<ObservedViolation>>(
                        json);

                if (values == null)
                {
                    return false;
                }

                foreach (ObservedViolation violation
                         in values)
                {
                    MergeLoaded(
                        violation);
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        private bool TryLoadLegacyJsonl()
        {
            if (string.IsNullOrWhiteSpace(
                    _legacyPersistencePath) ||
                !File.Exists(
                    _legacyPersistencePath))
            {
                return false;
            }

            string[] lines;

            try
            {
                lines =
                    File.ReadAllLines(
                        _legacyPersistencePath);
            }
            catch
            {
                return false;
            }

            bool loaded =
                false;

            foreach (string line in lines)
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                try
                {
                    ObservedViolation violation =
                        JsonConvert.DeserializeObject<ObservedViolation>(
                            line);

                    if (violation == null)
                    {
                        continue;
                    }

                    MergeLoaded(
                        violation);

                    loaded = true;
                }
                catch
                {
                }
            }

            return loaded;
        }

        private void MergeLoaded(
            ObservedViolation violation)
        {
            if (violation == null)
            {
                return;
            }

            NormalizeViolation(
                violation);

            string key =
                BuildKey(
                    violation);

            ObservedViolation existing;

            if (!_violations.TryGetValue(
                key,
                out existing))
            {
                _violations[key] =
                    violation;

                return;
            }

            if (string.IsNullOrWhiteSpace(
                    existing.ObservationId) &&
                !string.IsNullOrWhiteSpace(
                    violation.ObservationId))
            {
                existing.ObservationId =
                    violation.ObservationId;
            }

            if (violation.FirstSeenUtc <
                existing.FirstSeenUtc)
            {
                existing.FirstSeenUtc =
                    violation.FirstSeenUtc;
            }

            if (violation.LastSeenUtc >
                existing.LastSeenUtc)
            {
                existing.LastSeenUtc =
                    violation.LastSeenUtc;
            }

            existing.SeenCount =
                Math.Max(
                    existing.SeenCount,
                    violation.SeenCount);

            existing.SessionCount =
                Math.Max(
                    existing.SessionCount,
                    violation.SessionCount);

            if (string.IsNullOrWhiteSpace(
                    existing.FirstSessionId))
            {
                existing.FirstSessionId =
                    FirstNonEmpty(
                        violation.FirstSessionId,
                        violation.SessionId);
            }

            string violationLastSession =
                FirstNonEmpty(
                    violation.LastSessionId,
                    violation.SessionId);

            if (!string.IsNullOrWhiteSpace(
                violationLastSession))
            {
                existing.LastSessionId =
                    violationLastSession;

                existing.SessionId =
                    violationLastSession;
            }

            if (!string.IsNullOrWhiteSpace(
                violation.FirstPlayer) &&
                string.IsNullOrWhiteSpace(
                    existing.FirstPlayer))
            {
                existing.FirstPlayer =
                    violation.FirstPlayer;
            }

            if (!string.IsNullOrWhiteSpace(
                violation.LastPlayer))
            {
                existing.LastPlayer =
                    violation.LastPlayer;
            }

            existing.DisplayName =
                CopyIfPresent(
                    existing.DisplayName,
                    violation.DisplayName);

            existing.ModId =
                CopyIfPresent(
                    existing.ModId,
                    violation.ModId);

            existing.ArtifactId =
                CopyIfPresent(
                    existing.ArtifactId,
                    violation.ArtifactId);

            existing.FileName =
                CopyIfPresent(
                    existing.FileName,
                    violation.FileName);

            existing.Path =
                CopyIfPresent(
                    existing.Path,
                    violation.Path);

            existing.Version =
                CopyIfPresent(
                    existing.Version,
                    violation.Version);

            existing.AssemblyFullName =
                CopyIfPresent(
                    existing.AssemblyFullName,
                    violation.AssemblyFullName);

            existing.Sha256 =
                CopyIfPresent(
                    existing.Sha256,
                    violation.Sha256);

            if (violation.Severity >
                existing.Severity)
            {
                existing.Severity =
                    violation.Severity;
            }

            if (violation.Classification !=
                ViolationClassification.Unknown)
            {
                existing.Classification =
                    violation.Classification;
            }

            if (!string.IsNullOrWhiteSpace(
                violation.Notes))
            {
                existing.Notes =
                    violation.Notes;
            }
        }

        private bool TryGetInternal(
            string observationId,
            out ObservedViolation violation)
        {
            violation = null;

            if (string.IsNullOrWhiteSpace(
                observationId))
            {
                return false;
            }

            string normalized =
                observationId.Trim();

            violation =
                _violations.Values.FirstOrDefault(
                    item =>
                        string.Equals(
                            item.ObservationId,
                            normalized,
                            StringComparison.OrdinalIgnoreCase));

            return violation != null;
        }

        private void PersistAll()
        {
            if (string.IsNullOrWhiteSpace(
                _persistencePath))
            {
                return;
            }

            try
            {
                string directory =
                    Path.GetDirectoryName(
                        _persistencePath);

                if (!string.IsNullOrWhiteSpace(
                    directory) &&
                    !Directory.Exists(
                        directory))
                {
                    Directory.CreateDirectory(
                        directory);
                }

                string json =
                    JsonConvert.SerializeObject(
                        _violations.Values
                            .OrderBy(
                                x =>
                                    x.ViolationType.ToString())
                            .ThenBy(
                                x =>
                                    x.ModId ?? "",
                                StringComparer.OrdinalIgnoreCase)
                            .ThenBy(
                                x =>
                                    x.Path ?? "",
                                StringComparer.OrdinalIgnoreCase)
                            .ToList(),
                        Formatting.Indented);

                string temporary =
                    _persistencePath +
                    ".tmp";

                File.WriteAllText(
                    temporary,
                    json);

                if (File.Exists(
                    _persistencePath))
                {
                    try
                    {
                        File.Replace(
                            temporary,
                            _persistencePath,
                            null);
                    }
                    catch
                    {
                        File.Delete(
                            _persistencePath);

                        File.Move(
                            temporary,
                            _persistencePath);
                    }
                }
                else
                {
                    File.Move(
                        temporary,
                        _persistencePath);
                }
            }
            catch
            {
            }
        }

        private static string BuildKey(
            ObservedViolation violation)
        {
            return
                NormalizeOptional(
                    violation.ViolationType.ToString()) +
                "|" +
                NormalizeOptional(
                    violation.ModId) +
                "|" +
                NormalizeOptional(
                    violation.ArtifactId) +
                "|" +
                NormalizeOptional(
                    violation.Path) +
                "|" +
                NormalizeOptional(
                    violation.Sha256) +
                "|" +
                NormalizeOptional(
                    violation.AssemblyFullName);
        }

        private static void NormalizeViolation(
            ObservedViolation violation)
        {
            if (violation.SeenCount <= 0)
            {
                violation.SeenCount =
                    1;
            }

            violation.FirstSeenUtc =
                NormalizeUtc(
                    violation.FirstSeenUtc);

            violation.LastSeenUtc =
                NormalizeUtc(
                    violation.LastSeenUtc);

            if (string.IsNullOrWhiteSpace(
                    violation.FirstSessionId))
            {
                violation.FirstSessionId =
                    violation.SessionId;
            }

            if (string.IsNullOrWhiteSpace(
                    violation.LastSessionId))
            {
                violation.LastSessionId =
                    violation.SessionId;
            }

            if (violation.SessionCount <= 0)
            {
                violation.SessionCount =
                    1;
            }

            if (string.IsNullOrWhiteSpace(
                    violation.ObservationId))
            {
                violation.ObservationId =
                    Guid.NewGuid().ToString("N");
            }
        }

        private static DateTime NormalizeUtc(
            DateTime value)
        {
            if (value.Kind ==
                DateTimeKind.Utc)
            {
                return value;
            }

            return value.ToUniversalTime();
        }

        private static string NormalizeOptional(
            string value)
        {
            if (string.IsNullOrWhiteSpace(
                value))
            {
                return null;
            }

            return value.Trim();
        }

        private static string FirstNonEmpty(
            string first,
            string second)
        {
            if (!string.IsNullOrWhiteSpace(first))
            {
                return first.Trim();
            }

            if (!string.IsNullOrWhiteSpace(second))
            {
                return second.Trim();
            }

            return null;
        }

        private static string CopyIfPresent(
            string target,
            string source)
        {
            if (string.IsNullOrWhiteSpace(source))
            {
                return target;
            }

            return source.Trim();
        }

        private static ObservedViolation Clone(
            ObservedViolation source)
        {
            if (source == null)
            {
                return null;
            }

            return
                JsonConvert.DeserializeObject<ObservedViolation>(
                    JsonConvert.SerializeObject(
                        source));
        }

        private static IReadOnlyList<ObservedViolation> EmptyResult()
        {
            return new ReadOnlyCollection<ObservedViolation>(
                new List<ObservedViolation>());
        }
    }
}
