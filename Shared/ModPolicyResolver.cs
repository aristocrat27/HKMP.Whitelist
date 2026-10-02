using System;
using System.Collections.Generic;
using System.Linq;

namespace HKMP.Whitelist.Shared
{
    public static class ModPolicyResolver
    {
        public static ModPolicy Resolve(
            PresetConfig preset,
            string modId,
            string fallbackIdentity = null)
        {
            if (preset == null)
            {
                return ModPolicy.Forbidden;
            }

            EnsureLists(preset);

            if (Contains(preset.RequiredMods, modId) ||
                Contains(preset.RequiredMods, fallbackIdentity))
            {
                return ModPolicy.Required;
            }

            if (Contains(preset.AllowedMods, modId) ||
                Contains(preset.AllowedMods, fallbackIdentity))
            {
                return ModPolicy.Allowed;
            }

            if (Contains(preset.IgnoredMods, modId) ||
                Contains(preset.IgnoredMods, fallbackIdentity))
            {
                return ModPolicy.Ignored;
            }

            if (Contains(preset.ForbiddenMods, modId) ||
                Contains(preset.ForbiddenMods, fallbackIdentity))
            {
                return ModPolicy.Forbidden;
            }

            return ModPolicy.Forbidden;
        }

        public static bool IsExplicit(
            PresetConfig preset,
            string modId,
            string fallbackIdentity = null)
        {
            if (preset == null)
            {
                return false;
            }

            EnsureLists(preset);

            return
                Contains(preset.RequiredMods, modId) ||
                Contains(preset.RequiredMods, fallbackIdentity) ||
                Contains(preset.AllowedMods, modId) ||
                Contains(preset.AllowedMods, fallbackIdentity) ||
                Contains(preset.IgnoredMods, modId) ||
                Contains(preset.IgnoredMods, fallbackIdentity) ||
                Contains(preset.ForbiddenMods, modId) ||
                Contains(preset.ForbiddenMods, fallbackIdentity);
        }

        public static bool IsExplicitForbidden(
            PresetConfig preset,
            string modId,
            string fallbackIdentity = null)
        {
            if (preset == null)
            {
                return false;
            }

            EnsureLists(preset);

            return
                Contains(preset.ForbiddenMods, modId) ||
                Contains(preset.ForbiddenMods, fallbackIdentity);
        }

        public static void SetPolicy(
            PresetConfig preset,
            string modId,
            ModPolicy policy,
            string fallbackIdentity = null)
        {
            if (preset == null)
            {
                return;
            }

            EnsureLists(preset);

            RemoveFromAllLists(
                preset,
                modId,
                fallbackIdentity);

            string identity =
                FirstNonEmpty(
                    modId,
                    fallbackIdentity);

            if (string.IsNullOrWhiteSpace(identity))
            {
                Normalize(preset);
                return;
            }

            switch (policy)
            {
                case ModPolicy.Required:
                    preset.RequiredMods.Add(identity);
                    break;

                case ModPolicy.Allowed:
                    preset.AllowedMods.Add(identity);
                    break;

                case ModPolicy.Ignored:
                    preset.IgnoredMods.Add(identity);
                    break;

                case ModPolicy.Forbidden:
                    preset.ForbiddenMods.Add(identity);
                    break;
            }

            Normalize(preset);
        }

        public static void Normalize(
            PresetConfig preset)
        {
            if (preset == null)
            {
                return;
            }

            EnsureLists(preset);

            preset.RequiredMods =
                NormalizeList(preset.RequiredMods);

            preset.AllowedMods =
                NormalizeList(preset.AllowedMods);

            preset.IgnoredMods =
                NormalizeList(preset.IgnoredMods);

            preset.ForbiddenMods =
                NormalizeList(preset.ForbiddenMods);

            HashSet<string> claimed =
                new HashSet<string>(
                    StringComparer.OrdinalIgnoreCase);

            preset.RequiredMods =
                KeepUnclaimed(
                    preset.RequiredMods,
                    claimed);

            preset.AllowedMods =
                KeepUnclaimed(
                    preset.AllowedMods,
                    claimed);

            preset.IgnoredMods =
                KeepUnclaimed(
                    preset.IgnoredMods,
                    claimed);

            preset.ForbiddenMods =
                KeepUnclaimed(
                    preset.ForbiddenMods,
                    claimed);
        }

        private static List<string> KeepUnclaimed(
            IEnumerable<string> source,
            HashSet<string> claimed)
        {
            List<string> result =
                new List<string>();

            foreach (string value in source)
            {
                if (claimed.Add(value))
                {
                    result.Add(value);
                }
            }

            return result;
        }

        private static List<string> NormalizeList(
            IEnumerable<string> source)
        {
            return
                (source ?? Enumerable.Empty<string>())
                .Where(
                    value => !string.IsNullOrWhiteSpace(value))
                .Select(
                    value => value.Trim())
                .Distinct(
                    StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private static void RemoveFromAllLists(
            PresetConfig preset,
            string firstIdentity,
            string secondIdentity)
        {
            Remove(preset.RequiredMods, firstIdentity);
            Remove(preset.AllowedMods, firstIdentity);
            Remove(preset.IgnoredMods, firstIdentity);
            Remove(preset.ForbiddenMods, firstIdentity);

            if (!string.Equals(
                    firstIdentity,
                    secondIdentity,
                    StringComparison.OrdinalIgnoreCase))
            {
                Remove(preset.RequiredMods, secondIdentity);
                Remove(preset.AllowedMods, secondIdentity);
                Remove(preset.IgnoredMods, secondIdentity);
                Remove(preset.ForbiddenMods, secondIdentity);
            }
        }

        private static void Remove(
            List<string> list,
            string value)
        {
            if (list == null ||
                string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            list.RemoveAll(
                item =>
                    string.Equals(
                        item,
                        value,
                        StringComparison.OrdinalIgnoreCase));
        }

        private static bool Contains(
            List<string> list,
            string value)
        {
            return
                list != null &&
                !string.IsNullOrWhiteSpace(value) &&
                list.Any(
                    item =>
                        string.Equals(
                            item,
                            value,
                            StringComparison.OrdinalIgnoreCase));
        }

        private static string FirstNonEmpty(
            string first,
            string second)
        {
            if (!string.IsNullOrWhiteSpace(first))
            {
                return first.Trim();
            }

            return
                string.IsNullOrWhiteSpace(second)
                    ? null
                    : second.Trim();
        }

        private static void EnsureLists(
            PresetConfig preset)
        {
            if (preset.RequiredMods == null)
            {
                preset.RequiredMods = new List<string>();
            }

            if (preset.AllowedMods == null)
            {
                preset.AllowedMods = new List<string>();
            }

            if (preset.IgnoredMods == null)
            {
                preset.IgnoredMods = new List<string>();
            }

            if (preset.ForbiddenMods == null)
            {
                preset.ForbiddenMods = new List<string>();
            }
        }
    }
}
