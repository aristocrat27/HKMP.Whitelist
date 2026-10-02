
using HKMP.Whitelist.Shared;
using SharedModPolicy = HKMP.Whitelist.Shared.ModPolicy;
using Satchel.BetterMenus;
using System;
using System.Collections.Generic;
using System.Linq;

namespace HKMP.Whitelist.UI
{
    public sealed class ModPolicyMenu
    {
        private readonly WhitelistMenu _root;

        private List<ModEntry> _mods =
            new List<ModEntry>();

        private enum PolicyFilter
        {
            All,
            Required,
            Allowed,
            Ignored,
            Forbidden
        }

        public ModPolicyMenu(
            WhitelistMenu root)
        {
            _root = root;
        }

        public void Open()
        {
            Refresh();

            int required =
                CountPolicy(
                    SharedModPolicy.Required);

            int allowed =
                CountPolicy(
                    SharedModPolicy.Allowed);

            int ignored =
                CountPolicy(
                    SharedModPolicy.Ignored);

            int forbidden =
                CountPolicy(
                    SharedModPolicy.Forbidden);

            _root.GoTo(
                new Menu(
                    "HKMP.Whitelist - Mod Policies",
                    new Element[]
                    {
                        new TextPanel(
                            "MOD POLICIES",
                            fontSize:
                                WhitelistUiStyle.Title),

                        new TextPanel(
                            "Total detected: " +
                            _mods.Count,
                            fontSize:
                                WhitelistUiStyle.Body),

                        new TextPanel(
                            "Required: " +
                            required +
                            "   Allowed: " +
                            allowed,
                            fontSize:
                                WhitelistUiStyle.Small),

                        new TextPanel(
                            "Ignored: " +
                            ignored +
                            "   Forbidden: " +
                            forbidden,
                            fontSize:
                                WhitelistUiStyle.Small),

                        new MenuButton(
                            "All",
                            "Show all detected mods",
                            delegate(
                                UnityEngine.UI.MenuButton button)
                            {
                                OpenCategory(
                                    PolicyFilter.All);
                            },
                            true,
                            "All"),

                        new MenuButton(
                            "Required",
                            required.ToString(),
                            delegate(
                                UnityEngine.UI.MenuButton button)
                            {
                                OpenCategory(
                                    PolicyFilter.Required);
                            },
                            true,
                            "Required"),

                        new MenuButton(
                            "Allowed",
                            allowed.ToString(),
                            delegate(
                                UnityEngine.UI.MenuButton button)
                            {
                                OpenCategory(
                                    PolicyFilter.Allowed);
                            },
                            true,
                            "Allowed"),

                        new MenuButton(
                            "Ignored",
                            ignored.ToString(),
                            delegate(
                                UnityEngine.UI.MenuButton button)
                            {
                                OpenCategory(
                                    PolicyFilter.Ignored);
                            },
                            true,
                            "Ignored"),

                        new MenuButton(
                            "Forbidden",
                            forbidden.ToString(),
                            delegate(
                                UnityEngine.UI.MenuButton button)
                            {
                                OpenCategory(
                                    PolicyFilter.Forbidden);
                            },
                            true,
                            "Forbidden"),

                        new MenuButton(
                            "Refresh",
                            "Rescan installed DLLs",
                            delegate(
                                UnityEngine.UI.MenuButton button)
                            {
                                Refresh();
                                Open();
                            },
                            false,
                            "Refresh")
                    }));
        }

        private void OpenCategory(
            PolicyFilter filter)
        {
            Refresh();

            List<ModEntry> selected =
                GetFiltered(
                    filter);

            List<Element> elements =
                new List<Element>();

            elements.Add(
                new TextPanel(
                    GetTitle(filter),
                    fontSize:
                        WhitelistUiStyle.Title));

            elements.Add(
                new TextPanel(
                    "Found: " +
                    selected.Count,
                    fontSize:
                        WhitelistUiStyle.Small));

            foreach (ModEntry mod in selected)
            {
                ModEntry captured =
                    mod;

                string state =
                    captured.IsDisabled
                        ? "DISABLED"
                        : "ACTIVE";

                string policy =
                    GetPolicyText(
                        captured,
                        GetPolicy(captured));

                elements.Add(
                    new MenuButton(
                        captured.Name,
                        "Version " +
                        captured.Version +
                        "  |  " +
                        state +
                        "  |  " +
                        policy,
                        delegate (
                            UnityEngine.UI.MenuButton button)
                        {
                            OpenDetails(
                                captured);
                        },
                        true,
                        "Mod_" +
                        SanitizeId(
                            captured.Name) +
                        "_" +
                        SanitizeId(
                            captured.Version)));
            }

            if (selected.Count == 0)
            {
                elements.Add(
                    new TextPanel(
                        "No mods are in this category.",
                        fontSize:
                            WhitelistUiStyle.Body));
            }

            _root.GoTo(
                new Menu(
                    "HKMP.Whitelist - " +
                    GetTitle(filter),
                    elements.ToArray()));
        }

        private void OpenDetails(
            ModEntry entry)
        {
            if (entry == null)
            {
                return;
            }

            SharedModPolicy current =
                GetPolicy(
                    entry);

            List<Element> elements =
                new List<Element>();

            elements.Add(
                new TextPanel(
                    entry.Name,
                    fontSize:
                        WhitelistUiStyle.Title));

            elements.Add(
                new TextPanel(
                    "Version " +
                    entry.Version +
                    "  |  " +
                    (
                        entry.IsDisabled
                            ? "DISABLED"
                            : "ACTIVE"
                    ),
                    fontSize:
                        WhitelistUiStyle.Body));

            elements.Add(
                new TextPanel(
                    "Policy: " +
                    GetPolicyText(
                        entry,
                        current),
                    fontSize:
                        WhitelistUiStyle.Body));

            elements.Add(
                new TextPanel(
                    "Mod ID",
                    fontSize:
                        WhitelistUiStyle.Small));

            elements.Add(
                new TextPanel(
                    GetModId(
                        entry),
                    fontSize:
                        WhitelistUiStyle.Small));

            elements.Add(
                new TextPanel(
                    "SHA-256",
                    fontSize:
                        WhitelistUiStyle.Small));

            elements.Add(
                new TextPanel(
                    string.IsNullOrEmpty(
                        entry.Hash)
                        ? "Unavailable"
                        : entry.Hash,
                    fontSize:
                        WhitelistUiStyle.Small));

            elements.Add(
                new TextPanel(
                    "FILE",
                    fontSize:
                        WhitelistUiStyle.Small));

            elements.Add(
                new TextPanel(
                    entry.FilePath,
                    fontSize:
                        WhitelistUiStyle.Small));

            elements.Add(
                new TextPanel(
                    "POLICY",
                    fontSize:
                        WhitelistUiStyle.Small));

            AddPolicyButton(
                elements,
                entry,
                SharedModPolicy.Required,
                "Required");

            AddPolicyButton(
                elements,
                entry,
                SharedModPolicy.Allowed,
                "Allowed");

            AddPolicyButton(
                elements,
                entry,
                SharedModPolicy.Ignored,
                "Ignored");

            AddPolicyButton(
                elements,
                entry,
                SharedModPolicy.Forbidden,
                "Forbidden");

            _root.GoTo(
                new Menu(
                    "HKMP.Whitelist - Mod",
                    elements.ToArray()));
        }

        private void AddPolicyButton(
            List<Element> elements,
            ModEntry entry,
            SharedModPolicy policy,
            string caption)
        {
            bool selected =
                GetPolicy(entry) ==
                policy;

            string text =
                selected
                    ? "✓ " +
                      caption
                    : caption;

            string description =
                selected &&
                policy == SharedModPolicy.Forbidden &&
                !ModPolicyResolver.IsExplicitForbidden(
                    PresetStore.GetEditingOrActive(),
                    GetModId(entry),
                    entry.Name)
                    ? "Currently forbidden by default"
                    : "Set policy to " +
                      caption.ToLowerInvariant();

            elements.Add(
                new MenuButton(
                    text,
                    description,
                    delegate (
                        UnityEngine.UI.MenuButton button)
                    {
                        SetPolicy(
                            entry,
                            policy);

                        _root.MarkDirty();

                        if (PresetStore.SaveEditing(
                                _root.ModDirectory,
                                _root))
                        {
                            PresetStore.NotifyPolicyChanged();
                        }

                        ModEntry updated =
                            FindMod(entry);

                        if (updated != null)
                        {
                            OpenDetails(updated);
                        }
                    },
                    !selected,
                    "Policy_" +
                    caption +
                    "_" +
                    SanitizeId(entry.Name)));
        }

        private void SetPolicy(
            ModEntry entry,
            SharedModPolicy policy)
        {
            if (entry == null)
            {
                return;
            }

            PresetConfig preset =
                PresetStore.GetEditingOrActive();

            if (preset == null)
            {
                return;
            }

            ModPolicyResolver.SetPolicy(
                preset,
                GetModId(entry),
                policy,
                entry.Name);
        }

        private SharedModPolicy GetPolicy(
            ModEntry entry)
        {
            if (entry == null)
            {
                return SharedModPolicy.Forbidden;
            }

            return
                ModPolicyResolver.Resolve(
                    PresetStore.GetEditingOrActive(),
                    GetModId(entry),
                    entry.Name);
        }

        private List<ModEntry> GetFiltered(
            PolicyFilter filter)
        {
            IEnumerable<ModEntry> query =
                _mods;

            switch (filter)
            {
                case PolicyFilter.Required:
                    query =
                        query.Where(
                            x =>
                                GetPolicy(x) ==
                                SharedModPolicy.Required);
                    break;

                case PolicyFilter.Allowed:
                    query =
                        query.Where(
                            x =>
                                GetPolicy(x) ==
                                SharedModPolicy.Allowed);
                    break;

                case PolicyFilter.Ignored:
                    query =
                        query.Where(
                            x =>
                                GetPolicy(x) ==
                                SharedModPolicy.Ignored);
                    break;

                case PolicyFilter.Forbidden:
                    query =
                        query.Where(
                            x =>
                                GetPolicy(x) ==
                                SharedModPolicy.Forbidden);
                    break;

                case PolicyFilter.All:
                default:
                    break;
            }

            return
                query
                    .OrderBy(
                        x =>
                            x.Name,
                        StringComparer.OrdinalIgnoreCase)
                    .ThenBy(
                        x =>
                            x.Version,
                        StringComparer.OrdinalIgnoreCase)
                    .ToList();
        }

        private int CountPolicy(
            SharedModPolicy policy)
        {
            return
                _mods.Count(
                    x =>
                        GetPolicy(x) ==
                        policy);
        }

        private ModEntry FindMod(
            ModEntry entry)
        {
            if (entry == null)
            {
                return null;
            }

            string hash =
                entry.Hash;

            if (!string.IsNullOrWhiteSpace(hash))
            {
                ModEntry byHash =
                    _mods.FirstOrDefault(
                        x =>
                            string.Equals(
                                x.Hash,
                                hash,
                                StringComparison.OrdinalIgnoreCase));

                if (byHash != null)
                {
                    return byHash;
                }
            }

            return
                _mods.FirstOrDefault(
                    x =>
                        string.Equals(
                            x.Name,
                            entry.Name,
                            StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(
                            x.Version,
                            entry.Version,
                            StringComparison.OrdinalIgnoreCase));
        }

        private void Refresh()
        {
            _mods =
                ModScanner.GetMods();
        }

        private string GetModId(
            ModEntry entry)
        {
            if (entry == null)
            {
                return "UnknownMod";
            }

            if (!string.IsNullOrWhiteSpace(entry.ModId))
            {
                return entry.ModId;
            }

            return
                string.IsNullOrWhiteSpace(entry.Name)
                    ? "UnknownMod"
                    : entry.Name;
        }

        private string GetPolicyText(
            ModEntry entry,
            SharedModPolicy policy)
        {
            if (policy == SharedModPolicy.Forbidden &&
                !ModPolicyResolver.IsExplicitForbidden(
                    PresetStore.GetEditingOrActive(),
                    GetModId(entry),
                    entry == null ? null : entry.Name))
            {
                return "FORBIDDEN BY DEFAULT";
            }

            switch (policy)
            {
                case SharedModPolicy.Required:
                    return "REQUIRED";

                case SharedModPolicy.Allowed:
                    return "ALLOWED";

                case SharedModPolicy.Ignored:
                    return "IGNORED";

                case SharedModPolicy.Forbidden:
                default:
                    return "FORBIDDEN";
            }
        }

        private static string GetTitle(
            PolicyFilter filter)
        {
            switch (filter)
            {
                case PolicyFilter.Required:
                    return "REQUIRED MODS";

                case PolicyFilter.Allowed:
                    return "ALLOWED MODS";

                case PolicyFilter.Ignored:
                    return "IGNORED MODS";

                case PolicyFilter.Forbidden:
                    return "FORBIDDEN MODS";

                case PolicyFilter.All:
                default:
                    return "ALL MODS";
            }
        }

        private static string SanitizeId(
            string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return "Unknown";
            }

            char[] chars =
                value.ToCharArray();

            for (int i = 0;
                 i < chars.Length;
                 i++)
            {
                if (!char.IsLetterOrDigit(
                        chars[i]))
                {
                    chars[i] =
                        '_';
                }
            }

            return
                new string(chars);
        }
    }
}
