using HKMP.Whitelist.Shared;
using Newtonsoft.Json;
using Satchel.BetterMenus;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using BetterMenuButton = Satchel.BetterMenus.MenuButton;
using UnityInputField = UnityEngine.UI.InputField;

namespace HKMP.Whitelist.UI
{
    public sealed class PresetMenu
    {
        private readonly WhitelistMenu _root;

        private Menu _menu;
        private MenuScreen _parent;

        private UnityInputField _searchField;
        private UnityInputField _createField;

        private readonly BetterMenuButton[] _slots =
            new BetterMenuButton[
                WhitelistUiStyle.PresetPageSize];

        private List<PresetItem> _all =
            new List<PresetItem>();

        private List<PresetItem> _filtered =
            new List<PresetItem>();

        private int _page;

        private string _query =
            "";

        private BetterMenuButton _previous;
        private BetterMenuButton _next;
        private TextPanel _resultText;
        private TextPanel _pageText;

        private PresetItem _selected;

        public PresetMenu(
            WhitelistMenu root)
        {
            _root = root;
        }

        public void Open(
            MenuScreen parent)
        {
            _parent =
                parent;

            EnsureMenu();

            LoadPresets();

            ApplyFilter(
                false);

            _root.GoTo(
                _menu,
                _parent);
        }

        private void EnsureMenu()
        {
            if (_menu != null)
            {
                return;
            }

            List<Element> elements =
                new List<Element>();

            elements.Add(
                new TextPanel(
                    "PROFILES",
                    fontSize:
                        WhitelistUiStyle.Title,
                    Id:
                        "Title"));

            StaticPanel search =
                new StaticPanel(
                    "Search",
                    delegate (
                        UnityEngine.GameObject panel)
                    {
                        _searchField =
                            WhitelistUiFactory.CreateSearchField(
                                panel,
                                "Search profiles...",
                                OnSearchChanged);
                    },
                    WhitelistUiStyle.StaticWidth,
                    "SearchPanel");

            elements.Add(
                search);

            StaticPanel create =
                new StaticPanel(
                    "Create",
                    delegate (
                        UnityEngine.GameObject panel)
                    {
                        _createField =
                            WhitelistUiFactory.CreateSearchField(
                                panel,
                                "New profile name...",
                                null);
                    },
                    WhitelistUiStyle.StaticWidth,
                    "CreatePanel");

            elements.Add(
                create);

            elements.Add(
                new BetterMenuButton(
                    "+",
                    "Create a new deny-by-default profile",
                    delegate (
                        UnityEngine.UI.MenuButton button)
                    {
                        CreateFromName();
                    },
                    false,
                    "CreateButton"));

            _resultText =
                new TextPanel(
                    "",
                    fontSize:
                        WhitelistUiStyle.Body,
                    Id:
                        "ResultText");

            elements.Add(
                _resultText);

            for (int i = 0;
                 i < _slots.Length;
                 i++)
            {
                int index =
                    i;

                BetterMenuButton slot =
                    new BetterMenuButton(
                        "",
                        "",
                        delegate (
                            UnityEngine.UI.MenuButton button)
                        {
                            OpenSlot(index);
                        },
                        true,
                        "PresetSlot_" +
                        i);

                slot.isVisible =
                    false;

                _slots[i] =
                    slot;

                elements.Add(
                    slot);
            }

            _pageText =
                new TextPanel(
                    "",
                    fontSize:
                        WhitelistUiStyle.Body,
                    Id:
                        "Page");

            _previous =
                new BetterMenuButton(
                    "←",
                    "Previous page",
                    delegate (
                        UnityEngine.UI.MenuButton button)
                    {
                        if (_page > 0)
                        {
                            _page--;
                            UpdateResults();
                        }
                    },
                    false,
                    "Previous");

            _next =
                new BetterMenuButton(
                    "→",
                    "Next page",
                    delegate (
                        UnityEngine.UI.MenuButton button)
                    {
                        if (_page + 1 <
                            GetPageCount())
                        {
                            _page++;
                            UpdateResults();
                        }
                    },
                    false,
                    "Next");

            elements.Add(
                new MenuRow(
                    new List<Element>
                    {
                        _previous,
                        _pageText,
                        _next
                    },
                    "Navigation"));

            elements.Add(
                new BetterMenuButton(
                    "Refresh",
                    "Reload profile files",
                    delegate (
                        UnityEngine.UI.MenuButton button)
                    {
                        LoadPresets();
                        ApplyFilter(true);
                    },
                    false,
                    "Refresh"));

            _menu =
                new Menu(
                    "HKMP.Whitelist - Profiles",
                    elements.ToArray());
        }

        private void OnSearchChanged(
            string value)
        {
            _query =
                value ?? "";

            _page =
                0;

            ApplyFilter(
                true);
        }

        private void ApplyFilter(
            bool update)
        {
            string query =
                (_query ?? "").Trim();

            if (string.IsNullOrEmpty(query))
            {
                _filtered =
                    new List<PresetItem>(
                        _all);
            }
            else
            {
                _filtered =
                    _all
                        .Where(
                            x =>
                                x.Name.IndexOf(
                                    query,
                                    StringComparison.OrdinalIgnoreCase) >=
                                0)
                        .ToList();
            }

            UpdateResults(
                update);
        }

        private void UpdateResults(
            bool update = true)
        {
            int pages =
                GetPageCount();

            if (_page >= pages)
            {
                _page =
                    Math.Max(
                        0,
                        pages - 1);
            }

            int start =
                _page *
                _slots.Length;

            for (int i = 0;
                 i < _slots.Length;
                 i++)
            {
                int index =
                    start + i;

                BetterMenuButton slot =
                    _slots[i];

                if (index >=
                    _filtered.Count)
                {
                    slot.isVisible =
                        false;

                    continue;
                }

                PresetItem item =
                    _filtered[index];

                slot.Name =
                    item.Name;

                bool isActive =
                    string.Equals(
                        item.Name,
                        PresetStore.GetActivePresetName(),
                        StringComparison.OrdinalIgnoreCase);

                slot.Description =
                    isActive
                        ? "Active profile"
                        : "Open profile";

                slot.isVisible =
                    true;
            }

            if (_resultText != null)
            {
                _resultText.Name =
                    "Found: " +
                    _filtered.Count;
            }

            if (_pageText != null)
            {
                _pageText.Name =
                    pages <= 1
                        ? " "
                        : "Page " +
                          (_page + 1) +
                          " / " +
                          pages;
            }

            if (_previous != null)
            {
                _previous.isVisible =
                    _page > 0;
            }

            if (_next != null)
            {
                _next.isVisible =
                    pages > 0 &&
                    _page + 1 <
                    pages;
            }

            if (update &&
                _menu != null)
            {
                _menu.Update();
            }
        }

        private void OpenSlot(
            int slot)
        {
            int index =
                _page *
                _slots.Length +
                slot;

            if (index < 0 ||
                index >= _filtered.Count)
            {
                return;
            }

            _selected =
                _filtered[index];

            OpenDetails(
                _selected);
        }

        private void OpenDetails(
            PresetItem item)
        {
            if (item == null)
            {
                return;
            }

            PresetConfig preset =
                LoadPreset(
                    item.Name);

            if (preset == null)
            {
                return;
            }

            PresetStore.SetEditing(
                preset,
                item.Name);

            bool isActive =
                string.Equals(
                    item.Name,
                    PresetStore.GetActivePresetName(),
                    StringComparison.OrdinalIgnoreCase);

            Menu menu = null;

            menu =
                new Menu(
                    "HKMP.Whitelist - Profile",
                    new Element[]
                    {
                        new TextPanel(
                            item.Name,
                            fontSize:
                                WhitelistUiStyle.PresetTitle),

                        new TextPanel(
                            isActive
                                ? "Active profile"
                                : "Profile not activated",
                            fontSize:
                                WhitelistUiStyle.PresetSubtitle),

                        new BetterMenuButton(
                            isActive
                                ? "Active"
                                : "Activate",
                            isActive
                                ? "This profile is currently active"
                                : "Make this profile active",
                            delegate(
                                UnityEngine.UI.MenuButton button)
                            {
                                Activate(
                                    item.Name);
                            },
                            !isActive,
                            "Activate"),

                        new BetterMenuButton(
                            "SECURITY",
                            "Configure security settings",
                            delegate(
                                UnityEngine.UI.MenuButton button)
                            {
                                _root.OpenSecurity(
                                    menu.menuScreen);
                            },
                            true,
                            "Security"),

                        new BetterMenuButton(
                            "MODS",
                            "Configure mod policies",
                            delegate(
                                UnityEngine.UI.MenuButton button)
                            {
                                _root.OpenMods(
                                    menu.menuScreen);
                            },
                            true,
                            "Mods"),

                        new BetterMenuButton(
                            "Copy",
                            "Create a copy of this profile",
                            delegate(
                                UnityEngine.UI.MenuButton button)
                            {
                                Duplicate(
                                    item.Name);
                            },
                            false,
                            "Duplicate"),

                        new BetterMenuButton(
                            "Deactivate",
                            "Clear the active profile",
                            delegate(
                                UnityEngine.UI.MenuButton button)
                            {
                                ClearActive();
                            },
                            isActive,
                            "ClearActive"),

                        new BetterMenuButton(
                            "Delete",
                            "Delete this profile",
                            delegate(
                                UnityEngine.UI.MenuButton button)
                            {
                                Delete(
                                    item.Name);
                            },
                            false,
                            "Delete")
                    });

            _root.GoTo(
                menu,
                _menu.menuScreen);
        }

        private void Activate(
            string name)
        {
            if (!PresetStore.BeginEditing(
                    name))
            {
                return;
            }

            PresetStore.ActivateEditing(
                name,
                _root.ModDirectory,
                _root);

            Open(
                _parent);
        }

        private void ClearActive()
        {
            PresetStore.ClearActive(
                _root.ModDirectory,
                _root);

            PresetStore.ClearEditing();

            Open(
                _parent);
        }

        private void CreateFromName()
        {
            if (_createField == null)
            {
                return;
            }

            string name =
                (_createField.text ?? "").Trim();

            if (string.IsNullOrEmpty(name))
            {
                return;
            }

            string unique =
                CreateUniqueName(
                    name);

            PresetConfig preset =
                PresetStore.CreateDefaultPreset(
                    unique);

            SavePreset(
                preset,
                unique);

            PresetStore.SetEditing(
                preset,
                unique);

            PresetStore.ActivateEditing(
                unique,
                _root.ModDirectory,
                _root);

            _createField.text =
                "";

            LoadPresets();

            _root.OpenSecurity(
                _menu.menuScreen);
        }

        private void Duplicate(
            string sourceName)
        {
            PresetConfig source =
                LoadPreset(
                    sourceName);

            if (source == null)
            {
                return;
            }

            string name =
                CreateUniqueName(
                    sourceName +
                    " Copy");

            PresetConfig copy =
                Clone(
                    source);

            copy.PresetName =
                name;

            SavePreset(
                copy,
                name);

            LoadPresets();

            Open(
                _parent);
        }

        private void Delete(
            string name)
        {
            if (string.Equals(
                name,
                PresetStore.GetActivePresetName(),
                StringComparison.OrdinalIgnoreCase))
            {
                PresetStore.ClearActive(
                    _root.ModDirectory,
                    _root);
            }

            PresetStore.ClearEditing();

            string path =
                GetPresetPath(
                    name);

            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch (Exception ex)
            {
                Modding.Logger.LogError(
                    "[Whitelist] Failed to delete profile:\n" +
                    ex);
            }

            LoadPresets();

            Open(
                _parent);
        }

        private PresetConfig LoadPreset(
            string name)
        {
            string path =
                GetPresetPath(
                    name);

            try
            {
                if (!File.Exists(path))
                {
                    return null;
                }

                PresetConfig preset =
                    JsonConvert.DeserializeObject<PresetConfig>(
                        File.ReadAllText(path));

                if (preset != null)
                {
                    preset.PresetName =
                        name;
                }

                return preset;
            }
            catch
            {
                return null;
            }
        }

        private void SavePreset(
            PresetConfig preset,
            string name)
        {
            if (preset == null ||
                string.IsNullOrWhiteSpace(name))
            {
                return;
            }

            try
            {
                File.WriteAllText(
                    GetPresetPath(
                        name),
                    JsonConvert.SerializeObject(
                        preset,
                        Formatting.Indented));
            }
            catch (Exception ex)
            {
                Modding.Logger.LogError(
                    "[Whitelist] Failed to save profile:\n" +
                    ex);
            }
        }

        private void LoadPresets()
        {
            _all.Clear();

            string directory =
                Path.Combine(
                    _root.ModDirectory,
                    "presets");

            Directory.CreateDirectory(
                directory);

            foreach (string file in
                     Directory.GetFiles(
                         directory,
                         "*.json",
                         SearchOption.TopDirectoryOnly))
            {
                try
                {
                    PresetConfig preset =
                        JsonConvert.DeserializeObject<PresetConfig>(
                            File.ReadAllText(file));

                    string name =
                        preset == null ||
                        string.IsNullOrWhiteSpace(
                            preset.PresetName)
                            ? Path.GetFileNameWithoutExtension(
                                file)
                            : preset.PresetName;

                    if (!string.IsNullOrWhiteSpace(name))
                    {
                        _all.Add(
                            new PresetItem
                            {
                                Name = name
                            });
                    }
                }
                catch
                {
                    string name =
                        Path.GetFileNameWithoutExtension(
                            file);

                    if (!string.IsNullOrWhiteSpace(name))
                    {
                        _all.Add(
                            new PresetItem
                            {
                                Name = name
                            });
                    }
                }
            }

            _all =
                _all
                    .GroupBy(
                        x =>
                            x.Name,
                        StringComparer.OrdinalIgnoreCase)
                    .Select(
                        x =>
                            x.First())
                    .OrderBy(
                        x =>
                            !string.Equals(
                                x.Name,
                                PresetStore.GetActivePresetName(),
                                StringComparison.OrdinalIgnoreCase))
                    .ThenBy(
                        x =>
                            x.Name,
                        StringComparer.OrdinalIgnoreCase)
                    .ToList();
        }

        private string CreateUniqueName(
            string baseName)
        {
            string candidate =
                baseName;

            int number =
                2;

            while (
                File.Exists(
                    GetPresetPath(
                        candidate)))
            {
                candidate =
                    baseName +
                    " " +
                    number;

                number++;
            }

            return candidate;
        }

        private int GetPageCount()
        {
            if (_filtered.Count == 0)
            {
                return 0;
            }

            return
                (
                    _filtered.Count +
                    _slots.Length -
                    1) /
                _slots.Length;
        }

        private string GetPresetPath(
            string name)
        {
            string directory =
                Path.Combine(
                    _root.ModDirectory,
                    "presets");

            Directory.CreateDirectory(
                directory);

            return
                Path.Combine(
                    directory,
                    PresetStore.SanitizeFileName(
                        name) +
                    ".json");
        }

        private static PresetConfig Clone(
            PresetConfig source)
        {
            if (source == null)
            {
                return null;
            }

            PresetConfig clone =
                JsonConvert.DeserializeObject<PresetConfig>(
                    JsonConvert.SerializeObject(
                        source));

            if (clone == null)
            {
                clone =
                    PresetStore.CreateDefaultPreset(
                        source.PresetName);
            }

            return clone;
        }

        private sealed class PresetItem
        {
            public string Name;
        }
    }
}