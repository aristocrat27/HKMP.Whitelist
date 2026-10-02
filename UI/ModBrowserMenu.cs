using HKMP.Whitelist.Shared;
using SharedModPolicy = HKMP.Whitelist.Shared.ModPolicy;
using Satchel.BetterMenus;
using System;
using System.Collections.Generic;
using System.Linq;
using BetterMenuButton = Satchel.BetterMenus.MenuButton;
using UnityInputField = UnityEngine.UI.InputField;

namespace HKMP.Whitelist.UI
{
    public sealed class ModBrowserMenu
    {
        private readonly WhitelistMenu _root;
        private readonly ModDetailsMenu _details;

        private Menu _menu;
        private MenuScreen _parentScreen;
        private UnityInputField _searchField;

        private List<ModEntry> _allMods =
            new List<ModEntry>();

        private List<ModEntry> _filteredMods =
            new List<ModEntry>();

        private ModRuleFilter _filter =
            ModRuleFilter.All;

        private string _query = "";
        private int _page;

        private const string Prefix = "ModSlot_";

        private readonly BetterMenuButton[] _slots =
            new BetterMenuButton[WhitelistUiStyle.ModPageSize];

        private TextPanel _resultCount;
        private TextPanel _pageText;
        private BetterMenuButton _previous;
        private BetterMenuButton _next;

        public ModBrowserMenu(
            WhitelistMenu root)
        {
            _root = root;
            _details =
                new ModDetailsMenu(
                    root);

            PresetStore.PolicyChanged +=
                OnPolicyChanged;
        }

        private void OnPolicyChanged()
        {
            if (_menu == null)
            {
                return;
            }

            try
            {
                RefreshPolicyView();
            }
            catch (Exception ex)
            {
                Modding.Logger.LogError(
                    "[Whitelist] Failed to refresh mod policy view: " +
                    ex);
            }
        }

        public void Open(
            MenuScreen parent)
        {
            _parentScreen =
                parent;

            _menu =
                null;

            _searchField =
                null;

            EnsureMenu();

            try
            {
                _root.GoTo(
                    _menu,
                    _parentScreen);
            }
            catch (Exception ex)
            {
                Modding.Logger.LogError(
                    "[Whitelist] Failed to open Mods menu: " +
                    ex);

                return;
            }

            try
            {
                Refresh();
            }
            catch (Exception ex)
            {
                Modding.Logger.LogError(
                    "[Whitelist] Failed to refresh Mods menu: " +
                    ex);

                _allMods =
                    new List<ModEntry>();

                _filteredMods =
                    new List<ModEntry>();

                UpdateResults(
                    true);
            }
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
                    "MODS",
                    fontSize: WhitelistUiStyle.Title,
                    Id: "ModsTitle"));

            StaticPanel searchPanel =
                new StaticPanel(
                    "Search",
                    delegate (UnityEngine.GameObject panel)
                    {
                        _searchField =
                            WhitelistUiFactory.CreateSearchField(
                                panel,
                                "Search loaded mods...",
                                OnSearchChanged);
                    },
                    WhitelistUiStyle.StaticWidth,
                    "SearchPanel");

            elements.Add(searchPanel);

            elements.Add(
                new HorizontalOption(
                    "Show",
                    "Filter loaded mods by policy",
                    new[]
                    {
                        "All",
                        "Required",
                        "Allowed",
                        "Ignored",
                        "Forbidden"
                    },
                    OnFilterChanged,
                    GetFilterIndex,
                    "StatusFilter"));

            _resultCount =
                new TextPanel(
                    "",
                    fontSize: WhitelistUiStyle.Body,
                    Id: "ResultCount");

            elements.Add(_resultCount);

            for (int i = 0; i < _slots.Length; i++)
            {
                int index = i;

                BetterMenuButton slot =
                    new BetterMenuButton(
                        "",
                        "",
                        delegate (UnityEngine.UI.MenuButton button)
                        {
                            OpenSlot(index);
                        },
                        true,
                        Prefix + i);

                slot.isVisible = false;
                _slots[i] = slot;
                elements.Add(slot);
            }

            TextPanel noResults =
                new TextPanel(
                    "Nothing found.",
                    fontSize: WhitelistUiStyle.Body,
                    Id: "NoResults");

            noResults.isVisible = false;
            elements.Add(noResults);

            _pageText =
                new TextPanel(
                    "",
                    fontSize: WhitelistUiStyle.Body,
                    Id: "Page");

            _previous =
                new BetterMenuButton(
                    "←",
                    "Previous page",
                    delegate (UnityEngine.UI.MenuButton button)
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
                    delegate (UnityEngine.UI.MenuButton button)
                    {
                        int pageCount = GetPageCount();

                        if (_page + 1 < pageCount)
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
                    "Refresh loaded game mods",
                    delegate (UnityEngine.UI.MenuButton button)
                    {
                        Refresh();
                    },
                    false,
                    "Refresh"));

            _menu =
                new Menu(
                    "HKMP.Whitelist - Mods",
                    elements.ToArray());
        }

        private void OnSearchChanged(string value)
        {
            _query = value ?? "";
            _page = 0;
            ApplyFilter(true);
        }

        private void OnFilterChanged(int value)
        {
            switch (value)
            {
                case 1:
                    _filter = ModRuleFilter.Required;
                    break;

                case 2:
                    _filter = ModRuleFilter.Allowed;
                    break;

                case 3:
                    _filter = ModRuleFilter.Ignored;
                    break;

                case 4:
                    _filter = ModRuleFilter.Forbidden;
                    break;

                default:
                    _filter = ModRuleFilter.All;
                    break;
            }

            _page = 0;
            ApplyFilter(true);
        }

        private int GetFilterIndex()
        {
            switch (_filter)
            {
                case ModRuleFilter.Required:
                    return 1;

                case ModRuleFilter.Allowed:
                    return 2;

                case ModRuleFilter.Ignored:
                    return 3;

                case ModRuleFilter.Forbidden:
                    return 4;

                default:
                    return 0;
            }
        }

        private void ApplyFilter(bool updateMenu)
        {
            if (_allMods == null)
            {
                _allMods = ModScanner.GetMods();
            }

            PresetConfig preset =
                PresetStore.GetEditingOrActive();

            IEnumerable<ModEntry> query = _allMods;

            switch (_filter)
            {
                case ModRuleFilter.Required:
                    query = query.Where(
                        x =>
                            ResolvePolicy(preset, x) ==
                            SharedModPolicy.Required);
                    break;

                case ModRuleFilter.Allowed:
                    query = query.Where(
                        x =>
                            ResolvePolicy(preset, x) ==
                            SharedModPolicy.Allowed);
                    break;

                case ModRuleFilter.Ignored:
                    query = query.Where(
                        x =>
                            ResolvePolicy(preset, x) ==
                            SharedModPolicy.Ignored);
                    break;

                case ModRuleFilter.Forbidden:
                    query = query.Where(
                        x =>
                            ResolvePolicy(preset, x) ==
                            SharedModPolicy.Forbidden);
                    break;
            }

            if (!string.IsNullOrWhiteSpace(_query))
            {
                string normalized = _query.Trim();

                query = query.Where(
                    x =>
                        ContainsIgnoreCase(x.Name, normalized) ||
                        ContainsIgnoreCase(x.ModId, normalized) ||
                        ContainsIgnoreCase(x.AssemblyFullName, normalized) ||
                        ContainsIgnoreCase(x.Version, normalized));
            }

            _filteredMods =
                query
                    .OrderBy(
                        x => x.Name,
                        StringComparer.OrdinalIgnoreCase)
                    .ThenBy(
                        x => x.Version,
                        StringComparer.OrdinalIgnoreCase)
                    .ToList();

            UpdateResults(updateMenu);
        }

        private void UpdateResults(bool updateMenu = true)
        {
            int pageCount = GetPageCount();

            if (_page >= pageCount)
            {
                _page = Math.Max(0, pageCount - 1);
            }

            int start =
                _page * _slots.Length;

            for (int i = 0; i < _slots.Length; i++)
            {
                int itemIndex = start + i;
                BetterMenuButton button = _slots[i];

                if (itemIndex >= _filteredMods.Count)
                {
                    button.isVisible = false;
                    continue;
                }

                ModEntry mod = _filteredMods[itemIndex];

                button.Name = mod.Name ?? "Unknown";
                button.Description =
                    "Version " +
                    (mod.Version ?? "?") +
                    "  ·  LOADED  ·  " +
                    GetPolicyName(mod);
                button.isVisible = true;
            }

            if (_resultCount != null)
            {
                _resultCount.Name =
                    "Loaded mods: " +
                    _filteredMods.Count;
            }

            if (_pageText != null)
            {
                _pageText.Name =
                    pageCount <= 1
                        ? " "
                        : "Page " +
                          (_page + 1) +
                          " / " +
                          pageCount;
            }

            if (_previous != null)
            {
                _previous.isVisible = _page > 0;
            }

            if (_next != null)
            {
                _next.isVisible =
                    pageCount > 0 &&
                    _page + 1 < pageCount;
            }

            Element empty =
                _menu == null
                    ? null
                    : _menu.Find("NoResults");

            if (empty != null)
            {
                empty.isVisible =
                    _filteredMods.Count == 0;
            }

            if (updateMenu && _menu != null)
            {
                _menu.Update();
            }
        }

        private void OpenSlot(int slot)
        {
            int index =
                _page * _slots.Length + slot;

            if (index < 0 ||
                index >= _filteredMods.Count)
            {
                return;
            }

            _details.Open(
                _filteredMods[index],
                _menu.menuScreen);
        }

        private void Refresh()
        {
            try
            {
                _allMods =
                    ModScanner.Refresh();
            }
            catch (Exception ex)
            {
                Modding.Logger.LogError(
                    "[Whitelist] Mod scan failed: " +
                    ex);

                _allMods =
                    new List<ModEntry>();
            }

            _page =
                0;

            ApplyFilter(
                true);
        }

        private void RefreshPolicyView()
        {
            ApplyFilter(true);
        }

        private int GetPageCount()
        {
            if (_filteredMods == null ||
                _filteredMods.Count == 0)
            {
                return 0;
            }

            return
                (_filteredMods.Count + _slots.Length - 1) /
                _slots.Length;
        }

        private static SharedModPolicy ResolvePolicy(
            PresetConfig preset,
            ModEntry mod)
        {
            if (mod == null)
            {
                return SharedModPolicy.Forbidden;
            }

            return
                ModPolicyResolver.Resolve(
                    preset,
                    mod.ModId,
                    mod.Name);
        }

        private static string GetPolicyName(ModEntry mod)
        {
            if (mod == null)
            {
                return "FORBIDDEN";
            }

            PresetConfig preset =
                PresetStore.GetEditingOrActive();

            SharedModPolicy policy =
                ResolvePolicy(
                    preset,
                    mod);

            if (policy == SharedModPolicy.Forbidden &&
                !ModPolicyResolver.IsExplicitForbidden(
                    preset,
                    mod.ModId,
                    mod.Name))
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

                default:
                    return "FORBIDDEN";
            }
        }

        private static bool ContainsIgnoreCase(
            string source,
            string query)
        {
            return
                !string.IsNullOrEmpty(source) &&
                source.IndexOf(
                    query,
                    StringComparison.OrdinalIgnoreCase) >= 0;
        }
    }
}
