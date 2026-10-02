
using HKMP.Whitelist.Server;
using HKMP.Whitelist.Shared;
using SharedModPolicy = HKMP.Whitelist.Shared.ModPolicy;
using Satchel.BetterMenus;
using System;
using System.Collections.Generic;
using System.Linq;

namespace HKMP.Whitelist.UI
{
    public sealed class DiagnosticsMenu
    {
        private readonly WhitelistMenu _root;

        private Menu _menu;

        private TextPanel _preset;
        private TextPanel _mods;
        private TextPanel _required;
        private TextPanel _allowed;
        private TextPanel _forbidden;
        private TextPanel _ignored;

        public DiagnosticsMenu(
            WhitelistMenu root)
        {
            _root = root;

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
                Refresh();
            }
            catch (Exception ex)
            {
                Modding.Logger.LogError(
                    "[Whitelist] Failed to refresh diagnostics policy view: " +
                    ex);
            }
        }

        public void Open(
            MenuScreen parent)
        {
            EnsureMenu();

            _root.GoTo(
                _menu,
                parent);

            Refresh();
        }

        private void EnsureMenu()
        {
            if (_menu != null)
            {
                return;
            }

            _preset =
                CreateBody(
                    "Preset");

            _mods =
                CreateBody(
                    "Mods");

            _required =
                CreateBody(
                    "Required");

            _allowed =
                CreateBody(
                    "Allowed");

            _forbidden =
                CreateBody(
                    "Forbidden");

            _ignored =
                CreateBody(
                    "Ignored");

            _menu =
                new Menu(
                    "HKMP.Whitelist - Diagnostics",
                    new Element[]
                    {
                        new TextPanel(
                            "DIAGNOSTICS",
                            fontSize:
                                WhitelistUiStyle.Title),

                        _preset,
                        _mods,
                        _required,
                        _allowed,
                        _forbidden,
                        _ignored,

                        new MenuButton(
                            "Refresh",
                            "Refresh whitelist diagnostics",
                            delegate(
                                UnityEngine.UI.MenuButton button)
                            {
                                Refresh();
                            },
                            false,
                            "Refresh")
                    });
        }

        private static TextPanel CreateBody(
            string id)
        {
            return
                new TextPanel(
                    "",
                    fontSize:
                        WhitelistUiStyle.Diagnostic,
                    Id:
                        id);
        }

        private void Refresh()
        {
            List<ModEntry> mods =
                ModScanner.GetMods();

            PresetConfig preset =
                PresetStore.GetActive();

            _preset.Name =
                "Active profile: " +
                (
                    preset == null
                        ? "None"
                        : preset.PresetName);

            _mods.Name =
                "Detected mods: " +
                mods.Count;

            _required.Name =
                "Required: " +
                Count(
                    mods,
                    SharedModPolicy.Required);

            _allowed.Name =
                "Allowed: " +
                Count(
                    mods,
                    SharedModPolicy.Allowed);

            _forbidden.Name =
                "Forbidden: " +
                Count(
                    mods,
                    SharedModPolicy.Forbidden);

            _ignored.Name =
                "Ignored: " +
                Count(
                    mods,
                    SharedModPolicy.Ignored);

            try
            {
                _preset.Update();
                _mods.Update();
                _required.Update();
                _allowed.Update();
                _forbidden.Update();
                _ignored.Update();

                _menu.Update();
            }
            catch
            {
            }
        }

        private static int Count(
            List<ModEntry> mods,
            SharedModPolicy policy)
        {
            return
                mods.Count(
                    x =>
                        GetPolicy(x) ==
                        policy);
        }

        private static SharedModPolicy GetPolicy(
            ModEntry mod)
        {
            if (mod == null)
            {
                return SharedModPolicy.Forbidden;
            }

            return
                ModPolicyResolver.Resolve(
                    PresetStore.GetEditingOrActive(),
                    mod.ModId,
                    mod.Name);
        }
    }
}