using Hkmp.Api.Client;
using Hkmp.Api.Server;
using HKMP.Whitelist.Client;
using HKMP.Whitelist.Server;
using HKMP.Whitelist.UI;
using Modding;
using System.Collections.Generic;
using UnityEngine;

namespace HKMP.Whitelist
{
    public sealed class WhitelistMod :
        Mod,
        IGlobalSettings<WhitelistGlobalSettings>,
        ICustomMenuMod
    {
        public static WhitelistMod Instance
        {
            get;
            private set;
        }

        public static WhitelistGlobalSettings GlobalSettings
        {
            get;
            private set;
        }

        private WhitelistMenu _menu;

        public WhitelistMod()
            : base("HKMP.Whitelist")
        {
            Instance =
                this;
        }

        public override string GetVersion()
        {
            return "1.1.0";
        }

        public override List<(string, string)> GetPreloadNames()
        {
            return new List<(string, string)>();
        }

        public void OnLoadGlobal(
            WhitelistGlobalSettings settings)
        {
            GlobalSettings =
                settings ??
                new WhitelistGlobalSettings();
        }

        public WhitelistGlobalSettings OnSaveGlobal()
        {
            return
                GlobalSettings ??
                new WhitelistGlobalSettings();
        }

        public override void Initialize(
            Dictionary<string,
                Dictionary<string, GameObject>> preloadedObjects)
        {
            Instance =
                this;

            if (GlobalSettings == null)
            {
                GlobalSettings =
                    new WhitelistGlobalSettings();
            }

            ClientAddon.RegisterAddon(
                new WhitelistClientAddon());

            ServerAddon.RegisterAddon(
                new WhitelistServerAddon());

            _menu =
                new WhitelistMenu();

            Log(
                "[Whitelist] Initialized.");
        }

        public bool ToggleButtonInsideMenu
        {
            get { return false; }
        }

        public MenuScreen GetMenuScreen(
            MenuScreen modListMenu,
            ModToggleDelegates? toggleDelegates)
        {
            if (_menu == null)
            {
                _menu =
                    new WhitelistMenu();
            }

            return
                _menu.GetMenuScreen(
                    modListMenu);
        }
    }
}