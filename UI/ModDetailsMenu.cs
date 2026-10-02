using HKMP.Whitelist.Shared;
using SharedModPolicy = HKMP.Whitelist.Shared.ModPolicy;
using Satchel.BetterMenus;
using System;

namespace HKMP.Whitelist.UI
{
    internal sealed class ModDetailsMenu
    {
        private readonly WhitelistMenu _root;

        private Menu _menu;
        private MenuScreen _parent;
        private ModEntry _mod;

        private TextPanel _name;
        private TextPanel _version;
        private TextPanel _hash;
        private TextPanel _path;
        private TextPanel _modId;
        private HorizontalOption _policyOption;

        public ModDetailsMenu(
            WhitelistMenu root)
        {
            _root = root;
        }

        public void Open(
            ModEntry mod,
            MenuScreen parent)
        {
            if (mod == null)
            {
                return;
            }

            _mod = mod;
            _parent = parent;

            _menu = null;

            EnsureMenu();
            Refresh();

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

            _name =
                new TextPanel(
                    "",
                    fontSize: WhitelistUiStyle.ModuleTitle,
                    Id: "Name");

            _version =
                new TextPanel(
                    "",
                    fontSize: WhitelistUiStyle.Body,
                    Id: "Version");

            _hash =
                new TextPanel(
                    "",
                    fontSize: WhitelistUiStyle.Body,
                    Id: "Hash");

            _path =
                new TextPanel(
                    "",
                    fontSize: WhitelistUiStyle.Body,
                    Id: "Path");

            _modId =
                new TextPanel(
                    "",
                    fontSize: WhitelistUiStyle.Body,
                    Id: "ModId");

            _policyOption =
                new HorizontalOption(
                    "Policy",
                    "Access rule for this mod",
                    new[]
                    {
                        "Required",
                        "Allowed",
                        "Ignored",
                        "Forbidden"
                    },
                    SetPolicy,
                    GetPolicyIndex,
                    "Policy");

            _menu =
                new Menu(
                    "HKMP.Whitelist - Mod",
                    new Element[]
                    {
                        _name,
                        _version,
                        _hash,
                        _path,
                        _modId,
                        _policyOption
                    });
        }

        private void Refresh()
        {
            if (_mod == null)
            {
                return;
            }

            _name.Name = _mod.Name ?? "Unknown";

            _version.Name =
                "Version: " +
                (_mod.Version ?? "?") +
                "  ·  " +
                (_mod.IsDisabled ? "Disabled" : "Active");

            string hash =
                ModScanner.GetHash(_mod);

            _hash.Name =
                "SHA-256: " +
                (string.IsNullOrWhiteSpace(hash)
                    ? "Unavailable"
                    : hash);

            _path.Name =
                "Path: " +
                (_mod.FilePath ?? "Unavailable");

            _modId.Name =
                "Mod ID: " +
                GetModId();

            try
            {
                _name.Update();
                _version.Update();
                _hash.Update();
                _path.Update();
                _modId.Update();
                _policyOption.Update();
                _menu.Update();
            }
            catch
            {
            }
        }

        private int GetPolicyIndex()
        {
            switch (GetPolicy())
            {
                case SharedModPolicy.Required:
                    return 0;

                case SharedModPolicy.Allowed:
                    return 1;

                case SharedModPolicy.Ignored:
                    return 2;

                default:
                    return 3;
            }
        }

        private void SetPolicy(
            int index)
        {
            if (_mod == null)
            {
                return;
            }

            SharedModPolicy policy;

            switch (index)
            {
                case 0:
                    policy = SharedModPolicy.Required;
                    break;

                case 1:
                    policy = SharedModPolicy.Allowed;
                    break;

                case 2:
                    policy = SharedModPolicy.Ignored;
                    break;

                default:
                    policy = SharedModPolicy.Forbidden;
                    break;
            }

            PresetConfig preset =
                PresetStore.GetEditingOrActive();

            if (preset == null)
            {
                return;
            }

            ModPolicyResolver.SetPolicy(
                preset,
                GetModId(),
                policy,
                _mod.Name);

            _root.MarkDirty();

            if (PresetStore.SaveEditing(
                    _root.ModDirectory,
                    _root))
            {
                PresetStore.NotifyPolicyChanged();
            }

            Refresh();
        }

        private SharedModPolicy GetPolicy()
        {
            if (_mod == null)
            {
                return SharedModPolicy.Forbidden;
            }

            return
                ModPolicyResolver.Resolve(
                    PresetStore.GetEditingOrActive(),
                    GetModId(),
                    _mod.Name);
        }

        private string GetModId()
        {
            if (_mod == null)
            {
                return "UnknownMod";
            }

            if (!string.IsNullOrWhiteSpace(_mod.ModId))
            {
                return _mod.ModId.Trim();
            }

            if (!string.IsNullOrWhiteSpace(_mod.Name))
            {
                return _mod.Name.Trim();
            }

            return "UnknownMod";
        }
    }
}
