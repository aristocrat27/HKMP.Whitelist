using HKMP.Whitelist.Shared;
using Satchel.BetterMenus;
using System;
using UnityEngine;

namespace HKMP.Whitelist.UI
{
    public sealed class SecurityMenu
    {
        private readonly WhitelistMenu _root;

        private Menu _menu;

        public SecurityMenu(
            WhitelistMenu root)
        {
            _root = root;
        }

        public void Open(
            MenuScreen parent)
        {
            EnsureMenu();

            _root.GoTo(
                _menu,
                parent);
        }

        private void EnsureMenu()
        {
            if (_menu != null)
            {
                return;
            }

            _menu =
                new Menu(
                    "HKMP.Whitelist - Security",
                    new Element[]
                    {
                        new TextPanel(
                            "SECURITY",
                            fontSize:
                                WhitelistUiStyle.Title),

                        new HorizontalOption(
                            "Security Mode",
                            "Normal / Strict / Maximum",
                            new[]
                            {
                                "Normal",
                                "Strict",
                                "Maximum"
                            },
                            SetSecurityMode,
                            GetSecurityMode,
                            "SecurityMode"),

                        new HorizontalOption(
                            "Unknown Files",
                            "Allow / Deny",
                            new[]
                            {
                                "Allow",
                                "Deny"
                            },
                            SetUnknownPolicy,
                            GetUnknownPolicy,
                            "UnknownFiles"),

                        new HorizontalOption(
                            "Complete Scan",
                            "Require / Do Not Require",
                            new[]
                            {
                                "Allow incomplete",
                                "Require complete"
                            },
                            SetCompleteScan,
                            GetCompleteScan,
                            "CompleteScan"),

                        new HorizontalOption(
                            "Core Integrity",
                            "Disabled / Enabled",
                            new[]
                            {
                                "Disabled",
                                "Enabled"
                            },
                            SetCoreIntegrity,
                            GetCoreIntegrity,
                            "CoreIntegrity"),

                        new HorizontalOption(
                            "Self Integrity",
                            "Disabled / Enabled",
                            new[]
                            {
                                "Disabled",
                                "Enabled"
                            },
                            SetSelfIntegrity,
                            GetSelfIntegrity,
                            "SelfIntegrity"),

                        new HorizontalOption(
                            "Runtime Monitoring",
                            "Disabled / Enabled",
                            new[]
                            {
                                "Disabled",
                                "Enabled"
                            },
                            SetRuntimeMonitoring,
                            GetRuntimeMonitoring,
                            "RuntimeMonitoring"),

                        new HorizontalOption(
                            "Timer Integration",
                            "Use /timer start to lock Whitelist membership",
                            new[]
                            {
                                "Disabled",
                                "Enabled"
                            },
                            SetTimerIntegration,
                            GetTimerIntegration,
                            "TimerIntegration"),

                        new HorizontalOption(
                            "Anti-Tamper Challenge",
                            "Disabled / Enabled",
                            new[]
                            {
                                "Disabled",
                                "Enabled"
                            },
                            SetChallenge,
                            GetChallenge,
                            "AntiTamper"),

                        new HorizontalOption(
                            "Scan Interval",
                            "Seconds",
                            new[]
                            {
                                "5",
                                "10",
                                "15",
                                "30",
                                "60"
                            },
                            SetRuntimeInterval,
                            GetRuntimeInterval,
                            "RuntimeInterval"),

                        new HorizontalOption(
                            "Challenge Timeout",
                            "Milliseconds",
                            new[]
                            {
                                "1000",
                                "2000",
                                "3000",
                                "5000"
                            },
                            SetChallengeTimeout,
                            GetChallengeTimeout,
                            "ChallengeTimeout")
                    });
        }

        private PresetConfig GetPreset()
        {
            return PresetStore.GetEditingOrActive();
        }

        private void Changed()
        {
            _root.MarkDirty();

            PresetStore.SaveEditing(
                _root.ModDirectory,
                _root);
        }

        private void SetSecurityMode(
            int value)
        {
            PresetConfig preset =
                GetPreset();

            if (preset == null)
            {
                return;
            }

            preset.SecurityMode =
                (SecurityMode)Mathf.Clamp(
                    value,
                    0,
                    2);

            Changed();
        }

        private int GetSecurityMode()
        {
            PresetConfig preset =
                GetPreset();

            return
                preset == null
                    ? 2
                    : Mathf.Clamp(
                        (int)preset.SecurityMode,
                        0,
                        2);
        }

        private void SetUnknownPolicy(
            int value)
        {
            PresetConfig preset =
                GetPreset();

            if (preset == null)
            {
                return;
            }

            preset.UnknownPolicyDeny =
                value == 1;

            Changed();
        }

        private int GetUnknownPolicy()
        {
            PresetConfig preset =
                GetPreset();

            return
                preset != null &&
                preset.UnknownPolicyDeny
                    ? 1
                    : 0;
        }

        private void SetCompleteScan(
            int value)
        {
            PresetConfig preset =
                GetPreset();

            if (preset == null)
            {
                return;
            }

            preset.RequireCompleteScan =
                value == 1;

            Changed();
        }

        private int GetCompleteScan()
        {
            PresetConfig preset =
                GetPreset();

            return
                preset != null &&
                preset.RequireCompleteScan
                    ? 1
                    : 0;
        }

        private void SetCoreIntegrity(
            int value)
        {
            PresetConfig preset =
                GetPreset();

            if (preset == null)
            {
                return;
            }

            preset.CheckCoreIntegrity =
                value == 1;

            Changed();
        }

        private int GetCoreIntegrity()
        {
            PresetConfig preset =
                GetPreset();

            return
                preset != null &&
                preset.CheckCoreIntegrity
                    ? 1
                    : 0;
        }

        private void SetSelfIntegrity(
            int value)
        {
            PresetConfig preset =
                GetPreset();

            if (preset == null)
            {
                return;
            }

            preset.CheckSelfIntegrity =
                value == 1;

            Changed();
        }

        private int GetSelfIntegrity()
        {
            PresetConfig preset =
                GetPreset();

            return
                preset != null &&
                preset.CheckSelfIntegrity
                    ? 1
                    : 0;
        }

        private void SetRuntimeMonitoring(
            int value)
        {
            PresetConfig preset =
                GetPreset();

            if (preset == null)
            {
                return;
            }

            preset.RuntimeMonitoringEnabled =
                value == 1;

            Changed();
        }

        private int GetRuntimeMonitoring()
        {
            PresetConfig preset =
                GetPreset();

            return
                preset != null &&
                preset.RuntimeMonitoringEnabled
                    ? 1
                    : 0;
        }

        private void SetTimerIntegration(
            int value)
        {
            WhitelistGlobalSettings settings =
                WhitelistMod.GlobalSettings;

            if (settings == null)
            {
                return;
            }

            settings.TimerIntegrationEnabled =
                value == 1;
        }

        private int GetTimerIntegration()
        {
            WhitelistGlobalSettings settings =
                WhitelistMod.GlobalSettings;

            return
                settings != null &&
                settings.TimerIntegrationEnabled
                    ? 1
                    : 0;
        }

        private void SetChallenge(
            int value)
        {
            PresetConfig preset =
                GetPreset();

            if (preset == null)
            {
                return;
            }

            preset.ChallengeEnabled =
                value == 1;

            Changed();
        }

        private int GetChallenge()
        {
            PresetConfig preset =
                GetPreset();

            return
                preset != null &&
                preset.ChallengeEnabled
                    ? 1
                    : 0;
        }

        private void SetRuntimeInterval(
            int value)
        {
            PresetConfig preset =
                GetPreset();

            if (preset == null)
            {
                return;
            }

            int[] values =
            {
                5,
                10,
                15,
                30,
                60
            };

            value =
                Mathf.Clamp(
                    value,
                    0,
                    values.Length - 1);

            preset.RuntimeScanIntervalSeconds =
                values[value];

            Changed();
        }

        private int GetRuntimeInterval()
        {
            PresetConfig preset =
                GetPreset();

            return
                preset == null
                    ? 3
                    : Closest(
                        new[]
                        {
                            5,
                            10,
                            15,
                            30,
                            60
                        },
                        preset.RuntimeScanIntervalSeconds);
        }

        private void SetChallengeTimeout(
            int value)
        {
            PresetConfig preset =
                GetPreset();

            if (preset == null)
            {
                return;
            }

            int[] values =
            {
                1000,
                2000,
                3000,
                5000
            };

            value =
                Mathf.Clamp(
                    value,
                    0,
                    values.Length - 1);

            preset.ChallengeTimeoutMs =
                values[value];

            Changed();
        }

        private int GetChallengeTimeout()
        {
            PresetConfig preset =
                GetPreset();

            return
                preset == null
                    ? 2
                    : Closest(
                        new[]
                        {
                            1000,
                            2000,
                            3000,
                            5000
                        },
                        preset.ChallengeTimeoutMs);
        }

        private static int Closest(
            int[] values,
            int current)
        {
            if (values == null ||
                values.Length == 0)
            {
                return 0;
            }

            int best =
                0;

            int distance =
                Math.Abs(
                    values[0] -
                    current);

            for (int i = 1;
                 i < values.Length;
                 i++)
            {
                int currentDistance =
                    Math.Abs(
                        values[i] -
                        current);

                if (currentDistance <
                    distance)
                {
                    distance =
                        currentDistance;

                    best =
                        i;
                }
            }

            return best;
        }
    }
}