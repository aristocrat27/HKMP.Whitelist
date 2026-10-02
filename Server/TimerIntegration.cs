using System;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Reflection.Emit;
using MonoMod.RuntimeDetour;

namespace HKMP.Whitelist.Server
{
    internal sealed class TimerIntegration : IDisposable
    {
        private readonly Func<bool> _isEnabled;
        private readonly Func<bool> _beforeTimerStarted;

        private Hook _hook;
        private bool _installed;
        private bool _disposed;

        private static TimerIntegration Active { get; set; }

        public TimerIntegration(
            Func<bool> isEnabled,
            Func<bool> beforeTimerStarted)
        {
            _isEnabled =
                isEnabled;

            _beforeTimerStarted =
                beforeTimerStarted;
        }

        public TimerIntegration(
            Action onTimerStarted)
            : this(
                () => true,
                () =>
                {
                    if (onTimerStarted != null)
                    {
                        onTimerStarted();
                    }

                    return true;
                })
        {
        }

        public bool IsInstalled
        {
            get
            {
                return _installed &&
                       !_disposed;
            }
        }

        public bool IsEnabled
        {
            get
            {
                if (_disposed)
                {
                    return false;
                }

                if (_isEnabled == null)
                {
                    return true;
                }

                try
                {
                    return _isEnabled();
                }
                catch
                {
                    return false;
                }
            }
        }

        public bool TryInstall()
        {
            if (_disposed)
            {
                return false;
            }

            if (_installed)
            {
                return true;
            }

            try
            {
                Assembly timerAssembly =
                    AppDomain.CurrentDomain
                        .GetAssemblies()
                        .FirstOrDefault(
                            assembly =>
                                assembly != null &&
                                string.Equals(
                                    assembly.GetName().Name,
                                    "HKMP.Timer",
                                    StringComparison.OrdinalIgnoreCase));

                if (timerAssembly == null)
                {
                    return false;
                }

                Type managerType =
                    timerAssembly.GetType(
                        "HKMP.Timer.TimerServerManager",
                        false);

                if (managerType == null)
                {
                    return false;
                }

                MethodInfo start =
                    managerType
                        .GetMethods(
                            BindingFlags.Public |
                            BindingFlags.NonPublic |
                            BindingFlags.Instance)
                        .FirstOrDefault(
                            method =>
                                method.Name == "Start" &&
                                method.ReturnType == typeof(void) &&
                                method.GetParameters().Length == 1 &&
                                method.GetParameters()[0].ParameterType ==
                                    typeof(Action<string>));

                if (start == null)
                {
                    return false;
                }

                MethodInfo detour =
                    BuildDetourMethod(
                        managerType,
                        start);

                _hook =
                    new Hook(
                        start,
                        detour);

                _installed =
                    true;

                Active =
                    this;

                return true;
            }
            catch
            {
                _hook = null;
                _installed = false;

                return false;
            }
        }

        private MethodInfo BuildDetourMethod(
            Type managerType,
            MethodInfo source)
        {
            ParameterInfo[] parameters =
                source.GetParameters();

            Type[] sourceSignature =
                new Type[
                    parameters.Length + 1];

            sourceSignature[0] =
                managerType;

            for (int i = 0;
                 i < parameters.Length;
                 i++)
            {
                sourceSignature[i + 1] =
                    parameters[i].ParameterType;
            }

            Type[] originalDelegateSignature =
                sourceSignature
                    .Concat(
                        new[]
                        {
                            source.ReturnType
                        })
                    .ToArray();

            Type originalDelegateType =
                Expression.GetDelegateType(
                    originalDelegateSignature);

            Type[] detourParameters =
                new Type[
                    sourceSignature.Length + 1];

            detourParameters[0] =
                originalDelegateType;

            for (int i = 0;
                 i < sourceSignature.Length;
                 i++)
            {
                detourParameters[i + 1] =
                    sourceSignature[i];
            }

            DynamicMethod method =
                new DynamicMethod(
                    "HKMP_Whitelist_TimerStartDetour",
                    source.ReturnType,
                    detourParameters,
                    typeof(TimerIntegration).Module,
                    true);

            ILGenerator il =
                method.GetILGenerator();

            Label denyOriginal =
                il.DefineLabel();

            MethodInfo gate =
                typeof(TimerIntegration).GetMethod(
                    nameof(ShouldAllowOriginalStart),
                    BindingFlags.NonPublic |
                    BindingFlags.Static);

            if (gate == null)
            {
                throw new MissingMethodException(
                    typeof(TimerIntegration).FullName,
                    nameof(ShouldAllowOriginalStart));
            }

            il.Emit(
                OpCodes.Call,
                gate);

            il.Emit(
                OpCodes.Brfalse,
                denyOriginal);

            LocalBuilder argsArray =
                il.DeclareLocal(
                    typeof(object[]));

            il.Emit(
                OpCodes.Ldc_I4,
                sourceSignature.Length);

            il.Emit(
                OpCodes.Newarr,
                typeof(object));

            il.Emit(
                OpCodes.Stloc,
                argsArray);

            for (int i = 0;
                 i < sourceSignature.Length;
                 i++)
            {
                il.Emit(
                    OpCodes.Ldloc,
                    argsArray);

                il.Emit(
                    OpCodes.Ldc_I4,
                    i);

                il.Emit(
                    OpCodes.Ldarg,
                    i + 1);

                Type parameterType =
                    sourceSignature[i];

                if (parameterType.IsValueType)
                {
                    il.Emit(
                        OpCodes.Box,
                        parameterType);
                }

                il.Emit(
                    OpCodes.Stelem_Ref);
            }

            il.Emit(
                OpCodes.Ldarg_0);

            il.Emit(
                OpCodes.Ldloc,
                argsArray);

            MethodInfo dynamicInvoke =
                typeof(Delegate).GetMethod(
                    "DynamicInvoke",
                    new[]
                    {
                        typeof(object[])
                    });

            if (dynamicInvoke == null)
            {
                throw new MissingMethodException(
                    typeof(Delegate).FullName,
                    "DynamicInvoke");
            }

            il.Emit(
                OpCodes.Callvirt,
                dynamicInvoke);

            if (source.ReturnType != typeof(void))
            {
                il.Emit(
                    OpCodes.Pop);
            }

            il.Emit(
                OpCodes.Ret);

            il.MarkLabel(
                denyOriginal);

            il.Emit(
                OpCodes.Ret);

            return method;
        }

        private static bool ShouldAllowOriginalStart()
        {
            TimerIntegration active =
                Active;

            if (active == null ||
                active._disposed)
            {
                return false;
            }

            if (!active.IsEnabled)
            {
                return true;
            }

            if (active._beforeTimerStarted == null)
            {
                return false;
            }

            try
            {
                return active._beforeTimerStarted();
            }
            catch
            {
                return false;
            }
        }

        public void Activate()
        {
            if (_disposed)
            {
                return;
            }

            Active =
                this;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            try
            {
                if (_hook != null)
                {
                    _hook.Dispose();
                }
            }
            catch
            {
            }

            _hook = null;
            _installed = false;

            if (ReferenceEquals(
                    Active,
                    this))
            {
                Active = null;
            }
        }
    }
}