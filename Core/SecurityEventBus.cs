using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using HKMP.Whitelist.Shared;

namespace HKMP.Whitelist.Core
{
    public sealed class SecurityEventBus
    {
        private readonly object _sync =
            new object();

        private readonly List<Action<SecurityEvent>> _handlers =
            new List<Action<SecurityEvent>>();

        public IReadOnlyCollection<Action<SecurityEvent>> Subscribers
        {
            get
            {
                lock (_sync)
                {
                    return new ReadOnlyCollection<Action<SecurityEvent>>(
                        _handlers.ToList());
                }
            }
        }

        public void Subscribe(
            Action<SecurityEvent> handler)
        {
            if (handler == null)
            {
                return;
            }

            lock (_sync)
            {
                if (_handlers.Contains(handler))
                {
                    return;
                }

                _handlers.Add(handler);
            }
        }

        public void Unsubscribe(
            Action<SecurityEvent> handler)
        {
            if (handler == null)
            {
                return;
            }

            lock (_sync)
            {
                _handlers.Remove(handler);
            }
        }

        public void Publish(
            SecurityEvent securityEvent)
        {
            if (securityEvent == null)
            {
                return;
            }

            Action<SecurityEvent>[] handlers;

            lock (_sync)
            {
                handlers =
                    _handlers.ToArray();
            }

            foreach (Action<SecurityEvent> handler in handlers)
            {
                try
                {
                    handler(securityEvent);
                }
                catch
                {
                }
            }
        }

        public void Clear()
        {
            lock (_sync)
            {
                _handlers.Clear();
            }
        }
    }
}