"""GoPlus AgentGuard native plugin for Hermes Agent.

Hermes imports this package and calls :func:`register` at load time.
"""

from __future__ import annotations

try:  # package context (installed under ~/.hermes/plugins/agentguard/)
    from .plugin import register
except ImportError:  # top-level module context (tests / ad-hoc)
    from plugin import register

__all__ = ["register"]
