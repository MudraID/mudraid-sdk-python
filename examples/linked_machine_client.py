"""Linked Machine Client example. Install mudraid-sdk first.

Configure the prefixed variables described in README.md. Linking the client
and approve a bounded resource grant before calling the platform.
"""

import os

from mudraid import MachineAgent


def build_agent(prefix="MUDRAID"):
    """Load this client's explicit configuration; never fall back to legacy keys."""

    return MachineAgent.from_env(prefix)


if __name__ == "__main__":
    agent = build_agent()
    try:
        response = agent.get(os.environ["MUDRAID_TASKS_URL"], timeout=15)
        response.raise_for_status()
        print(f"Platform call succeeded: HTTP {response.status_code}")
    finally:
        agent.close()
