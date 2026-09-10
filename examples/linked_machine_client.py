"""V2 linked Machine Client example. Install mudraid-sdk[v2] first.

Configure the prefixed variables described in README.md. Linking the client
in the portal does not change an existing legacy Agent instance.
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
