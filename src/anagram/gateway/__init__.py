"""The agent gateway (layers plan, section 2.5; open-agents plan stages 1
to 3): the only path from an outside agent (the person's own Claude, a local
model, a lab agent) to the person's data. The agent never holds a key.

- `access.py`: agent grant v2 (primitive `agent-grant`), one for each agent,
  in the encrypted index store (meta key `agent_grants`; it replaces the v1
  key `mcp`). Scopes of tools, recipient class, end date, revoke, daily
  limit, loopback HTTP key. Off by default.
- `tools.py`: the tools (`TOOLS`): search, ask, read_item, timeline (read,
  only items that the trust policy permits), and propose_lines (an act).
- `acts.py`: the act queue. An act tool only queues a proposal; the person
  decides in the local UI (`shell/ui/agents.py`). In v1 an outside agent
  prepares drafts only and never negotiates.
- `server.py`: the MCP protocol (JSON-RPC 2.0) and stdio.
- `http.py`: MCP over loopback HTTP, a bearer key for each grant (decision
  A1: no public URL).

The command `anagram mcp` is in the shell (`anagram.shell.cli.mcp`): it is
the composition root that gives the gateway its session and the trust
policy port.
"""
