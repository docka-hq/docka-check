## docka-check: what each AI client sees on `http://127.0.0.1:PORT/mcp`

**Checked 19 of 27 known failures. Found: 0. Only an agent run shows: 6. Needs write calls (v1): 2. Not checked in this run: 0.**

<sub>docka-check 0.1.0 · rule table 2026-10-20 · tiers run: signin, schema, calls · (time)</sub>

| | Copilot Studio | Claude API | claude.ai | Claude Code | OpenAI API | ChatGPT |
|---|---|---|---|---|---|---|
| sign-in | not found in our checks | not found in our checks | not found in our checks | not found in our checks | not checked here | not found in our checks |
| schema | not found in our checks | not found in our checks | not found in our checks | not found in our checks | not found in our checks | not found in our checks |
| calls | not found in our checks | not found in our checks | not found in our checks | not found in our checks | not found in our checks | not checked here |
| agent run | not checked here | not checked here | not checked here | not checked here | not checked here | not checked here |

### Info (1)

- **ISS-9207** · ChatGPT · client behaviour of 2026-10-17: Which redirect URI ChatGPT will use. Where: ChatGPT will use https://chatgpt.com/connector/oauth/{callback_id}.
  - Without RFC 9207 iss, ChatGPT uses https://chatgpt.com/connector/oauth/{callback_id} instead of https://chatgpt.com/connector_platform_oauth_redirect.
  - Documented: https://developers.openai.com/plugins/build/auth (read 2026-10-17).
  - Fix: Allow the redirect URI that matches your setting.

### How each client will see your tools

- **Copilot Studio**: no notes from the tool definitions
- **Claude API**: ~107 tokens of tool definitions on every turn (dated case: a server with 282 tools (~131K tokens of definitions) cost $0.94 a job, 2026-10-12)
- **claude.ai**: no notes from the tool definitions
- **Claude Code**: no notes from the tool definitions
- **OpenAI API**: ~107 tokens of tool definitions on every turn (dated case: a server with 282 tools (~131K tokens of definitions) cost $0.02 a job, 2026-10-12)
- **ChatGPT**: no notes from the tool definitions

### Not checked here

- a client setting: CLIENT-CONFIG
- a registry property; the owner gives the real URL: TEMPLATED
- needs write calls (--allow-writes, v1): READ-AFTER-CREATE, UPDATE-IN-CONNECTOR
- only an agent run shows it: DELETE-ON-CLEANUP, DUPLICATE-CHECK, MODEL-SUMS, PLANNED-NOT-RUN, TOOL-SEARCH-CALLS, TOOLS-NOT-SEEN
- unconfirmed, never shown as findings: AS-FIRST for Copilot Studio, CLIENT-CONFIG for OpenAI API, CLIENT-CONFIG for claude.ai, DELETE-NOHINT for Claude API, DELETE-NOHINT for Copilot Studio, PKCE-S256 for Copilot Studio, RESULT-SCHEMA for ChatGPT

Last agent run: never. Copilot Studio needs a Microsoft tenant: Docka runs it (https://docka.ai).
