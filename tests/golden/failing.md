## docka-check: what each AI client sees on `http://127.0.0.1:PORT/mcp`

**Checked 16 of 27 known failures. Found: 7. Only an agent run shows: 6. Needs write calls (v1): 2. Not checked in this run: 3.**

Listed below, client by client: 10 findings (5 blocker, 2 likely, 3 advisory).

<sub>docka-check 0.1.0 · rule table 2026-10-20 · tiers run: signin, schema, calls · (time)</sub>

| | Copilot Studio | Claude API | claude.ai | Claude Code | OpenAI API | ChatGPT |
|---|---|---|---|---|---|---|
| sign-in | found | not found in our checks | not found in our checks | not found in our checks | not checked here | not found in our checks |
| schema | found | found | found | not found in our checks | not found in our checks | not found in our checks |
| calls | not found in our checks | found | not found in our checks | found | found | not checked here |
| agent run | not checked here | not checked here | not checked here | not checked here | not checked here | not checked here |

### Blockers: our own run confirmed the failure (5)

- **F1-ROW** · Copilot Studio · client behaviour of 2026-10-20: Required fields inside the rows of a required top-level array. Where: create_items.
  - On Standard agents, Copilot asks the user for row fields the model already filled, and never calls the tool.
  - Seen in our run, 2026-09-27: monday create_items: 0 of 24 in Copilot across four models and both paths (25 and 27 September) (https://github.com/mondaycom/mcp/issues/499).
  - Seen in our run, 2026-09-30: a work-management vendor's create-task tool: 0 of 3, and 0 of 3 on the vendor's own documented setup.
  - Seen in our run, 2026-10-20: our own test server with monday's 2026-09-23 create_items: Standard agents 0 of 6 (GPT Chat Latest, Claude Opus 4.8), the newer agent type 6 of 6 (Claude Opus 5.5, GPT-5.5 Chat) (https://lab.docka.ai/guides/copilot-studio-mcp/#2-required-fields-in-array-rows-the-mcp-tool-is-never-called).
  - Note: Standard agents only. On 2026-10-20 Studio's newer Agent (GitHub Copilot) type, the one its main Agent card makes, called this shape 6 of 6 (Claude Opus 5.5, GPT-5.5 Chat); Standard agents 0 of 6 (GPT Chat Latest, Claude Opus 4.8).
  - Fix: Do not mark fields inside rows as required; check them in your handler. Or take the array as a JSON string. Guide: https://lab.docka.ai/guides/copilot-studio-mcp/#2-required-fields-in-array-rows-the-mcp-tool-is-never-called
- **OAUTH-DISC** · Copilot Studio · client behaviour of 2026-10-17: Copilot cannot find the protected-resource document. Where: protected-resource document (path form): not found; metadata on the MCP host (fallback): not found.
  - 'Failed to login. Could not discover authorization server metadata.'
  - Seen in our run, 2026-10-08: another vendor's server: GET 403, the path-form document 403, every metadata path 403 (guide §7).
  - Seen in our run, 2026-10-17: our test server: Copilot reads the document named in a 401 to GET, root form included.
  - Fix: Send your 401 challenge to a GET too, or serve the document at /.well-known/oauth-protected-resource/<path>, or serve the metadata on the MCP host. Guide: https://lab.docka.ai/guides/copilot-studio-mcp/#7-could-not-discover-authorization-server-metadata
- **REQ8** · Copilot Studio · client behaviour of 2026-10-20: Eight or more required inputs on one tool. Where: search.
  - On Standard agents, Copilot asks the user for a required input the model left out, instead of returning the error to the model.
  - Seen in our run, 2026-10-05: monday search with 8 required: GPT-5.5 Chat in Copilot 0 of 3; with 1 required: 3 of 3 (https://github.com/mondaycom/mcp/issues/508).
  - Seen in our run, 2026-10-20: our own test server with monday's search and its eight required inputs of 2026-10-05, reconstructed: GPT-5.5 Chat 0 of 3 on a Standard agent, 3 of 3 on the newer agent type (https://lab.docka.ai/guides/copilot-studio-mcp/#5-copilot-asks-the-user-for-an-input-the-model-left-out).
  - Note: Standard agents only, and model-dependent there: Claude in Copilot filled all eight and passed (2026-10-05). On 2026-10-20 GPT-5.5 Chat left the inputs empty on a Standard agent (0 of 3) and filled all eight on Studio's newer Agent (GitHub Copilot) type (3 of 3).
  - Fix: Require only what you cannot default. Guide: https://lab.docka.ai/guides/copilot-studio-mcp/#5-copilot-asks-the-user-for-an-input-the-model-left-out
- **RESULT-SCHEMA** · Claude API · client behaviour of 2026-09-24: A result that does not match the tool's own outputSchema. Where: get_deal.
  - 'Tool output schema validation failed': every such call rejected.
  - Seen in our run, 2026-09-24: a CRM's deals read: custom_fields declared an object, returned null.
  - Fix: Make the schema match what the server returns (for example allow null), or return what the schema says.
- **UNTYPED** · Copilot Studio · client behaviour of 2026-10-20: A required top-level array whose items have no type. Where: create_org_chart.
  - On Standard agents, Copilot types the input as a list of plain values and stops with SystemError when the model passes objects.
  - Seen in our run, 2026-10-01: Lucid lucid_create_org_chart: 0 of 6 in Copilot, 6 of 6 outside (https://github.com/lucidsoftware/lucid-mcp-server/issues/13).
  - Seen in our run, 2026-10-20: our own test server with Lucid's org-chart tool as it was before its 2026-10-12 fix: a Standard agent 0 of 3 (SystemError before the call), the newer agent type 3 of 3 (https://lab.docka.ai/guides/copilot-studio-mcp/#4-error-code-systemerror-array-items-without-a-type).
  - Note: Standard agents only. On 2026-10-20 Studio's newer Agent (GitHub Copilot) type, the one its main Agent card makes, called this shape 3 of 3 (Claude Opus 5.5); a Standard agent still stopped with SystemError, 0 of 3 (GPT Chat Latest).
  - Fix: Describe each row as an object with its properties. Guide: https://lab.docka.ai/guides/copilot-studio-mcp/#4-error-code-systemerror-array-items-without-a-type

### Likely: the platform documents it (2)

- **OUTSCHEMA-DECLARED** · claude.ai · client behaviour of 2026-07-22: A tool declares outputSchema. Where: get_deal.
  - Open issue: tools that declare outputSchema are rejected.
  - Documented: https://github.com/anthropics/claude-ai-mcp/issues/673 (read 2026-10-17).
  - Fix: Keep results matching the schema (see RESULT-SCHEMA); claude.ai's open issue rejects such tools.
- **RESULT-SCHEMA** · Claude Code · client behaviour of 2026-10-17: A result that does not match the tool's own outputSchema. Where: get_deal.
  - Claude Code validates outputSchema through the MCP TypeScript SDK.
  - Documented: https://code.claude.com/docs/en/mcp (read 2026-10-17).
  - Fix: Make the schema match what the server returns (for example allow null), or return what the schema says.

### Advisory: seen in our runs but not a failure by itself, or friction (3)

- **OUTSCHEMA-DECLARED** · Claude API · client behaviour of 2026-09-24: A tool declares outputSchema. Where: get_deal.
  - Results are validated against it; a mismatch rejects the whole result (RESULT-SCHEMA).
  - Seen in our run, 2026-09-24: a CRM's deals read.
  - Fix: Keep results matching the schema (see RESULT-SCHEMA); claude.ai's open issue rejects such tools.
- **RESULT-UTF8** · OpenAI API · client behaviour of 2026-10-16: Bytes in a result that are not valid UTF-8. Where: list_deals.
  - OpenAI's client times out (504) on such results: minutes per task instead of seconds.
  - Seen in our run, 2026-10-16: a CRM's metadata read with Latin-1 bytes: three unfixed runs took 131–254 s with five 504s; re-encoded, 9–11 s.
  - Fix: Encode every string as UTF-8.
- **ROWKEYS** · Copilot Studio · client behaviour of 2026-10-08: Array rows with optional keys. Where: create_items.
  - Copilot sends every row with the first row's keys only; it fails only when the rows differ.
  - Seen in our run, 2026-10-01: an opening-hours tool: rows lost the keys they needed, 0 of 3.
  - Seen in our run, 2026-10-01: a CRM's note and task in one call: the task arrived blank.
  - Seen in our run, 2026-10-12: Lucid after its fix (rows still optional): 6 of 6 (counter-case).
  - Fix: Give every row the same keys; use an empty value where a row has nothing. Guide: https://lab.docka.ai/guides/copilot-studio-mcp/#3-array-rows-lose-fields-copilot-sends-only-the-first-row-s-keys

### Info (1)

- **ISS-9207** · ChatGPT · client behaviour of 2026-10-17: Which redirect URI ChatGPT will use. Where: ChatGPT will use https://chatgpt.com/connector/oauth/{callback_id}.
  - Without RFC 9207 iss, ChatGPT uses https://chatgpt.com/connector/oauth/{callback_id} instead of https://chatgpt.com/connector_platform_oauth_redirect.
  - Documented: https://developers.openai.com/plugins/build/auth (read 2026-10-17).
  - Fix: Allow the redirect URI that matches your setting.

### How each client will see your tools

- **Copilot Studio**: required row fields: create_items; 8+ required inputs: search; untyped array items (SystemError): create_org_chart; rows may lose keys: create_items
- **Claude API**: validates results of: get_deal; ~485 tokens of tool definitions on every turn (dated case: a server with 282 tools (~131K tokens of definitions) cost $0.94 a job, 2026-10-12)
- **claude.ai**: declares outputSchema (claude-ai-mcp#673): get_deal
- **Claude Code**: validates results of: get_deal
- **OpenAI API**: ~485 tokens of tool definitions on every turn (dated case: a server with 282 tools (~131K tokens of definitions) cost $0.02 a job, 2026-10-12)
- **ChatGPT**: no notes from the tool definitions

### Not checked here

- Copilot Studio: no authorization-server metadata on its sign-in path: CONSENT-PAGE, SCOPE-DEFAULT, TOKEN-AUDIENCE
- a client setting: CLIENT-CONFIG
- a registry property; the owner gives the real URL: TEMPLATED
- needs write calls (--allow-writes, v1): READ-AFTER-CREATE, UPDATE-IN-CONNECTOR
- only an agent run shows it: DELETE-ON-CLEANUP, DUPLICATE-CHECK, MODEL-SUMS, PLANNED-NOT-RUN, TOOL-SEARCH-CALLS, TOOLS-NOT-SEEN
- unconfirmed, never shown as findings: AS-FIRST for Copilot Studio, CLIENT-CONFIG for OpenAI API, CLIENT-CONFIG for claude.ai, DELETE-NOHINT for Claude API, DELETE-NOHINT for Copilot Studio, PKCE-S256 for Copilot Studio, RESULT-SCHEMA for ChatGPT

Last agent run: never. Copilot Studio needs a Microsoft tenant: Docka runs it (https://docka.ai).
