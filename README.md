# docka-check

What each AI client sees on your MCP server: Copilot Studio, Claude through Anthropic's API, claude.ai and Claude
Desktop, Claude Code, GPT through OpenAI's API, ChatGPT. You run it on your own server, with your own credentials.
It makes no model calls and never prints a verdict. A full run needs a server you have verified as yours, and its
report then also goes to Docka (see [Your server, verified once](#your-server-verified-once)).

Its best possible result reads like this, on our own clean test server: *"Checked 19 of 27 known failures. Found: 0.
Only an agent run shows: 6. Needs write calls (v1): 2. Not checked in this run: 0."*
That is not "compatible". It means none of the failures we know how to check turned up, six more are invisible to
any check without an agent, and two need write calls this version does not make.

## Install and run

```
pipx install git+https://github.com/docka-hq/docka-check     # or: uvx --from git+https://… docka-check
docka-check verify --url https://mcp.example.com/mcp --email you@example.com    # once per server, see below
export MCP_TOKEN=…                                            # your own token; never put it on the command line
docka-check check --url https://mcp.example.com/mcp --token-env MCP_TOKEN --calls-config calls.json
```

Python 3.10 or later, standard library only.

| Command | What it does |
|---|---|
| `check` | the three tiers below, one report |
| `signin` | replays each client's sign-in on your server |
| `schema` | reads `tools/list` (with your token, so servers behind sign-in work too) and applies each client's rules |
| `calls` | calls the read tools you list, and holds each result against its own schema and each client's limits |
| `diff old.json new.json` | what a release changed |
| `verify` | proves a server is yours, once (below) |
| `key` | prints a verified server's key, for a CI secret |

Options worth knowing:

- `--token-env VAR` / `--header NAME=VAR`: credentials, read from environment variables only.
- A key written into the URL itself (`user:pass@`, `?api_key=…`, a long random path segment) is used for the requests
  and shown as `[credential]` everywhere in the report. A header is still better: a URL lands in shell history.
- `--register`: registers each client's redirect URI with your authorization server, then deletes those clients
  (RFC 7592) or prints their ids. **Only on a server verified as yours, or on this machine.**
- `--interactive`: you sign in in your browser, so the tool can check the consent page and the token.
- `--calls-config calls.json`: `{"calls": [{"tool": "get_deal", "arguments": {…}}], "promised_tools": [...]}`.
  Nothing outside this list is ever called. `--auto-read` adds tools marked `readOnlyHint: true` that take no
  required input, and never a tool on the strength of its name.
- `--format terminal|md|json`, `--json-out`, `--baseline previous.json` (exit code 1 only on a new blocker that our
  own runs confirmed), `--client copilot-studio` (or any one client).

## Your server, verified once

A full run registers clients, replays sign-ins and calls tools, so it is for the server's owner. To show that a server
is yours:

1. `docka-check verify --url https://mcp.example.com/mcp --email you@example.com` prints a token.
2. Serve it as plain text at `https://mcp.example.com/.well-known/docka-verify.txt`, on the host of your MCP URL.
3. Run the same command again (or add `--wait 600` to the first one). Docka fetches the file once and gives this
   machine a key, kept in `~/.config/docka-check/keys.json` (mode 600). You can take the file down afterwards.

What goes to Docka, and Docka keeps:

- when you verify: the server's origin (scheme, host and port, never the path or query) and your email;
- before each full run: the key, to confirm it is still valid for this server;
- after each full run: its JSON report, the one `--json-out` writes. Credentials are removed, and a key inside the URL
  shows as `[credential]`.

By verifying you agree to this. Nothing else is sent, and nothing at all from the two other kinds of run:

- **A server on this machine** (`localhost`, `127.0.0.1`, `::1`): a full run, no verification, nothing sent.
- **Any other server** gets an outside check: at most 5 requests per server, no client registration, no tool calls.
  Your credentials, if you pass them, are used for those requests. `--register`, `--interactive`, `--client-id`,
  `--calls-config` and `--auto-read` stop with an error. The report says it was an outside check and lists whatever
  the limit cut off as not checked.

In every kind of run, a 429 stops every further request to that server.

## How to read a finding: evidence classes

Every rule lives in `docka_check/rules.json`, with the date of the client behaviour it describes.

- **Blocker**: our own run confirmed it, in that client, on a dated case. The report shows the case, with a public
  link where one exists (a GitHub issue, a lab.docka.ai guide).
- **Likely**: the platform documents it (URL and the date we read it), or its own tracker has an open issue. We did
  not run it.
- **Advisory**: seen in our runs, but the shape alone does not predict the failure (it depends on the data in the
  call), or it is friction (cost, a confirmation, a header that needs approval).
- **Info**: a fact about the client, not about your server, such as which redirect URI ChatGPT will use.
- **Unconfirmed**: never shown as a finding, only in the not-checked list.

"Not found in our checks" needs an answer from your server. A step that got none (a timeout, a 5xx, a 429, the
request limit) makes every rule that depends on it "not checked here", with the reason, and is never read as "not
found" or as a finding. In `--interactive`, when no sign-in comes back the tool asks whether the page failed, and
without your yes the consent page counts as not checked. A refusal is no answer either. If a call without credentials
is refused and the server offers no OAuth, the rules that count credentials stay not checked until you pass yours. If
initialize answers 404, the whole sign-in tier stays not checked.

Where sources disagree, the report keeps both. For example, Zuplo lists 128 tools as Copilot Studio's cap. In our
runs a classic agent showed "Limiting number of tools to 70" on one server, and the new default agent listed all 282
tools of another.

## What this cannot see

- **Anything only an agent run shows**: a model adding up records itself and getting totals wrong, deleting on "clean
  up", creating a duplicate, Copilot planning a call it never runs, an agent that never finds the tool it needs.
  The report counts these, and "Last agent run: never" stays true until someone runs your jobs in the real clients.
- **Copilot Studio itself.** It needs a Microsoft tenant, so its rules here come from our runs in our own tenant,
  each with its date.
- **Write calls** (read-after-create, updates): v1, test accounts only.
- **Client releases after a rule's date.** Clients change often. Every rule carries the date of the behaviour it
  describes; re-run when a client ships.

## For CI

`action.yml` wraps the CLI. Credentials come from GitHub secrets. The report goes into the job summary and, when
enabled, into a PR comment. The job log gets its two count lines and, on a verified run, whether the report reached
Docka; never the URL.

Verify the server on your own machine first, then store its key as a secret:
`docka-check key --url https://mcp.example.com/mcp | gh secret set DOCKA_CHECK_KEY`.

```yaml
- uses: docka-hq/docka-check@v0
  with:
    url: https://mcp.example.com/mcp
    verify-key: ${{ secrets.DOCKA_CHECK_KEY }}
    token: ${{ secrets.MCP_TOKEN }}
    calls-config: .github/docka-calls.json
    baseline: docka-check-baseline.json     # optional: a previous run's JSON report
    comment: "true"
```

Without `verify-key` the run is an outside check, and `calls-config` or `auto-read` make it stop with an error.

`.github/workflows/demo.yml` runs the Action against our own test server inside the job, on `127.0.0.1`: a full run
that sends nothing.

## Development

```
python3 -m unittest discover -s tests -t .     # about two minutes
python3 -m testserver.cases                    # rewrite KNOWN_CASES.md after changing the cases
UPDATE_GOLDEN=1 python3 -m unittest tests.test_report
```

- `testserver/shapes.py` is our own MCP and OAuth server, switchable into each failure shape one of our runs or a
  client's documentation shows. `KNOWN_CASES.md` lists every case with its evidence. Its `FAULTS` (a 503, a 429, a
  slow or failing call, an endless tools/list) test that no answer is ever read as one.
- The tests never call a third-party server. `tests/test_owner.py` runs Docka's side of `verify`
  (`server/verify_api.py`) in-process, against our own test server.
- The run records and captures behind the rule table are Docka's and are not published. Each case in `rules.json`
  carries its date, the text a report shows and a public link where one exists.
- `docka_check/t5/` holds the Copilot Studio shape checks (see its README).
