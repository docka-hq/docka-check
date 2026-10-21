# The Copilot Studio shape checks

The schema tier's checks for the shapes Copilot Studio fails on, from our runs:

| File | What it does |
|---|---|
| `schema_checks.py` | the checks (F1-ROW, UNTYPED, REQ8 and the advisory ones), on one server's tools/list |
| `owner2_shapes.py` | the walk over each input schema that finds the risky shapes |
| `schema_lint.py` | Microsoft's documented known issues for MCP tool schemas |
| `fixtures/*.json` | schema_lint's self-test inputs (four SDK shapes, 2026-09-23) |

`docka_check/schema.py` reads their output and attaches each client's label from the rule table. They also run on
their own: `python3 docka_check/t5/schema_checks.py tools.json [--json]`.
