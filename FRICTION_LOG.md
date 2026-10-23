# Friction log

Friction logs can add up to 10% to the judging score. Keep entries honest and specific, and add your own as you go.

## 1. MCP Python SDK v2 renamed FastMCP and changed startup

- **Task:** Build an MCP server and run background listeners (the honeypots) alongside it.
- **Steps:** Imported `from mcp.server.fastmcp import FastMCP` from tutorials, and tried `app.add_event_handler("startup", ...)`.
- **Expected:** Both to work as documented in common examples.
- **Actual:** `FastMCP` is now `MCPServer` (`from mcp.server.mcpserver import MCPServer`), and the returned Starlette app has no `add_event_handler`; startup must go through the lifespan context.
- **Severity:** Medium (blocks you until you find the v2 docs).
- **Workaround:** Switched to `MCPServer` and wrapped the existing `lifespan_context` to start the honeypots.
- **Suggestion:** The Alexa+ getting-started material should show a v2 example, and show how to run background tasks next to the MCP app.

## 2. AWS credits ran out before the deadline

- **Task:** Request the $150 AWS credits for Bedrock, Polly and SNS.
- **Expected:** Credits available to registered entrants.
- **Actual:** Credits ran out on October 7.
- **Severity:** Medium.
- **Workaround:** Added a full demo mode (template reports, browser voice) so the project runs with no AWS, and used the low-cost Nova Lite model.
- **Suggestion:** Show remaining credit availability on the hackathon page.

## 3. (add your own)

- **Task:**
- **Steps:**
- **Expected:**
- **Actual:**
- **Severity:**
- **Workaround:**
- **Suggestion:**
