# Checks the MCP server the way Alexa+ would connect to it.
# Run the app first (python app.py), then: python test_mcp.py

import asyncio
import json

from mcp import Client


async def main():
    async with Client("http://localhost:8000/mcp") as client:
        tools = await client.list_tools()
        print("Tools:", [t.name for t in tools.tools])

        result = await client.call_tool("status", {})
        print("\nstatus:", json.loads(result.content[0].text))

        result = await client.call_tool("whats_happening", {"minutes": 60})
        print("\nsummary:", json.loads(result.content[0].text)["spoken"])


asyncio.run(main())
