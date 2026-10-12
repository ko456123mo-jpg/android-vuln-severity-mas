"""حزمة خوادم MCP / MCP servers package.

خوادم الأدوات الأربع (jadx, mobsf, frida, objection) + مكتبة مشتركة + مدير موحّد:
- mcp_servers.common        : FastMCP base, process runner, artifact store, schemas, mocks
- mcp_servers.<tool>_server : FastMCP servers (stdio)
- mcp_servers.manager       : MCPManager + get_mcp_client() (MultiServerMCPClient)
"""
