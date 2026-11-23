# Where to start

1. **Search your web, proxy and sign-in logs** for HexStrike's user agents and the XSS probe. They are code defaults, so a hit is close to certain.
2. **Run the cross-framework hunts** in `behaviors/` against your internet-facing applications. HexStrike runs stock tools, so its scanning looks like the tools themselves.
3. **Check your own hosts.** Run the server and MCP client hunts. A developer machine with an AI assistant wired to HexStrike is a full attack toolkit, and a HexStrike server reachable on 8888 lets anyone run commands on it.
