// Stand-in for a well-behaved MCP stdio server: exits when its stdin closes
// (what a real server launched directly by an app does when the app quits).
process.stdin.resume();
process.stdin.on('end', () => process.exit(0));
