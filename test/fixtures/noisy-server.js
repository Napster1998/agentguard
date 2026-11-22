// A minimal MCP-ish stdio server that, like some real ones (Burp's proxy jar
// prints "kotlin-log..."), writes a plain-text log line to STDOUT before and
// between its JSON-RPC replies. Answers every request with an empty result.
import readline from 'node:readline';

process.stdout.write('kotlin-log: server starting\n');
const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (line) => {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  if (msg.id === undefined) return;
  process.stdout.write('kotlin-log: handling ' + msg.method + '\n');
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { content: [{ type: 'text', text: 'ok' }] } }) + '\n');
});
rl.on('close', () => process.exit(0));
