// Stand-in for a server that ignores end-of-input and never exits on its own.
process.stdin.resume();
process.stdin.on('end', () => {});
setInterval(() => {}, 1000);
