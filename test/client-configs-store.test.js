// Windows Store Claude Desktop keeps its live config under
// %LOCALAPPDATA%\Claude-Data\claude_<id>\, not %APPDATA%\Claude\. Everything
// here is hermetic: the filesystem is injected, the real machine is never read.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { clientConfigs } from '../src/adapters/discovery/client-configs.js';
import { duplicateClientNotes } from '../src/adapters/wrap/orchestrate.js';
import { formatStatus } from '../src/cli/status-command.js';

const LOCAL = 'C:\\Users\\u\\AppData\\Local';
const ROOT = path.join(LOCAL, 'Claude-Data');
const storeFile = (id) => path.join(ROOT, id, 'claude_desktop_config.json');

function win({ dirs = [], files = [], env, homedir = 'C:\\Users\\u' } = {}) {
  return clientConfigs({
    cwd: 'C:\\proj',
    platform: 'win32',
    homedir,
    env: env ?? { APPDATA: 'C:\\Users\\u\\AppData\\Roaming', LOCALAPPDATA: LOCAL },
    readdir: (p) => {
      if (p !== ROOT) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
      return dirs;
    },
    exists: (p) => files.includes(p),
  });
}
const desktop = (list) => list.filter((c) => c.id === 'claude-desktop');

test('a Store install is found by pattern and listed as a second Claude Desktop config', () => {
  const list = desktop(win({ dirs: ['claude_pzs8sxrjxfjjc', 'README.txt'], files: [storeFile('claude_pzs8sxrjxfjjc')] }));
  assert.equal(list.length, 2);
  assert.match(list[0].path, /Roaming.Claude.claude_desktop_config\.json$/);
  assert.equal(list[1].path, storeFile('claude_pzs8sxrjxfjjc'));
  assert.match(list[1].label, /Microsoft Store/);
  assert.notEqual(list[0].label, list[1].label, 'the two copies are told apart by label');
  assert.ok(list.every((c) => c.wrappable), 'both are wrappable, and share one --client id');
});

test('no Store install: only the usual path, and no error', () => {
  assert.equal(desktop(win({ dirs: [] })).length, 1);
  assert.equal(desktop(win({ dirs: ['README.txt', 'something_else'] , files: [] })).length, 1);
});

test('a missing Claude-Data folder (readdir throws) is not an error', () => {
  const list = clientConfigs({
    platform: 'win32', homedir: 'C:\\Users\\u', env: {}, cwd: 'C:\\p',
    readdir: () => { throw new Error('EACCES'); }, exists: () => true,
  });
  assert.equal(desktop(list).length, 1);
});

test('a claude_ folder with no config file in it adds nothing', () => {
  assert.equal(desktop(win({ dirs: ['claude_abc'], files: [] })).length, 1);
});

test('only folders named claude_* count, and several package ids are all found, in a stable order', () => {
  const list = desktop(win({
    dirs: ['claude_zzz', 'other_claude', 'claude_aaa'],
    files: [storeFile('claude_zzz'), storeFile('claude_aaa'), storeFile('other_claude')],
  }));
  assert.deepEqual(list.slice(1).map((c) => c.path), [storeFile('claude_aaa'), storeFile('claude_zzz')]);
});

test('LOCALAPPDATA unset: falls back to <home>\\AppData\\Local', () => {
  const home = 'C:\\Users\\u';
  const root = path.join(home, 'AppData', 'Local', 'Claude-Data');
  const f = path.join(root, 'claude_x', 'claude_desktop_config.json');
  const list = clientConfigs({
    platform: 'win32', homedir: home, env: {}, cwd: 'C:\\p',
    readdir: (p) => (p === root ? ['claude_x'] : (() => { throw new Error('ENOENT'); })()),
    exists: (p) => p === f,
  });
  assert.equal(desktop(list)[1]?.path, f);
});

test('macOS and Linux never look for a Store install (the filesystem is not even consulted)', () => {
  for (const platform of ['darwin', 'linux']) {
    const list = clientConfigs({
      platform, homedir: '/home/u', env: {}, cwd: '/p',
      readdir: () => { throw new Error('must not be called'); },
      exists: () => { throw new Error('must not be called'); },
    });
    assert.equal(desktop(list).length, 1, platform);
  }
});

// ---- the duplicate-config note in `status` ---------------------------------

const planOf = (specs) =>
  specs.map(({ id = 'claude-desktop', label, file, status = 'ready', servers = [] }) => ({ client: { id, label, path: file, wrappable: true }, file, status, servers }));
const day = (s) => () => new Date(s);

test('two Claude Desktop files: status says the app reads only one, shows both with dates, and flags the newer', () => {
  const plan = planOf([
    { label: 'Claude Desktop', file: 'A\\legacy.json' },
    { label: 'Claude Desktop (Microsoft Store install)', file: 'B\\store.json' },
  ]);
  const dates = { 'A\\legacy.json': new Date('2026-05-19'), 'B\\store.json': new Date('2026-11-12') };
  const notes = duplicateClientNotes(plan, { statMtime: (f) => dates[f] });
  const text = notes.join('\n');
  assert.match(text, /Claude Desktop has 2 config files/);
  assert.match(text, /reads only one/);
  assert.match(text, /A\\legacy\.json.*modified 2026-05-19(?!.*most recently)/);
  assert.match(text, /B\\store\.json.*modified 2026-11-12, most recently changed/);
  assert.match(text, /agentguard wrap --apply/);
});

test('no note when each app has a single config, or the second file is absent, or the files are custom', () => {
  assert.deepEqual(duplicateClientNotes(planOf([{ label: 'Claude Desktop', file: 'A' }]), { statMtime: day('2026-01-01') }), []);
  assert.deepEqual(
    duplicateClientNotes(planOf([{ label: 'Claude Desktop', file: 'A' }, { label: 'x', file: 'B', status: 'absent' }]), { statMtime: day('2026-01-01') }),
    []
  );
  assert.deepEqual(
    duplicateClientNotes(planOf([{ id: 'custom', label: 'a.json', file: 'A' }, { id: 'custom', label: 'b.json', file: 'B' }]), { statMtime: day('2026-01-01') }),
    []
  );
});

test('an unreadable modified time degrades to "unknown", never a crash or a false "newest" claim', () => {
  const plan = planOf([{ label: 'Claude Desktop', file: 'A' }, { label: 'Claude Desktop (Microsoft Store install)', file: 'B' }]);
  const notes = duplicateClientNotes(plan, { statMtime: () => { throw new Error('EPERM'); } });
  const text = notes.join('\n');
  assert.match(text, /modified date unknown/);
  assert.doesNotMatch(text, /most recently changed/);
});

test('formatStatus prints a Notes section for real duplicate files, and none for a single one', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-dup-'));
  try {
    const a = path.join(dir, 'legacy.json');
    const b = path.join(dir, 'store.json');
    fs.writeFileSync(a, '{}');
    fs.writeFileSync(b, '{}');
    fs.utimesSync(a, new Date('2026-05-19'), new Date('2026-05-19'));
    const ctx = { paths: { home: dir, policy: path.join(dir, 'no-policy.yaml'), audit: path.join(dir, 'no-audit.jsonl') } };

    const two = formatStatus(
      planOf([
        { label: 'Claude Desktop', file: a, status: 'no-servers' },
        { label: 'Claude Desktop (Microsoft Store install)', file: b, status: 'no-servers' },
      ]),
      ctx
    );
    assert.match(two, /Notes/);
    assert.match(two, /Claude Desktop has 2 config files/);
    assert.ok(two.includes(a) && two.includes(b), 'both paths are shown');
    assert.match(two, /legacy\.json.*modified 2026-05-19/);

    const one = formatStatus(planOf([{ label: 'Claude Desktop', file: a, status: 'no-servers' }]), ctx);
    assert.doesNotMatch(one, /Notes/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
