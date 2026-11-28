const assert = require('node:assert/strict');
const { existsSync, readFileSync } = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function timeline() {
  const script = path.join(__dirname, '../internal/web/screen-events.js');
  assert.ok(existsSync(script), 'the wallboard needs a playback queue for both feeds');
  const context = vm.createContext({});
  vm.runInContext(readFileSync(script, 'utf8'), context);
  return vm.runInContext('new ScreenAttackTimeline()', context);
}

const history = {
  id: 42, req_id: '0123456789ab', ts: '2026-11-27 07:09:08',
  client_ip: '203.0.113.5', city: '上海市', country: 'CN',
  domain: 'api.example.com', method: 'GET', url: '/orders',
  status: 403, action: 'waf', msg: 'sample block', lat: 31.23, lon: 121.47
};
const live = {
  req_id: '123456789abc', ts: '2026-11-27 07:10:00', type: 'attack',
  ip: '198.51.100.5', city: '新加坡', country: 'SG',
  domain: 'shop.example.com', method: 'POST', url: '/cart',
  status: 403, action: 'waf', msg: 'sample block', lat: 1.35, lon: 103.82
};

test('recovered history keeps coordinates and plays only as historical replay', () => {
  const screen = timeline();
  screen.mergeHistory([history]);
  assert.equal(screen.recent.length, 1);
  assert.equal(screen.take(0), null);
  const replay = screen.take(10000);
  assert.equal(replay.mode, 'replay');
  assert.equal(replay.event.lat, 31.23);
  assert.equal(replay.event.ip, '203.0.113.5');
  assert.equal(screen.take(10001), null);
});

test('live traffic takes priority and remains one row when history catches up', () => {
  const screen = timeline();
  screen.mergeHistory([history]);
  assert.equal(screen.addLive(live, 10000), true);
  screen.mergeHistory([{ ...live, id: 43, type: undefined, client_ip: live.ip, ip: undefined }, history]);
  const flight = screen.take(10200);
  assert.equal(flight.mode, 'live');
  assert.equal(flight.event.domain, 'shop.example.com');
  assert.equal(screen.addLive(live, 10300), false);
  assert.equal(screen.recent.length, 2);
  assert.equal(screen.take(10400), null);
});

test('unlocated attacks stay in the feed and observations stay out', () => {
  const screen = timeline();
  assert.equal(screen.addLive({ ...live, lat: 0, lon: 0 }, 200), true);
  assert.equal(screen.addLive({ ...live, req_id: '223456789abc', status: 200 }, 300), false);
  assert.equal(screen.recent.length, 1);
  assert.equal(screen.recent[0].located, false);
  assert.equal(screen.take(10000), null);
});

test('a newly recovered source enters replay outside the initial snapshot', () => {
  const screen = timeline();
  screen.mergeHistory([history]);
  assert.equal(screen.take(10000).event.domain, 'api.example.com');
  screen.mergeHistory([{ ...live, id: 43, client_ip: live.ip, ip: undefined, lat: 0 }, history]);
  const replay = screen.take(20000);
  assert.equal(replay.mode, 'replay');
  assert.equal(replay.event.domain, 'shop.example.com');
  assert.equal(replay.event.lat, 0);
});

test('repeated database refreshes retain previously observed coordinates', () => {
  const screen = timeline();
  screen.addLive(live, 200);
  const stored = { ...live, id: 43, client_ip: live.ip, ip: undefined, lat: undefined, lon: undefined };
  screen.mergeHistory([stored]);
  screen.mergeHistory([stored]);
  assert.equal(screen.recent[0].located, true);
  assert.equal(screen.recent[0].lon, 103.82);
});

test('latest arrivals remain visible when a burst shares the same timestamp', () => {
  const screen = timeline();
  for (let i = 1; i <= 62; i++) {
    screen.addLive({ ...live, req_id: String(i), ip: '192.0.2.' + i }, i);
  }
  assert.equal(screen.recent[0].ip, '192.0.2.62');
  assert.equal(screen.recent.at(-1).ip, '192.0.2.3');
  assert.equal(screen.take(100).event.ip, '192.0.2.3');
});

test('history reports expired login and reconnects the wallboard after login', async () => {
  const page = readFileSync(path.join(__dirname, '../internal/web/screen.html'), 'utf8');
  const connection = { hidden: true, textContent: '' };
  const streams = [];
  const polls = [];
  let status = 401;
  class EventSource {
    static CLOSED = 2;
    constructor() {
      this.readyState = 0;
      streams.push(this);
    }
  }
  const context = vm.createContext({
    $: () => connection,
    EventSource,
    console: { warn() {} },
    setInterval: poll => polls.push(poll),
    j: async () => {
      if (status !== 200) throw Object.assign(new Error(status), { status });
      return { list: [] };
    },
    timeline: { mergeHistory() {} },
    updateMapPoints() {},
    feedDirty: false,
  });
  const start = page.indexOf('let historyLoading = false;');
  vm.runInContext(page.slice(start, page.indexOf('</script>', start)), context);
  streams[0].readyState = EventSource.CLOSED;
  streams[0].onerror();
  await new Promise(setImmediate);
  assert.equal(connection.hidden, false);
  assert.match(connection.textContent, /重新登录/);

  status = 200;
  await polls[0]();
  assert.equal(streams.length, 2);
  assert.match(connection.textContent, /攻击日志/);
  streams[1].onopen();
  assert.equal(connection.hidden, true);
});
