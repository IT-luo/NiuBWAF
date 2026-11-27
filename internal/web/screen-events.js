'use strict';

const SCREEN_EVENT_LIMIT = 60;
const SCREEN_LIVE_MAX_AGE = 20000;
const SCREEN_REPLAY_INTERVAL = 6500;

class ScreenAttackTimeline {
  constructor() {
    this.recent = [];
    this.history = [];
    this.unconfirmed = new Map();
    this.liveKeys = new Set();
    this.pending = [];
    this.replayAfter = SCREEN_REPLAY_INTERVAL;
    this.lastReplayed = '';
  }

  static normalize(raw) {
    const status = Number(raw.status);
    if (!Number.isInteger(status) || status < 100 || status >= 600 || status === 200) return null;

    const ip = raw.ip || raw.client_ip || '';
    const id = Number(raw.id) || 0;
    const key = raw.req_id
      ? JSON.stringify(['request', raw.req_id, raw.action, status])
      : JSON.stringify(id ? ['log', id] : ['legacy', raw.ts, ip, raw.domain, raw.method, raw.url, raw.action, status]);
    const { lat, lon } = raw;
    const located = Number.isFinite(lat) && Number.isFinite(lon) &&
      Math.abs(lat) <= 90 && Math.abs(lon) <= 180 && (lat !== 0 || lon !== 0);
    return { ...raw, id, key, ts: String(raw.ts || ''), ip, status, located };
  }

  addLive(raw, now) {
    const event = ScreenAttackTimeline.normalize(raw);
    if (!event || this.liveKeys.has(event.key)) return false;
    this.liveKeys.add(event.key);
    if (this.liveKeys.size > SCREEN_EVENT_LIMIT * 2) {
      this.liveKeys.delete(this.liveKeys.values().next().value);
    }

    this.unconfirmed.set(event.key, event);
    if (this.unconfirmed.size > SCREEN_EVENT_LIMIT) {
      this.unconfirmed.delete(this.unconfirmed.keys().next().value);
    }
    this.replayAfter = now + SCREEN_REPLAY_INTERVAL;
    if (event.located) {
      this.pending.push({ event, received: now });
      if (this.pending.length > SCREEN_EVENT_LIMIT) this.pending.shift();
    }
    this.updateRecent();
    return true;
  }

  mergeHistory(rows) {
    const previous = new Map(this.recent.map(event => [event.key, event]));
    this.history = [];
    for (const row of rows) {
      const event = ScreenAttackTimeline.normalize(row);
      if (!event) continue;
      const known = this.unconfirmed.get(event.key) || previous.get(event.key);
      if (known?.located && !event.located) {
        Object.assign(event, { lat: known.lat, lon: known.lon, country: known.country, city: known.city });
        event.located = true;
      }
      this.unconfirmed.delete(event.key);
      this.history.push(event);
    }
    this.updateRecent();
  }

  updateRecent() {
    const events = new Map();
    for (const event of [...this.unconfirmed.values()].reverse()) events.set(event.key, event);
    for (const event of this.history) {
      if (!events.has(event.key)) events.set(event.key, event);
    }
    this.recent = [...events.values()]
      .sort((a, b) => b.ts.localeCompare(a.ts))
      .slice(0, SCREEN_EVENT_LIMIT);
  }

  hasLive(now) {
    while (this.pending.length) {
      const {event, received} = this.pending[0];
      if (now - received <= SCREEN_LIVE_MAX_AGE && this.recent.some(row => row.key === event.key)) return true;
      this.pending.shift();
    }
    return false;
  }

  take(now) {
    if (this.hasLive(now)) {
      this.replayAfter = now + SCREEN_REPLAY_INTERVAL;
      return { mode: 'live', event: this.pending.shift().event };
    }
    if (now < this.replayAfter) return null;
    this.replayAfter = now + SCREEN_REPLAY_INTERVAL;
    const located = this.recent.filter(event => event.located);
    if (located.length === 0) return null;
    const previous = located.findIndex(event => event.key === this.lastReplayed);
    const event = located[(previous + 1) % located.length];
    this.lastReplayed = event.key;
    return { mode: 'replay', event };
  }
}
