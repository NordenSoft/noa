/**
 * Structured JSON-line logger (enterprise bar): every event is one machine-parseable line +
 * an optional human tag. It NEVER logs a secret. Any field whose key looks key/secret-bearing,
 * or whose value looks like a private key / bearer token, is hard-redacted before emit — a defense
 * in depth on top of "the drivers never pass a secret here in the first place" (Red Line 1/3).
 */

export type LogFields = Record<string, unknown>;

const SECRET_KEY_RE = /(privatekey|private_key|secret|apikey|api_key|devicesecret|bearer|seed|pkcs8|token)/i;
// base64 PKCS8 Ed25519 private keys start with this fixed DER prefix; bearer tokens use these prefixes.
const SECRET_VALUE_RE = /(MC4CAQAwBQYDK2Vw|noa_agent_|noa_device_|noa_pair_|Bearer\s)/;

function redact(value: unknown): unknown {
  if (typeof value === 'string') {
    return SECRET_VALUE_RE.test(value) ? '[REDACTED]' : value;
  }
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object') {
    const out: LogFields = {};
    for (const [k, v] of Object.entries(value as LogFields)) {
      out[k] = SECRET_KEY_RE.test(k) ? '[REDACTED]' : redact(v);
    }
    return out;
  }
  return value;
}

export interface Logger {
  event(ev: string, fields?: LogFields): void;
  child(scope: string): Logger;
  readonly lines: ReadonlyArray<string>;
}

export function createLogger(opts: { scope?: string; echo?: boolean; sink?: string[] } = {}): Logger {
  const sink: string[] = opts.sink ?? [];
  const echo = opts.echo ?? true;
  const scope = opts.scope;
  const log: Logger = {
    lines: sink,
    event(ev, fields = {}) {
      const record = {
        ts: new Date().toISOString(),
        ...(scope ? { scope } : {}),
        ev,
        ...(redact(fields) as LogFields),
      };
      const line = JSON.stringify(record);
      sink.push(line);
      if (echo) process.stdout.write(line + '\n');
    },
    child(childScope: string) {
      return createLogger({ scope: scope ? `${scope}.${childScope}` : childScope, echo, sink });
    },
  };
  return log;
}
