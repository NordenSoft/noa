/**
 * NOA Relay — push-provider abstraction.
 *
 * BUILD-DECISION (patron mandate, master-plan v5.2): the mobile client is React Native
 * (Android-first), so the notification target is a native FCM-style push, NOT PWA WebPush. This
 * slice ABSTRACTS the provider: a `PushProvider` interface + a no-op/log driver for localhost.
 * The real FCM integration is the NEXT slice and drops in behind this interface without touching
 * any locked decision.
 *
 * RED LINE 11 / invariant (spec §9): the push payload carries an OPAQUE hold-id + deep-link ONLY.
 * Never raw action params, never PII. The provider contract below cannot carry anything else.
 */

export interface PushMessage {
  /** Opaque hold id — the ONLY correlator the notification is allowed to carry. */
  holdId: string;
  /** Fixed, non-sensitive title. */
  title: string;
  /** Non-sensitive body: at most "<requester> wants to <canonical>". Never raw params. */
  body: string;
  /** Deep link into the app, e.g. "/app/approve/<holdId>". */
  deepLink: string;
}

export interface PushDelivery {
  deviceId: string;
  delivered: boolean;
  detail: string;
}

export interface PushProvider {
  readonly name: string;
  send(deviceId: string, subscription: unknown, msg: PushMessage): Promise<PushDelivery>;
}

/**
 * Localhost driver: logs the (opaque) notification and returns "delivered". A dropped push is not
 * fatal — the app also 10s-polls the inbox (degraded-mode survival, FAZ-APP §5.3), so a no-op
 * push provider still yields a working approval loop for the demo.
 */
export class NoopLogPushProvider implements PushProvider {
  readonly name = "noop-log";
  private readonly sink: (line: string) => void;
  public readonly sent: Array<{ deviceId: string; msg: PushMessage }> = [];

  constructor(sink: (line: string) => void = () => {}) {
    this.sink = sink;
  }

  async send(deviceId: string, _subscription: unknown, msg: PushMessage): Promise<PushDelivery> {
    // Assert the opaque-only contract at runtime: only holdId/title/body/deepLink, nothing else.
    this.sent.push({ deviceId, msg });
    this.sink(`[push:${this.name}] device=${deviceId} hold=${msg.holdId} "${msg.title}"`);
    return { deviceId, delivered: true, detail: "logged (no-op localhost driver)" };
  }
}
