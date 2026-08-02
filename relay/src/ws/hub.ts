import type { WebSocket } from 'ws';

/**
 * Registry of live sockets, keyed by tenant *and* device. The account id is
 * part of the key rather than merely stored alongside it so that a lookup can
 * never resolve a device id belonging to a different tenant, even if two
 * tenants somehow held colliding device ids.
 */
export class SocketHub {
  readonly #sockets = new Map<string, WebSocket>();

  static key(accountId: string, deviceId: string): string {
    return `${accountId}:${deviceId}`;
  }

  attach(accountId: string, deviceId: string, socket: WebSocket): void {
    const key = SocketHub.key(accountId, deviceId);
    const previous = this.#sockets.get(key);
    this.#sockets.set(key, socket);
    // One socket per device: a reconnect supersedes a stale connection rather
    // than leaving two sockets racing for the same peer's frames.
    if (previous !== undefined && previous !== socket) {
      previous.close(4000, 'superseded');
    }
  }

  detach(accountId: string, deviceId: string, socket: WebSocket): void {
    const key = SocketHub.key(accountId, deviceId);
    if (this.#sockets.get(key) === socket) this.#sockets.delete(key);
  }

  get(accountId: string, deviceId: string): WebSocket | undefined {
    return this.#sockets.get(SocketHub.key(accountId, deviceId));
  }

  /** Revocation is immediate (brief §6.1): the socket goes away with the pairing. */
  drop(accountId: string, deviceId: string, reason: string): void {
    const key = SocketHub.key(accountId, deviceId);
    const socket = this.#sockets.get(key);
    if (socket === undefined) return;
    this.#sockets.delete(key);
    socket.close(4001, reason);
  }

  get size(): number {
    return this.#sockets.size;
  }
}
