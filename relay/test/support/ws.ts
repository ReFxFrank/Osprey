import { WebSocket } from 'ws';

export interface WsClient {
  send(value: unknown): void;
  /** Resolves with the next frame, or rejects if the socket closes first. */
  next(timeoutMs?: number): Promise<unknown>;
  /** Resolves with the close code once the socket closes. */
  closed(timeoutMs?: number): Promise<number>;
  /**
   * Resolves once `quietMs` has passed with nothing delivered, and rejects with
   * whatever did arrive. Asserting on the *absence* of a frame is the only way
   * to show that a rejected relay reached no one: a test that only inspects the
   * sender's error would pass even if the payload had also been delivered.
   */
  receivedNothing(quietMs?: number): Promise<void>;
  close(): void;
}

export function openWs(url: string, bearerToken: string): Promise<WsClient> {
  const socket = new WebSocket(url, { headers: { authorization: `Bearer ${bearerToken}` } });
  const inbox: unknown[] = [];
  const waiters: ((value: unknown) => void)[] = [];
  let closeCode: number | null = null;
  const closeWaiters: ((code: number) => void)[] = [];

  socket.on('message', (data) => {
    const parsed: unknown = JSON.parse(data.toString('utf8'));
    const waiter = waiters.shift();
    if (waiter !== undefined) waiter(parsed);
    else inbox.push(parsed);
  });
  socket.on('close', (code) => {
    closeCode = code;
    for (const w of closeWaiters.splice(0)) w(code);
  });

  const client: WsClient = {
    send: (value) => socket.send(JSON.stringify(value)),
    next: (timeoutMs = 5_000) =>
      new Promise((resolve, reject) => {
        const buffered = inbox.shift();
        if (buffered !== undefined) {
          resolve(buffered);
          return;
        }
        const timer = setTimeout(() => reject(new Error('timed out waiting for a frame')), timeoutMs);
        waiters.push((value) => {
          clearTimeout(timer);
          resolve(value);
        });
      }),
    closed: (timeoutMs = 5_000) =>
      new Promise((resolve, reject) => {
        if (closeCode !== null) {
          resolve(closeCode);
          return;
        }
        const timer = setTimeout(() => reject(new Error('timed out waiting for close')), timeoutMs);
        closeWaiters.push((code) => {
          clearTimeout(timer);
          resolve(code);
        });
      }),
    receivedNothing: (quietMs = 300) =>
      new Promise((resolve, reject) => {
        const buffered = inbox.shift();
        if (buffered !== undefined) {
          reject(new Error(`expected silence, received ${JSON.stringify(buffered)}`));
          return;
        }
        const timer = setTimeout(() => {
          const index = waiters.indexOf(waiter);
          if (index >= 0) waiters.splice(index, 1);
          resolve();
        }, quietMs);
        const waiter = (value: unknown) => {
          clearTimeout(timer);
          reject(new Error(`expected silence, received ${JSON.stringify(value)}`));
        };
        waiters.push(waiter);
      }),
    close: () => socket.close(),
  };

  return new Promise((resolve, reject) => {
    socket.once('open', () => resolve(client));
    socket.once('unexpected-response', (_req, res) => {
      reject(new Error(`websocket upgrade rejected with ${res.statusCode}`));
    });
    socket.once('error', (err) => reject(err));
  });
}
