// Zero-dependency ambient declarations for Node.js >= 23.6 / v26 built-in modules

type BufferEncoding =
  | 'ascii'
  | 'utf8'
  | 'utf-8'
  | 'utf16le'
  | 'ucs2'
  | 'ucs-2'
  | 'base64'
  | 'base64url'
  | 'latin1'
  | 'binary'
  | 'hex';

interface Buffer extends Uint8Array {
  toString(encoding?: BufferEncoding, start?: number, end?: number): string;
  equals(otherBuffer: Uint8Array): boolean;
  subarray(start?: number, end?: number): Buffer;
  fill(value: string | Uint8Array | number, offset?: number, end?: number, encoding?: BufferEncoding): this;
}

declare var Buffer: {
  from(value: string, encoding?: BufferEncoding): Buffer;
  from(value: ArrayBuffer | SharedArrayBuffer | Uint8Array | readonly number[]): Buffer;
  alloc(size: number, fill?: string | Buffer | number, encoding?: BufferEncoding): Buffer;
  concat(list: readonly Uint8Array[], totalLength?: number): Buffer;
  isBuffer(obj: unknown): obj is Buffer;
  byteLength(string: string | Uint8Array, encoding?: BufferEncoding): number;
};

interface URLSearchParams {
  append(name: string, value: string): void;
  delete(name: string, value?: string): void;
  get(name: string): string | null;
  getAll(name: string): string[];
  has(name: string, value?: string): boolean;
  set(name: string, value: string): void;
  sort(): void;
  toString(): string;
  entries(): IterableIterator<[string, string]>;
  keys(): IterableIterator<string>;
  values(): IterableIterator<string>;
  [Symbol.iterator](): IterableIterator<[string, string]>;
}

declare var URLSearchParams: {
  new (init?: string | Record<string, string> | Iterable<[string, string]> | URLSearchParams): URLSearchParams;
};

interface URL {
  hash: string;
  host: string;
  hostname: string;
  href: string;
  readonly origin: string;
  password: string;
  pathname: string;
  port: string;
  protocol: string;
  search: string;
  readonly searchParams: URLSearchParams;
  username: string;
  toString(): string;
  toJSON(): string;
}

declare var URL: {
  new (url: string | URL, base?: string | URL): URL;
};

declare var console: {
  log(...args: unknown[]): void;
  error(...args: unknown[]): void;
  warn(...args: unknown[]): void;
  info(...args: unknown[]): void;
};

interface TimerHandle {
  unref(): this;
  ref(): this;
}

declare function setTimeout(callback: (...args: unknown[]) => void, ms?: number): TimerHandle;
declare function clearTimeout(timeoutId: TimerHandle | undefined): void;

interface ImportMeta {
  url: string;
}

declare var process: {
  env: Record<string, string | undefined>;
  argv: string[];
  pid: number;
  version: string;
  cwd(): string;
  exit(code?: number): never;
  uptime(): number;
  stdin: import('node:stream').Readable;
  stdout: import('node:stream').Writable;
  stderr: import('node:stream').Writable;
  execPath: string;
  on(event: string, listener: (...args: unknown[]) => void): void;
};

declare module 'node:events' {
  export class EventEmitter {
    on(eventName: string | symbol, listener: (...args: any[]) => void): this;
    once(eventName: string | symbol, listener: (...args: any[]) => void): this;
    off(eventName: string | symbol, listener: (...args: any[]) => void): this;
    emit(eventName: string | symbol, ...args: any[]): boolean;
    removeAllListeners(eventName?: string | symbol): this;
  }
}

declare module 'node:stream' {
  import { EventEmitter } from 'node:events';
  export class Readable extends EventEmitter {
    setEncoding(encoding: BufferEncoding): this;
    resume(): this;
    pause(): this;
    destroy(error?: Error): this;
    [Symbol.asyncIterator](): AsyncIterableIterator<Buffer | string>;
  }
  export class Writable extends EventEmitter {
    write(chunk: string | Uint8Array, encoding?: BufferEncoding | ((err?: Error | null) => void), cb?: (err?: Error | null) => void): boolean;
    end(cb?: () => void): this;
    end(chunk: string | Uint8Array, cb?: () => void): this;
    end(chunk: string | Uint8Array, encoding?: BufferEncoding, cb?: () => void): this;
    destroy(error?: Error): this;
  }
  export class PassThrough extends Readable {
    write(chunk: string | Uint8Array, encoding?: BufferEncoding | ((err?: Error | null) => void), cb?: (err?: Error | null) => void): boolean;
    end(cb?: () => void): this;
    end(chunk: string | Uint8Array, cb?: () => void): this;
    end(chunk: string | Uint8Array, encoding?: BufferEncoding, cb?: () => void): this;
  }
}

declare module 'node:crypto' {
  export interface ScryptOptions {
    N?: number;
    cost?: number;
    r?: number;
    blockSize?: number;
    p?: number;
    parallelization?: number;
    maxmem?: number;
  }
  export interface CipherGCM {
    setAAD(buffer: Uint8Array, options?: { plaintextLength: number }): this;
    update(data: Uint8Array): Buffer;
    update(data: string, inputEncoding: BufferEncoding): Buffer;
    final(): Buffer;
    getAuthTag(): Buffer;
  }
  export interface DecipherGCM {
    setAAD(buffer: Uint8Array, options?: { plaintextLength: number }): this;
    setAuthTag(buffer: Uint8Array): this;
    update(data: Uint8Array): Buffer;
    final(): Buffer;
  }
  export interface Hash {
    update(data: string | Uint8Array, inputEncoding?: BufferEncoding): this;
    digest(): Buffer;
    digest(encoding: 'hex' | 'base64' | 'base64url'): string;
  }
  export function randomBytes(size: number): Buffer;
  export function randomUUID(): string;
  export function scryptSync(password: string | Uint8Array, salt: string | Uint8Array, keylen: number, options?: ScryptOptions): Buffer;
  export function hkdfSync(digest: string, ikm: string | Uint8Array, salt: string | Uint8Array, info: string | Uint8Array, keylen: number): ArrayBuffer;
  export function createCipheriv(algorithm: 'aes-256-gcm', key: Uint8Array, iv: Uint8Array, options?: { authTagLength?: number }): CipherGCM;
  export function createDecipheriv(algorithm: 'aes-256-gcm', key: Uint8Array, iv: Uint8Array, options?: { authTagLength?: number }): DecipherGCM;
  export function createHash(algorithm: string): Hash;
  export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean;
}

declare module 'node:sqlite' {
  export type SQLInputValue = null | number | bigint | string | Uint8Array;
  export type SQLOutputValue = null | number | bigint | string | Uint8Array;
  export interface StatementResultingChanges {
    changes: number | bigint;
    lastInsertRowid: number | bigint;
  }
  export class StatementSync {
    all(...params: SQLInputValue[]): Record<string, SQLOutputValue>[];
    get(...params: SQLInputValue[]): Record<string, SQLOutputValue> | undefined;
    run(...params: SQLInputValue[]): StatementResultingChanges;
  }
  export class DatabaseSync {
    constructor(location: string, options?: { open?: boolean; readOnly?: boolean; timeout?: number });
    exec(sql: string): void;
    prepare(sql: string): StatementSync;
    close(): void;
  }
}

declare module 'node:net' {
  export interface AddressInfo {
    address: string;
    family: string;
    port: number;
  }
}

declare module 'node:http' {
  import { EventEmitter } from 'node:events';
  import { Readable, Writable } from 'node:stream';
  import { AddressInfo } from 'node:net';

  export type IncomingHttpHeaders = Record<string, string | string[] | undefined>;
  export type OutgoingHttpHeaders = Record<string, string | string[] | number | undefined>;

  export class IncomingMessage extends Readable {
    method?: string;
    url?: string;
    statusCode?: number;
    statusMessage?: string;
    headers: IncomingHttpHeaders;
    socket: { remoteAddress?: string };
  }

  export class ServerResponse extends Writable {
    statusCode: number;
    statusMessage: string;
    headersSent: boolean;
    setHeader(name: string, value: number | string | readonly string[]): this;
    getHeader(name: string): number | string | string[] | undefined;
    writeHead(statusCode: number, headers?: OutgoingHttpHeaders): this;
  }

  export class ClientRequest extends Writable {
    destroy(error?: Error): this;
    setTimeout(timeout: number, callback?: () => void): this;
  }

  export interface RequestOptions {
    protocol?: string | null;
    hostname?: string | null;
    host?: string | null;
    port?: number | string | null;
    method?: string;
    path?: string | null;
    headers?: OutgoingHttpHeaders;
    timeout?: number;
  }

  export type RequestListener = (req: IncomingMessage, res: ServerResponse) => void | Promise<void>;

  export class Server extends EventEmitter {
    listening: boolean;
    listen(port?: number, hostname?: string, listeningListener?: () => void): this;
    listen(port?: number, listeningListener?: () => void): this;
    close(callback?: (err?: Error) => void): this;
    address(): AddressInfo | string | null;
  }

  export function createServer(requestListener?: RequestListener): Server;
  export function request(url: string | URL, options: RequestOptions, callback?: (res: IncomingMessage) => void): ClientRequest;
  export function request(options: RequestOptions, callback?: (res: IncomingMessage) => void): ClientRequest;
}

declare module 'node:https' {
  import { ClientRequest, IncomingMessage, RequestOptions } from 'node:http';
  export interface HttpsRequestOptions extends RequestOptions {
    rejectUnauthorized?: boolean;
  }
  export function request(url: string | URL, options: HttpsRequestOptions, callback?: (res: IncomingMessage) => void): ClientRequest;
  export function request(options: HttpsRequestOptions, callback?: (res: IncomingMessage) => void): ClientRequest;
}

declare module 'node:child_process' {
  import { EventEmitter } from 'node:events';
  import { Readable, Writable } from 'node:stream';

  export interface ExecFileOptions {
    cwd?: string;
    env?: Record<string, string | undefined>;
    timeout?: number;
    maxBuffer?: number;
    killSignal?: string | number;
    windowsHide?: boolean;
    shell?: boolean;
  }

  export interface ExecFileException extends Error {
    code?: number | string | null;
    killed?: boolean;
    signal?: string | null;
    cmd?: string;
  }

  export class ChildProcess extends EventEmitter {
    stdin: Writable | null;
    stdout: Readable | null;
    stderr: Readable | null;
    pid?: number;
    kill(signal?: string | number): boolean;
  }

  export function execFile(
    file: string,
    args: readonly string[],
    options: ExecFileOptions,
    callback: (error: ExecFileException | null, stdout: string, stderr: string) => void
  ): ChildProcess;

  export function spawn(
    command: string,
    args?: readonly string[],
    options?: { cwd?: string; env?: Record<string, string | undefined>; stdio?: ('pipe' | 'ignore' | 'inherit')[] }
  ): ChildProcess;
}

declare module 'node:fs' {
  export function existsSync(path: string): boolean;
  export function mkdirSync(path: string, options?: { recursive?: boolean }): string | undefined;
  export function rmSync(path: string, options?: { recursive?: boolean; force?: boolean }): void;
  export function readFileSync(path: string, encoding: BufferEncoding): string;
  export function writeFileSync(path: string, data: string | Uint8Array, encoding?: BufferEncoding): void;
  export function mkdtempSync(prefix: string): string;
  export function realpathSync(path: string): string;
}

declare module 'node:url' {
  export function fileURLToPath(url: string | URL): string;
}

declare module 'node:os' {
  export function tmpdir(): string;
  export function homedir(): string;
}

declare module 'node:path' {
  export function join(...paths: string[]): string;
  export function dirname(path: string): string;
  export function basename(path: string, suffix?: string): string;
  export function resolve(...paths: string[]): string;
}

declare module 'node:readline' {
  import { EventEmitter } from 'node:events';
  import { Readable, Writable } from 'node:stream';
  export interface Interface extends EventEmitter {
    close(): void;
    [Symbol.asyncIterator](): AsyncIterableIterator<string>;
  }
  export function createInterface(options: { input: Readable; output?: Writable; crlfDelay?: number; terminal?: boolean }): Interface;
}

declare module 'node:perf_hooks' {
  export const performance: {
    now(): number;
  };
}

declare module 'node:test' {
  export interface TestContext {
    name: string;
    after(fn: () => void | Promise<void>): void;
  }
  export type TestFn = (t: TestContext) => void | Promise<void>;
  export function describe(name: string, fn: () => void | Promise<void>): Promise<void>;
  export function test(name: string, fn: TestFn): Promise<void>;
  export function it(name: string, fn: TestFn): Promise<void>;
  export function before(fn: () => void | Promise<void>): void;
  export function after(fn: () => void | Promise<void>): void;
}

declare module 'node:assert/strict' {
  export function ok(value: unknown, message?: string | Error): asserts value;
  export function equal<T>(actual: unknown, expected: T, message?: string | Error): asserts actual is T;
  export function notEqual(actual: unknown, expected: unknown, message?: string | Error): void;
  export function deepEqual<T>(actual: unknown, expected: T, message?: string | Error): asserts actual is T;
  export function match(string: string, regexp: RegExp, message?: string | Error): void;
  export function doesNotMatch(string: string, regexp: RegExp, message?: string | Error): void;
  export function throws(block: () => unknown, error?: RegExp | (new (...args: any[]) => Error) | ((err: unknown) => boolean), message?: string | Error): void;
  export function rejects(block: (() => Promise<unknown>) | Promise<unknown>, error?: RegExp | (new (...args: any[]) => Error) | ((err: unknown) => boolean), message?: string | Error): Promise<void>;
}
