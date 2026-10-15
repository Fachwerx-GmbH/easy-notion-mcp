import { createCipheriv, createDecipheriv, createHash, randomBytes } from "crypto";
import { Redis } from "@upstash/redis";

/**
 * The one piece of shared state the OAuth flow needs. Every serverless
 * instance reads and writes through it, so no request depends on landing on
 * the instance that served the previous one.
 */
export interface Kv {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown, ttlSeconds?: number): Promise<void>;
  /** Read and delete in one step, so a value can be consumed only once. */
  take<T>(key: string): Promise<T | undefined>;
  del(key: string): Promise<void>;
}

export function redisKv(redis: Redis): Kv {
  return {
    async get<T>(key: string) {
      return (await redis.get<T>(key)) ?? undefined;
    },
    async set(key, value, ttlSeconds) {
      if (ttlSeconds) await redis.set(key, value, { ex: ttlSeconds });
      else await redis.set(key, value);
    },
    async take<T>(key: string) {
      return (await redis.getdel<T>(key)) ?? undefined;
    },
    async del(key) {
      await redis.del(key);
    },
  };
}

// ponytail: single-process only. Local development and tests; production uses Redis.
export function memoryKv(): Kv {
  const entries = new Map<string, { value: unknown; expiresAt?: number }>();
  const read = (key: string) => {
    const entry = entries.get(key);
    if (entry?.expiresAt && entry.expiresAt <= Date.now()) {
      entries.delete(key);
      return undefined;
    }
    return entry;
  };
  return {
    async get<T>(key: string) {
      return read(key)?.value as T | undefined;
    },
    async set(key, value, ttlSeconds) {
      entries.set(key, {
        value: structuredClone(value),
        expiresAt: ttlSeconds ? Date.now() + ttlSeconds * 1000 : undefined,
      });
    },
    async take<T>(key: string) {
      const entry = read(key);
      entries.delete(key);
      return entry?.value as T | undefined;
    },
    async del(key) {
      entries.delete(key);
    },
  };
}

/**
 * Redis when the environment names one (Upstash's own variables, or the
 * KV_REST_API_* pair the Vercel Marketplace integration injects).
 */
export function redisKvFromEnv(env: NodeJS.ProcessEnv): Kv | undefined {
  const url = env.UPSTASH_REDIS_REST_URL ?? env.KV_REST_API_URL;
  const token = env.UPSTASH_REDIS_REST_TOKEN ?? env.KV_REST_API_TOKEN;
  if (url && token) return redisKv(new Redis({ url, token, automaticDeserialization: false }));
  if (env.VERCEL) {
    throw new Error("OAuth mode on Vercel needs Redis: set UPSTASH_REDIS_REST_URL/TOKEN or KV_REST_API_URL/TOKEN");
  }
  return undefined;
}

/**
 * AES-256-GCM key for everything the OAuth flow stores. TOKEN_ENC_KEY holds 32
 * bytes as base64 (`openssl rand -base64 32`). Without it a process-local key
 * is generated, which only works with the memory store.
 */
export function encryptionKeyFromEnv(env: NodeJS.ProcessEnv, durable: boolean): Buffer {
  if (!env.TOKEN_ENC_KEY) {
    if (durable) throw new Error("TOKEN_ENC_KEY is required when OAuth state lives in Redis");
    return randomBytes(32);
  }
  const key = Buffer.from(env.TOKEN_ENC_KEY, "base64");
  if (key.length !== 32) throw new Error("TOKEN_ENC_KEY must be 32 bytes, base64-encoded");
  return key;
}

/**
 * Wraps a store so it only ever sees SHA-256 hashed keys and AES-256-GCM
 * sealed values. Bearer tokens, auth codes and Notion tokens all sit in keys
 * or values, so a leaked Redis snapshot yields none of them.
 */
export function sealedKv(inner: Kv, key: Buffer): Kv {
  const hashKey = (k: string) => createHash("sha256").update(k).digest("base64url");
  const seal = (value: unknown) => {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const data = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
    return [iv, cipher.getAuthTag(), data].map((b) => b.toString("base64")).join(":");
  };
  const open = <T>(blob: string | undefined): T | undefined => {
    if (blob === undefined) return undefined;
    const [iv, tag, data] = blob.split(":").map((part) => Buffer.from(part, "base64"));
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return JSON.parse(Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8")) as T;
  };
  return {
    get: async <T>(k: string) => open<T>(await inner.get<string>(hashKey(k))),
    set: (k, value, ttl) => inner.set(hashKey(k), seal(value), ttl),
    take: async <T>(k: string) => open<T>(await inner.take<string>(hashKey(k))),
    del: (k) => inner.del(hashKey(k)),
  };
}
