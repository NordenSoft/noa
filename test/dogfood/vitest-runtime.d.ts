/**
 * test/dogfood/vitest-runtime.d.ts — PRIVATE ambient type shim for the `vitest` test-runner.
 *
 * Why this exists: the dogfood test (./replay.test.ts) imports from "vitest", but vitest is NOT
 * a project dependency (it runs from the npx cache: `npx vitest run …` resolves the `vitest`
 * specifier to its own installation at runtime). `tsc --noEmit` would therefore emit
 * TS2307 ("Cannot find module 'vitest'") on that import. This file declares a minimal, permissive
 * ambient module so the PRIVATE dogfood test typechecks WITHOUT touching package.json / installing
 * anything. Runtime types come from vitest itself; this is a static-typecheck stand-in only.
 *
 * NOT published (under test/), and scoped to the dogfood surface this harness actually uses.
 */
declare module "vitest" {
  export interface Matchers<T = unknown> {
    toBe(expected: unknown): void;
    toEqual(expected: unknown): void;
    toStrictEqual(expected: unknown): void;
    toBeInstanceOf(expected: unknown): void;
    toMatch(expected: unknown): void;
    toContain(expected: unknown): void;
    toHaveLength(expected: number): void;
    toBeTruthy(): void;
    toBeFalsy(): void;
    toBeNull(): void;
    toBeDefined(): void;
    toBeUndefined(): void;
    toBeGreaterThan(expected: number): void;
    toBeGreaterThanOrEqual(expected: number): void;
    toBeLessThan(expected: number): void;
    toBeLessThanOrEqual(expected: number): void;
    toThrow(expected?: unknown): void;
    readonly not: Matchers<T>;
  }
  export function expect<T = unknown>(actual: T): Matchers<T>;
  export function describe(name: string, fn: () => void): void;
  export function it(name: string, fn: () => void | Promise<void>): void;
  export const test: typeof it;
  export function beforeAll(fn: () => void | Promise<void>): void;
  export function beforeEach(fn: () => void | Promise<void>): void;
}
