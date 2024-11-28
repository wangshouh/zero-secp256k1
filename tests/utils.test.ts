import { expect, test, describe } from "bun:test";
import { invert, mod, naf } from "..";

describe("f29 fields arithmetic", () => {
  test("17 + 20", () => {
    expect(mod(17n + 20n, 29n)).toBe(8n);
  });

  test("17 − 20", () => {
    expect(mod(17n - 20n, 29n)).toBe(26n);
  });

  test("17 * 20", () => {
    expect(mod(17n * 20n, 29n)).toBe(21n);
  });

  test("17^(-1)", () => {
    expect(invert(17n, 29n)).toBe(12n);
  });
});

describe("naf", () => {
  test("naf(7) = 1 0 0 −1", () => {
    expect(naf(7n)).toEqual([1n, 0n, 0n, -1n]);
  });
});
