export const CURVE = {
  P: 2n ** 256n - 2n ** 32n - 977n,
  n: 2n ** 256n - 432420386565659656852420866394968145599n,
  b: 7n,
  Gx: 55066263022277343669578718895168534326250603453777594175500187360389116729240n,
  Gy: 32670510020758816978083085130507043184471273380659243275938904335757337482424n,
};

export interface AffinePoint {
  x: bigint;
  y: bigint;
}

export class Point {
  static readonly BASE = new Point(CURVE.Gx, CURVE.Gy, 1n);
  static readonly ZERO = new Point(0n, 1n, 0n);
  constructor(
    readonly px: bigint,
    readonly py: bigint,
    readonly pz: bigint,
  ) {}

  static fromAffine(p: AffinePoint) {
    return p.x === 0n && p.y === 0n ? Point.ZERO : new Point(p.x, p.y, 1n);
  }

  add(other: Point) {
    const { px: X1, py: Y1, pz: Z1 } = this;
    const { px: X2, py: Y2, pz: Z2 } = other;

    let X3 = 0n,
      Y3 = 0n,
      Z3 = 0n;
    const b3 = mod(21n);

    let t0 = mod(X1 * X2), // 1
      t1 = mod(Y1 * Y2), // 2
      t2 = mod(Z1 * Z2), // 3
      t3 = mod(X1 + Y1), // 4
      t4 = mod(X2 + Y2); // 5
    t3 = mod(t3 * t4); // 6
    t4 = mod(t0 + t1); // 7
    t3 = mod(t3 - t4); // 8
    t4 = mod(Y1 + Z1); // 9
    X3 = mod(Y2 + Z2); // 10
    t4 = mod(t4 * X3); // 11
    X3 = mod(t1 + t2); // 12
    t4 = mod(t4 - X3); // 13
    X3 = mod(X1 + Z1); // 14
    Y3 = mod(X2 + Z2); // 15
    X3 = mod(X3 * Y3); // 16
    Y3 = mod(t0 + t2); // 17
    Y3 = mod(X3 - Y3); // 18
    X3 = mod(t0 + t0); // 19
    t0 = mod(X3 + t0); // 20
    t2 = mod(b3 * t2); // 21
    Z3 = mod(t1 + t2); // 22
    t1 = mod(t1 - t2); // 23
    Y3 = mod(b3 * Y3); // 24
    X3 = mod(t4 * Y3); // 25
    t2 = mod(t3 * t1); // 26
    X3 = mod(t2 - X3); // 27
    Y3 = mod(Y3 * t0); // 28
    t1 = mod(t1 * Z3); // 29
    Y3 = mod(t1 + Y3); // 30
    t0 = mod(t0 * t3); // 31
    Z3 = mod(Z3 * t4); // 32
    Z3 = mod(Z3 + t0); // 33

    return new Point(X3, Y3, Z3);
  }

  double() {
    return this.add(this);
  }

  equals(other: Point): boolean {
    const { px: X1, py: Y1, pz: Z1 } = this;
    const { px: X2, py: Y2, pz: Z2 } = other;
    const X1Z2 = mod(X1 * Z2),
      X2Z1 = mod(X2 * Z1);
    const Y1Z2 = mod(Y1 * Z2),
      Y2Z1 = mod(Y2 * Z1);
    return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
  }

  toAffine(): AffinePoint {
    const { px: x, py: y, pz: z } = this;
    if (this.equals(I)) return { x: 0n, y: 0n };
    if (z === 1n) return { x, y };

    const iz = invert(z);
    if (mod(z * iz) !== 1n) throw new Error("invalid inverse");
    return { x: mod(x * iz), y: mod(y * iz) };
  }

  static fromX(x: bigint, headOdd: Boolean): Point {
    let p: Point | undefined = undefined;
    let y = sqrt(crv(x));
    const isYOdd = (y & 1n) === 1n;

    if (headOdd !== isYOdd) y = mod(-y);
    p = new Point(x, y, 1n);

    return p;
  }

  aff() {
    return this.toAffine();
  }

  get x() {
    return this.aff().x;
  }
  get y() {
    return this.aff().y;
  }

  negate() {
    return new Point(this.px, mod(-this.py), this.pz);
  }

  mul(n: bigint, safe = true): Point {
    if (this.equals(G)) return wNAF(n).p;
    let p = I,
      f = G;
    for (let d: Point = this; n > 0n; d = d.double(), n >>= 1n) {
      if (n & 1n) p = p.add(d);
      else if (safe) f = f.add(d);
    }
    return p;
  }

  mulAddQUns(R: Point, u1: bigint, u2: bigint): Point {
    return this.mul(u1, false).add(R.mul(u2, false));
  }

  multiplyDA(n: bigint): Point {
    return wNAF(n).p;
  }
}

const crv = (x: bigint) => mod(mod(x * x) * x + CURVE.b);

export class Signature {
  constructor(
    readonly r: bigint,
    readonly s: bigint,
    readonly recovery: number,
  ) {}

  recoverPublicKey(msgh: string): Point {
    const { r, s, recovery: rec } = this;
    if (![0, 1, 2, 3].includes(rec!)) throw new Error("recovery id invalid");
    const h = mod(bits2int(hexToBytes(msgh)), N);
    const radj = rec === 2 || rec === 3 ? r + N : r;
    if (radj >= CURVE.P) throw new Error("q.x invalid");
    const headOdd = (rec! & 1) === 0 ? false : true;
    const R = Point.fromX(radj, headOdd);
    const ir = invert(radj, N);
    const u1 = mod(-h * ir, N);
    const u2 = mod(s * ir, N);
    return G.mulAddQUns(R, u1, u2);
  }
}

export const mod = (a: bigint, b: bigint = CURVE.P): bigint => {
  const result = a % b;
  return result >= 0 ? result : b + result;
};

export const invert = (number: bigint, modulo: bigint = CURVE.P): bigint => {
  if (number === 0n || modulo <= 0n) {
    throw new Error(
      `invert: expected positive integers, got n=${number} mod=${modulo}`,
    );
  }

  let a = mod(number, modulo);
  let b = modulo;
  let x = 0n,
    y = 1n,
    u = 1n,
    v = 0n;
  while (a !== 0n) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;

    b = a;
    a = r;
    x = u;
    y = v;
    u = m;
    v = n;
  }
  const gcd = b;
  if (gcd !== 1n) throw new Error("invert: does not exist");
  return mod(x, modulo);
};

export const naf = (number: bigint): bigint[] => {
  let k = number;
  let result: bigint[] = [];
  while (k >= 1) {
    let ki: bigint;
    if (k & 1n) {
      ki = 2n - mod(k, 4n);
      k -= ki;
    } else {
      ki = 0n;
    }

    k = k / 2n;

    result.push(ki);
  }

  return result.reverse();
};

const sqrt = (n: bigint) => {
  let r = 1n;
  for (let num = n, e = (CURVE.P + 1n) / 4n; e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * num) % CURVE.P;
    num = (num * num) % CURVE.P;
  }
  if (mod(r * r) !== n) {
    throw new Error("sqrt invalid");
  }
  return r;
};

const W = 8;
const { BASE: G, ZERO: I } = Point;
const precompute = () => {
  const points: Point[] = [];
  const windows = 256 / W + 1;
  let p = G,
    b = p;

  for (let w = 0; w < windows; w++) {
    b = p;
    points.push(b);
    for (let i = 1; i < 2 ** (W - 1); i++) {
      b = b.add(p);
      points.push(b);
    }
    p = b.double();
  }

  return points;
};

let Gpows: Point[] | undefined = undefined;
export const wNAF = (n: bigint): { p: Point; f: Point } => {
  const comp = Gpows || (Gpows = precompute());
  const neg = (cnd: boolean, p: Point) => {
    let n = p.negate();
    return cnd ? n : p;
  };

  let p = I;
  let f = G;

  const windows = 256 / W + 1;
  const mask = BigInt(2 ** W - 1);
  const wsize = 2 ** (W - 1);
  const maxNum = 2 ** W;
  const shiftBy = BigInt(W);
  for (let w = 0; w < windows; w++) {
    let wbits = Number(n & mask);
    n >>= shiftBy;
    if (wbits > wsize) {
      wbits -= maxNum;
      n += 1n;
    }
    const off = w * wsize;
    const off2 = off + Math.abs(wbits) - 1;

    if (wbits === 0) {
      f = f.add(neg(w % 2 !== 0, comp[off]));
    } else {
      p = p.add(neg(wbits < 0, comp[off2]));
    }
  }
  return { p, f };
};

type Bytes = Uint8Array;
type Hex = Bytes | string;
type PrivKey = Hex | bigint;

const B256 = 2n ** 256n;
const N = B256 - 0x14551231950b75fc4402da1732fc9bebfn;
const fLen = 32;

const padh = (n: number | bigint, pad: number) =>
  n.toString(16).padStart(pad, "0");

const hexToBytes = (hex: string): Bytes => {
  const l = hex.length;
  const arr = new Uint8Array(l / 2);
  for (let i = 0; i < arr.length; i++) {
    const j = i * 2;
    const h = hex.slice(j, j + 2);
    const b = Number.parseInt(h, 16);
    arr[i] = b;
  }

  return arr;
};

const bytesToHex = (b: Bytes): string =>
  Array.from(b)
    .map((e) => padh(e, 2))
    .join("");

export const bytesToBigInt = (b: Bytes): bigint =>
  BigInt("0x" + (bytesToHex(b) || "0"));

const bigintToBytes = (num: bigint): Bytes => {
  return hexToBytes(padh(num, 2 * fLen));
};

const bits2int = (bytes: Uint8Array): bigint => {
  const delta = bytes.length * 8 - 256;

  const num = bytesToBigInt(bytes);
  return delta > 0 ? num >> BigInt(delta) : num;
};

const concatBytes = (...arrs: Bytes[]) => {
  const r = new Uint8Array(arrs.reduce((sum, a) => sum + a.length, 0));
  let pad = 0;
  arrs.forEach((a) => {
    r.set(a, pad);
    pad += a.length;
  });
  return r;
};

const hmacSha256 = async (key: Bytes, ...msgs: Bytes[]) => {
  const hasher = new Bun.CryptoHasher("sha256", key);
  hasher.update(concatBytes(...msgs));

  return new Uint8Array(hasher.digest());
};

const moreThanHalfN = (n: bigint): boolean => n > N >> 1n;

export const prepSig = (msg: string, priv: bigint, lowS = true) => {
  const h1i = mod(bits2int(hexToBytes(msg)), N);
  const h1o = hexToBytes(padh(h1i, 2 * fLen));

  const seed = concatBytes(bigintToBytes(priv), h1o);
  const m = h1i;

  const k2sig = (kBytes: Bytes) => {
    const k = bits2int(kBytes);
    if (k > CURVE.n) return;
    const ik = invert(k, N);
    const q = G.multiplyDA(k).aff(); // q = kG
    const r = mod(q.x, N);
    if (r === 0n) return;
    const s = mod(ik * mod(m + mod(priv * r, N), N), N);
    if (s === 0n) return;
    let normS = s;
    let rec = (q.x === r ? 0 : 2) | Number(q.y & 1n);
    if (lowS && moreThanHalfN(s)) {
      normS = mod(-s, N);
      rec ^= 1;
    }

    return new Signature(r, normS, rec);
  };
  return { seed, k2sig };
};

type Pred = (v: Uint8Array) => Signature | undefined;
export const hmacDrbg = () => {
  let v = new Uint8Array(fLen);
  let k = new Uint8Array(fLen);
  let i = 0;

  const reset = () => {
    v.fill(1);
    k.fill(0);
    i = 0;
  };

  const h = (...b: Bytes[]) => hmacSha256(k, v, ...b);

  const reseed = async (seed: Bytes = new Uint8Array()) => {
    k = await h(new Uint8Array([0x00]), seed); // k = hmac_K(V || 0x00 || seed)
    v = await h(); // v = HMAC_K(v)
    k = await h(new Uint8Array([0x01]), seed); // k = hmac_K(V || 0x01 || seed)
    v = await h();
  };

  const gen = async () => {
    if (i++ >= 1000) throw new Error("drbg: tried 1000 values");
    v = await h();
    return v;
  };

  return async (seed: Bytes, pred: Pred) => {
    reset();
    await reseed(seed);
    let res: Signature | undefined = undefined;
    while (!(res = pred(await gen()))) await reseed();
    reset();
    return res!;
  };
};

export const signZero = async (
  msgh: string,
  priv: bigint,
  lowS = true,
): Promise<Signature> => {
  const { seed, k2sig } = prepSig(msgh, priv, lowS);
  return hmacDrbg()(seed, k2sig);
};

export const verifyZero = async (
  sig: Signature,
  publicKey: Point,
  msgh: string,
  lowS = true,
) => {
  if (lowS && moreThanHalfN(sig.s)) return false;
  const h = mod(bits2int(hexToBytes(msgh)), N);
  let R: AffinePoint;
  try {
    const w = invert(sig.s, N);
    const u1 = mod(h * w, N);
    const u2 = mod(sig.r * w, N);
    R = G.mulAddQUns(publicKey, u1, u2).aff();
  } catch (e) {
    return false;
  }

  const v = mod(R.x, N);
  return v === sig.r;
};
