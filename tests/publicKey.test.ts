import { expect, test, describe } from "bun:test";
import {
  utils,
  getPublicKey,
  ProjectivePoint,
  signAsync,
} from "@noble/secp256k1";
import {
  Point,
  CURVE,
  bytesToBigInt,
  signZero,
  verifyZero,
  Signature,
} from "..";
describe("public key", () => {
  test("random private key", () => {
    const privKey = utils.randomPrivateKey();
    const secp256k1Point = ProjectivePoint.fromPrivateKey(privKey);

    const G = new Point(CURVE.Gx, CURVE.Gy, 1n);
    const pubKeyPoint = G.multiplyDA(utils.normPrivateKeyToScalar(privKey));

    expect(pubKeyPoint.x).toBe(secp256k1Point.x);
    expect(pubKeyPoint.y).toBe(secp256k1Point.y);
    // secp256k1Point;
  });

  test("sign", async () => {
    const privKey = utils.randomPrivateKey();
    const privBigint = bytesToBigInt(privKey);

    const msgHash =
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    const signatureExpect = await signAsync(msgHash, privKey);
    const signature = await signZero(msgHash, privBigint);

    expect(signature.r).toBe(signatureExpect.r);
    expect(signature.s).toBe(signatureExpect.s);
    expect(signature.recovery).toBe(signatureExpect.recovery);
  });

  test("verify", async () => {
    const privKey = utils.randomPrivateKey();
    const publicKey = ProjectivePoint.fromPrivateKey(privKey);
    const publicPoint = new Point(publicKey.px, publicKey.py, publicKey.pz);
    const msgHash =
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    const signature = await signAsync(msgHash, privKey);
    const signatureZero = new Signature(
      signature.r,
      signature.s,
      signature.recovery,
    );
    const isVaild = await verifyZero(signatureZero, publicPoint, msgHash);

    expect(isVaild).toBe(true);
  });

  test("verify err", async () => {
    const privKey = utils.randomPrivateKey();
    const publicKey = ProjectivePoint.fromPrivateKey(privKey);
    const publicPoint = new Point(publicKey.px, publicKey.py, publicKey.pz);
    const msgHash =
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    const signature = await signAsync(msgHash, privKey);
    const signatureZero = new Signature(
      signature.r,
      signature.s,
      signature.recovery,
    );
    const isVaild = await verifyZero(
      signatureZero,
      publicPoint,
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcdf9",
    );

    expect(isVaild).toBe(false);
  });

  test("point from x", async () => {
    const privKey = utils.randomPrivateKey();
    const publicKey = ProjectivePoint.fromPrivateKey(privKey);
    const publicPoint = new Point(
      publicKey.px,
      publicKey.py,
      publicKey.pz,
    ).toAffine();

    const pointFromX = Point.fromX(
      publicPoint.x,
      (publicPoint.y & 1n) === 1n,
    ).toAffine();

    expect(pointFromX.y).toBe(publicPoint.y);
  });

  test("recovery public point", async () => {
    const privKey = utils.randomPrivateKey();
    const publicKey = ProjectivePoint.fromPrivateKey(privKey);
    const publicPoint = new Point(publicKey.px, publicKey.py, publicKey.pz);
    const msgHash =
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    const signature = await signAsync(msgHash, privKey);
    const signatureZero = new Signature(
      signature.r,
      signature.s,
      signature.recovery,
    );

    const publicPointRecovery = signatureZero.recoverPublicKey(msgHash);
    expect(publicPoint.x).toBe(publicPointRecovery.x);
    expect(publicPoint.y).toBe(publicPointRecovery.y);
  });
});
