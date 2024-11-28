import { bench, run } from "mitata";
import { Point, CURVE } from "..";

bench("small", () => {
  const G = new Point(CURVE.Gx, CURVE.Gy, 1n);
  G.multiplyDA(2n);
});

bench("big", () => {
  const G = new Point(CURVE.Gx, CURVE.Gy, 1n);
  G.multiplyDA(2n ** 255n - 19n);
});

await run();
