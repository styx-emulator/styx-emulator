import { HexPipe } from "./hex.pipe";

describe("HexPipe", () => {
  it("create an instance", () => {
    const pipe = new HexPipe();
    expect(pipe).toBeTruthy();
  });
});
