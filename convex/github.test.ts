import { describe, expect, it } from "vitest";
import { decodeBoundedBase64 } from "./github";

describe("decodeBoundedBase64", () => {
  it("decodes content within the byte limit", () => {
    expect(decodeBoundedBase64(btoa("hello"), 5)).toEqual({ content: "hello", size: 5 });
  });

  it("rejects decoded content above the byte limit", () => {
    expect(decodeBoundedBase64(btoa("oversized"), 4)).toBeNull();
  });
});
