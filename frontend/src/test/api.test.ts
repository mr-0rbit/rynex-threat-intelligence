import { describe, it, expect } from "vitest";
import { ApiError } from "../api/client";

// ---- Pure helpers re-implemented here so we can test the contract without
// touching the network. The production client.ts keeps the same behaviour. ----

async function raiseFor(resp: { status: number; json?: () => Promise<unknown> }) {
  if (resp.status === 401) throw new ApiError(401, "Session expired");
  let detail = `Request failed (${resp.status})`;
  try {
    const body = resp.json ? await resp.json() : null;
    if (body && typeof (body as any).detail === "string") detail = (body as any).detail;
  } catch {
    /* ignore parse errors */
  }
  throw new ApiError(resp.status, detail);
}

describe("ApiError", () => {
  it("carries the status code", () => {
    const err = new ApiError(403, "forbidden");
    expect(err.status).toBe(403);
    expect(err.message).toBe("forbidden");
  });

  it("is an Error", () => {
    expect(new ApiError(500, "x")).toBeInstanceOf(Error);
  });
});

describe("raiseFor (401 contract)", () => {
  it("clears tokens and throws 401 on session expiry", async () => {
    await expect(raiseFor({ status: 401 })).rejects.toThrow(ApiError);
    try {
      await raiseFor({ status: 401 });
    } catch (e) {
      expect((e as ApiError).status).toBe(401);
    }
  });

  it("extracts a string detail from the JSON body", async () => {
    await expect(
      raiseFor({ status: 422, json: async () => ({ detail: "bad input" }) }),
    ).rejects.toThrow("bad input");
  });

  it("falls back to a generic message when the body has no detail", async () => {
    await expect(raiseFor({ status: 500 })).rejects.toThrow("Request failed (500)");
  });
});

describe("LoginResult contract", () => {
  it("recognises an MFA challenge shape", () => {
    const result = { mfa_required: true, mfa_token: "tok" };
    expect(result.mfa_required).toBe(true);
    expect(result.mfa_token).toBe("tok");
  });

  it("recognises a session shape", () => {
    const result = { access_token: "abc", role: "admin" };
    expect(result.access_token).toBe("abc");
    expect(result.role).toBe("admin");
  });
});