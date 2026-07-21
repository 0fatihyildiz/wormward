import { describe, it, expect } from "vitest";
import { humanizeError } from "./errors";

describe("humanizeError", () => {
  it("maps 401 to an auth failure", () => {
    expect(humanizeError("Error: 401 Client Error")).toBe(
      "Authentication failed — check your token in Settings.",
    );
  });

  it("maps 'unauthorized' to an auth failure", () => {
    expect(humanizeError("request was unauthorized")).toBe(
      "Authentication failed — check your token in Settings.",
    );
  });

  it("maps 'bad credentials' to an auth failure", () => {
    expect(humanizeError("Bad credentials")).toBe(
      "Authentication failed — check your token in Settings.",
    );
  });

  it("maps 403 to a missing-scope message", () => {
    expect(humanizeError("Error: 403")).toBe(
      "GitHub refused the request — your token is missing a required scope. Give it repo read (and write, to fix) access in Settings.",
    );
  });

  it("maps 'forbidden' to a missing-scope message", () => {
    expect(humanizeError("Forbidden")).toBe(
      "GitHub refused the request — your token is missing a required scope. Give it repo read (and write, to fix) access in Settings.",
    );
  });

  it("maps 'rate limit' to a distinct wait-and-retry message", () => {
    expect(humanizeError("github rate limit: HTTP 403 from ...")).toBe(
      "GitHub rate limit reached — wormward paused and retried, but it's still limited. Wait a few minutes and try again.",
    );
  });

  it("maps network failures", () => {
    expect(humanizeError("failed to connect: connection timed out")).toBe(
      "Network error — couldn't reach the server. Check your connection and retry.",
    );
  });

  it("maps the OSM token requirement", () => {
    expect(humanizeError("online scan requires a token")).toBe(
      "Online cross-check needs an OpenSourceMalware token — add one in Settings.",
    );
  });

  it("passes unknown errors through, stripping the 'error:' prefix", () => {
    expect(humanizeError("Error: something odd happened")).toBe(
      "something odd happened",
    );
  });
});
