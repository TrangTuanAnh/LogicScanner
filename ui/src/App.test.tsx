import axe from "axe-core";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, test, vi } from "vitest";
import { App } from "./App";
import { normalizeAnalysis } from "./api/client";
import { SessionForm } from "./components/SessionForm";
import { renderWithProviders } from "./test/render";

function json(body: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

describe("LogicLab workbench", () => {
  test("falls back to clearly labeled demo data when the analysis API is unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn(() => json({ detail: "Not implemented" }, 404)));

    renderWithProviders(<App />);

    expect(await screen.findByRole("heading", { name: /security research, with a chain of custody/i })).toBeInTheDocument();
    expect(await screen.findByText("Demonstration data")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /atlas-commerce-api/i })).toHaveAttribute(
      "href",
      "/repositories/demo-atlas-api",
    );
  });

  test("submits the documented repository analysis contract and opens its dossier", async () => {
    const analysis = {
      id: "analysis-123",
      name: "payments-api",
      status: "queued",
      repository_url: "https://github.com/acme/payments-api.git",
      commit: "a".repeat(40),
      created_at: "2026-07-16T10:00:00Z",
      capabilities: { understanding: 0, runtime: 0, coverage: 0 },
      components: [],
      diagnostics: [],
      agent_tasks: [],
      claims: [],
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/repository-analyses") && init?.method === "POST") return json(analysis, 201);
      if (url.endsWith("/repository-analyses/analysis-123")) return json(analysis);
      return json({ items: [], total: 0 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    renderWithProviders(<App />, { route: "/repositories" });
    await screen.findByRole("heading", { name: "Analyze a repository" });
    await user.type(screen.getByLabelText("Display name (optional)"), "payments-api");
    await user.type(screen.getByLabelText("Repository URL"), analysis.repository_url);
    await user.type(screen.getByLabelText("Pinned commit SHA"), analysis.commit);
    await user.click(screen.getByRole("button", { name: "Start static analysis" }));

    expect(await screen.findByRole("heading", { name: "payments-api", level: 1 })).toBeInTheDocument();
    const postCall = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(postCall?.[0]).toBe("/v1/repository-analyses");
    expect(postCall?.[1]).toMatchObject({ credentials: "include" });
    expect(JSON.parse(String(postCall?.[1]?.body))).toEqual({
      name: "payments-api",
      repository_url: analysis.repository_url,
      commit: analysis.commit,
    });
  });

  test("renders FastAPI validation issues as readable form errors", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith("/repository-analyses") && init?.method === "POST") {
        return json(
          {
            detail: [
              {
                type: "value_error",
                loc: ["body", "repository_url"],
                msg: "Value error, repository host is not allowlisted",
              },
            ],
          },
          422,
        );
      }
      return json({ items: [], total: 0 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    renderWithProviders(<App />, { route: "/repositories" });
    await screen.findByRole("heading", { name: "Analyze a repository" });
    await user.type(screen.getByLabelText("Repository URL"), "https://evil.example/repo.git");
    await user.type(screen.getByLabelText("Pinned commit SHA"), "a".repeat(40));
    await user.click(screen.getByRole("button", { name: "Start static analysis" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "repository url: repository host is not allowlisted",
    );
    expect(screen.queryByText("[object Object]")).not.toBeInTheDocument();
  });

  test("exchanges a token for a cookie without writing browser storage", async () => {
    const fetchMock = vi.fn(() => Promise.resolve(new Response(null, { status: 204 })));
    vi.stubGlobal("fetch", fetchMock);
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();

    renderWithProviders(<SessionForm />);
    await user.type(screen.getByLabelText("API token"), "local-secret-token");
    await user.click(screen.getByRole("button", { name: "Unlock API" }));

    expect(await screen.findByText(/exchanged for an HttpOnly cookie/i)).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      "/v1/session",
      expect.objectContaining({
        method: "POST",
        credentials: "include",
        body: JSON.stringify({ token: "local-secret-token" }),
      }),
    );
    expect(storageSpy).not.toHaveBeenCalled();
    expect(screen.getByLabelText("API token")).toHaveValue("");
  });

  test("renders the main repository intake route without detectable axe violations", async () => {
    vi.stubGlobal("fetch", vi.fn(() => json({ items: [], total: 0 })));
    const { container } = renderWithProviders(<App />, { route: "/repositories" });
    await screen.findByRole("heading", { name: "Analyze a repository" });

    const results = await axe.run(container, {
      rules: { "color-contrast": { enabled: false } },
    });
    expect(results.violations).toEqual([]);
  });

  test("rejects repository payloads that omit chain-of-custody fields", () => {
    expect(() =>
      normalizeAnalysis({
        name: "payments-api",
        status: "ready",
        repository_url: "https://github.com/acme/payments-api.git",
        commit: "a".repeat(40),
        capabilities: { understanding: 100, runtime: 0, coverage: 100 },
        components: [],
        diagnostics: [],
        agent_tasks: [],
        claims: [],
      }),
    ).toThrow(/API_CONTRACT_INVALID.*id/i);

    expect(() =>
      normalizeAnalysis({
        id: "analysis-123",
        name: "payments-api",
        status: "ready",
        repository_url: "https://github.com/acme/payments-api.git",
        commit: "a".repeat(40),
        capabilities: { understanding: 100, runtime: 0, coverage: 100 },
        components: [],
        diagnostics: [],
        agent_tasks: [],
        claims: [],
      }),
    ).toThrow(/API_CONTRACT_INVALID.*created_at/i);
  });

  test("does not replace an invalid API contract with demonstration data", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        json({
          items: [
            {
              name: "missing-provenance",
              status: "ready",
              repository_url: "https://github.com/acme/missing.git",
              commit: "a".repeat(40),
              created_at: "2026-07-16T10:00:00Z",
              capabilities: { understanding: 100, runtime: 0, coverage: 100 },
              components: [],
              diagnostics: [],
              agent_tasks: [],
              claims: [],
            },
          ],
          total: 1,
        }),
      ),
    );

    renderWithProviders(<App />);

    expect(await screen.findByRole("alert")).toHaveTextContent(/API_CONTRACT_INVALID.*id/i);
    expect(screen.queryByText("Demonstration data")).not.toBeInTheDocument();
  });

  test("preserves the initial keyboard entry point and focuses hash targets after navigation", async () => {
    vi.stubGlobal("fetch", vi.fn(() => json({ items: [], total: 0 })));
    const scrollIntoView = vi.fn();
    Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
      configurable: true,
      value: scrollIntoView,
    });
    vi.spyOn(window, "requestAnimationFrame").mockImplementation((callback) => {
      callback(0);
      return 1;
    });
    const user = userEvent.setup();

    renderWithProviders(<App />, { route: "/repositories" });
    await screen.findByRole("heading", { name: "Repository analyses", level: 1 });
    expect(document.activeElement).not.toHaveAttribute("id", "main-content");

    await user.click(screen.getByRole("link", { name: "Unlock API" }));
    const heading = await screen.findByRole("heading", { name: "Control API session" });
    const target = heading.closest("section");
    await waitFor(() => expect(document.activeElement).toBe(target));
    expect(scrollIntoView).toHaveBeenCalledWith({ block: "start" });
  });

  test("renders an h1 on the not-found route", async () => {
    vi.stubGlobal("fetch", vi.fn(() => json({ items: [], total: 0 })));

    renderWithProviders(<App />, { route: "/not-a-route" });

    expect(
      await screen.findByRole("heading", { name: "Workbench route not found", level: 1 }),
    ).toBeInTheDocument();
  });
});
