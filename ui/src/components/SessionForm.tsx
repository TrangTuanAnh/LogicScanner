import { useState, type FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { createSession, deleteSession } from "../api/client";

export function SessionForm() {
  const queryClient = useQueryClient();
  const [token, setToken] = useState("");
  const [message, setMessage] = useState("");

  const unlock = useMutation({
    mutationFn: createSession,
    onSuccess: async () => {
      setToken("");
      setMessage("API session unlocked. The token was exchanged for an HttpOnly cookie.");
      await queryClient.invalidateQueries();
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : "Unable to unlock the API session."),
  });

  const lock = useMutation({
    mutationFn: deleteSession,
    onSuccess: async () => {
      setToken("");
      setMessage("API session locked and cached control-plane data cleared.");
      queryClient.clear();
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : "Unable to lock the API session."),
  });

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage("");
    if (!token.trim()) {
      setMessage("Enter the local control-plane token.");
      return;
    }
    unlock.mutate(token.trim());
  }

  return (
    <section
      id="session"
      className="session-section"
      aria-labelledby="session-heading"
      tabIndex={-1}
    >
      <div>
        <p className="eyebrow">Local authentication</p>
        <h2 id="session-heading">Control API session</h2>
        <p>The token is exchanged once for an HttpOnly cookie and is never persisted by this UI.</p>
      </div>
      <form className="session-form" onSubmit={submit} noValidate>
        <div className="field">
          <label htmlFor="api-token">API token</label>
          <input
            id="api-token"
            type="password"
            value={token}
            onChange={(event) => setToken(event.target.value)}
            autoComplete="current-password"
            required
            aria-required="true"
            aria-describedby="session-message"
          />
        </div>
        <div className="session-actions">
          <button className="primary-button" type="submit" disabled={unlock.isPending || lock.isPending}>
            {unlock.isPending ? "Unlocking…" : "Unlock API"}
          </button>
          <button className="secondary-button" type="button" disabled={unlock.isPending || lock.isPending} onClick={() => lock.mutate()}>
            Lock session
          </button>
        </div>
        <p id="session-message" className="form-message" role="status" aria-live="polite">{message}</p>
      </form>
    </section>
  );
}
