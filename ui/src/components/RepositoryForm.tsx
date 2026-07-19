import { useState, type FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { ApiError, createRepositoryAnalysis } from "../api/client";
import { queryKeys } from "../api/queries";

const fullCommitPattern = /^[0-9a-f]{40}$/i;

export function RepositoryForm() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [commit, setCommit] = useState("");
  const [validationError, setValidationError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: createRepositoryAnalysis,
    onSuccess: async (analysis) => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.repositories });
      navigate(`/repositories/${analysis.id}`);
    },
  });

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setValidationError(null);
    mutation.reset();

    if (!repositoryUrl.trim()) {
      setValidationError("Repository URL is required.");
      return;
    }
    if (!fullCommitPattern.test(commit.trim())) {
      setValidationError("Commit must be a full 40-character SHA.");
      return;
    }
    mutation.mutate({
      name: name.trim() || undefined,
      repository_url: repositoryUrl.trim(),
      commit: commit.trim().toLowerCase(),
    });
  }

  const requestError = mutation.error
    ? mutation.error instanceof ApiError
      ? mutation.error.message
      : "The repository analysis could not be created."
    : null;
  const formError = validationError || requestError;

  return (
    <form className="repository-form" onSubmit={submit} noValidate>
      <div className="form-heading">
        <div>
          <p className="eyebrow">Static-first intake</p>
          <h2>Analyze a repository</h2>
        </div>
        <span className="safe-label">No target code executed</span>
      </div>

      <div className="form-grid">
        <div className="field optional-field">
          <label htmlFor="repository-name">Display name <span>(optional)</span></label>
          <input
            id="repository-name"
            name="name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="payments-service"
            autoComplete="off"
          />
        </div>
        <div className="field repository-url-field">
          <label htmlFor="repository-url">Repository URL</label>
          <input
            id="repository-url"
            name="repository_url"
            type="url"
            value={repositoryUrl}
            onChange={(event) => setRepositoryUrl(event.target.value)}
            placeholder="https://github.com/org/repository.git"
            required
            aria-required="true"
            aria-invalid={Boolean(formError)}
            aria-describedby={formError ? "repository-form-error" : "repository-url-help"}
            autoComplete="url"
          />
          <small id="repository-url-help">HTTPS Git URL; credentials are handled outside this form.</small>
        </div>
        <div className="field commit-field">
          <label htmlFor="repository-commit">Pinned commit SHA</label>
          <input
            id="repository-commit"
            name="commit"
            value={commit}
            onChange={(event) => setCommit(event.target.value)}
            placeholder="40 hexadecimal characters"
            minLength={40}
            maxLength={40}
            required
            aria-required="true"
            aria-invalid={Boolean(formError)}
            aria-describedby={formError ? "repository-form-error" : "commit-help"}
            spellCheck={false}
            autoCapitalize="none"
            autoComplete="off"
          />
          <small id="commit-help">Approvals and evidence remain bound to this exact tree.</small>
        </div>
      </div>

      <div className="form-footer">
        <div id="repository-form-error" className="form-message" role="alert" aria-live="assertive">
          {formError}
        </div>
        <button className="primary-button" type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? "Submitting…" : "Start static analysis"}
        </button>
      </div>
    </form>
  );
}
