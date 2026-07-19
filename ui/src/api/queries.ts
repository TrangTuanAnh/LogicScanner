import { useQuery } from "@tanstack/react-query";
import {
  getFindings,
  getRepositoryAnalyses,
  getRepositoryAnalysis,
  getRuns,
  getSystemHealth,
} from "./client";

export const queryKeys = {
  repositories: ["repository-analyses"] as const,
  repositoryPage: (limit: number, offset: number) => ["repository-analyses", { limit, offset }] as const,
  repository: (id: string) => ["repository-analyses", id] as const,
  runs: ["runs"] as const,
  findings: ["findings"] as const,
  health: ["health"] as const,
};

export function useRepositoryAnalyses(limit = 20, offset = 0) {
  return useQuery({
    queryKey: queryKeys.repositoryPage(limit, offset),
    queryFn: () => getRepositoryAnalyses(limit, offset),
    refetchInterval: (query) =>
      query.state.data?.items.some((item) => ["queued", "fetching", "analyzing"].includes(item.status))
        ? 1_500
        : false,
  });
}

export function useRepositoryAnalysis(id: string) {
  return useQuery({
    queryKey: queryKeys.repository(id),
    queryFn: () => getRepositoryAnalysis(id),
    enabled: Boolean(id),
    refetchInterval: (query) =>
      query.state.data && ["queued", "fetching", "analyzing"].includes(query.state.data.item.status)
        ? 1_000
        : false,
  });
}

export function useRuns() {
  return useQuery({ queryKey: queryKeys.runs, queryFn: getRuns });
}

export function useFindings() {
  return useQuery({ queryKey: queryKeys.findings, queryFn: getFindings });
}

export function useSystemHealth() {
  return useQuery({ queryKey: queryKeys.health, queryFn: getSystemHealth, refetchInterval: 30_000 });
}
