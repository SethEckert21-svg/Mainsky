import { useCallback, useRef, useState } from "react";
import {
  FileMatch,
  SearchAbortedError,
  searchFiles,
} from "@/utils/searchFiles";

export type SearchStatus = "idle" | "searching" | "done" | "error" | "stopped";

export interface UseFileSearchReturn {
  results: FileMatch[];
  status: SearchStatus;
  error: string | null;
  search: (query: string) => void;
  stop: () => void;
}

export function useFileSearch(): UseFileSearchReturn {
  const [results, setResults] = useState<FileMatch[]>([]);
  const [status, setStatus] = useState<SearchStatus>("idle");
  const [error, setError] = useState<string | null>(null);

  const abortRef = useRef<AbortController | null>(null);

  const stop = useCallback(() => {
    abortRef.current?.abort();
  }, []);

  const search = useCallback((query: string) => {
    // Cancel any in-flight search before starting a new one.
    abortRef.current?.abort();

    const controller = new AbortController();
    abortRef.current = controller;

    setResults([]);
    setError(null);
    setStatus("searching");

    searchFiles(query, { signal: controller.signal })
      .then((matches) => {
        setResults(matches);
        setStatus("done");
      })
      .catch((err: unknown) => {
        if (err instanceof SearchAbortedError || controller.signal.aborted) {
          setStatus("stopped");
        } else {
          setError(err instanceof Error ? err.message : "Unknown error");
          setStatus("error");
        }
      });
  }, []);

  return { results, status, error, search, stop };
}
