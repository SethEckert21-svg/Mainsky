export interface FileMatch {
  path: string;
  name: string;
  size: number;
  lastModified: number;
}

export interface SearchOptions {
  signal?: AbortSignal;
  maxResults?: number;
}

export class SearchAbortedError extends Error {
  constructor() {
    super("File search was stopped.");
    this.name = "SearchAbortedError";
  }
}

/**
 * Searches files via the given query string.
 * Throws SearchAbortedError if signal is aborted before completion.
 */
export async function searchFiles(
  query: string,
  options: SearchOptions = {}
): Promise<FileMatch[]> {
  const { signal, maxResults = 100 } = options;

  const params = new URLSearchParams({ q: query, limit: String(maxResults) });
  const response = await fetch(`/api/files/search?${params}`, { signal });

  if (!response.ok) {
    if (signal?.aborted) throw new SearchAbortedError();
    throw new Error(`Search failed: ${response.statusText}`);
  }

  return response.json() as Promise<FileMatch[]>;
}
