"use client";

import { FormEvent, useState } from "react";
import { useFileSearch } from "@/hooks/useFileSearch";

export default function FileSearch() {
  const [query, setQuery] = useState("");
  const { results, status, error, search, stop } = useFileSearch();

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (query.trim()) search(query.trim());
  };

  const isSearching = status === "searching";

  return (
    <div className="file-search">
      <form onSubmit={handleSubmit} className="file-search__form">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search files…"
          disabled={isSearching}
          className="file-search__input"
          aria-label="File search query"
        />

        {isSearching ? (
          <button
            type="button"
            onClick={stop}
            className="file-search__btn file-search__btn--stop"
            aria-label="Stop search"
          >
            Stop
          </button>
        ) : (
          <button
            type="submit"
            disabled={!query.trim()}
            className="file-search__btn file-search__btn--search"
            aria-label="Start search"
          >
            Search
          </button>
        )}
      </form>

      {isSearching && (
        <p className="file-search__status" role="status">
          Searching…
        </p>
      )}

      {status === "stopped" && (
        <p className="file-search__status file-search__status--stopped" role="status">
          Search stopped.
        </p>
      )}

      {status === "error" && error && (
        <p className="file-search__status file-search__status--error" role="alert">
          {error}
        </p>
      )}

      {status === "done" && results.length === 0 && (
        <p className="file-search__status" role="status">
          No files found.
        </p>
      )}

      {results.length > 0 && (
        <ul className="file-search__results" aria-label="Search results">
          {results.map((file) => (
            <li key={file.path} className="file-search__result">
              <span className="file-search__result-name">{file.name}</span>
              <span className="file-search__result-path">{file.path}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
