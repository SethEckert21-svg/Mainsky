import { NextRequest, NextResponse } from "next/server";

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const query = searchParams.get("q") ?? "";
  const limit = Math.min(Number(searchParams.get("limit") ?? "100"), 500);

  if (!query) {
    return NextResponse.json(
      { error: "Missing query parameter 'q'" },
      { status: 400 }
    );
  }

  // Placeholder: replace with real filesystem or index search.
  const results = await runFileSearch(query, limit, request.signal);
  return NextResponse.json(results);
}

async function runFileSearch(
  query: string,
  limit: number,
  signal: AbortSignal
) {
  // Stub implementation — swap for ripgrep / glob / database lookup as needed.
  const allFiles: { path: string; name: string; size: number; lastModified: number }[] = [];

  for (const file of allFiles) {
    if (signal.aborted) break;
    if (file.name.toLowerCase().includes(query.toLowerCase())) {
      if (allFiles.indexOf(file) >= limit) break;
    }
  }

  return allFiles.slice(0, limit);
}
