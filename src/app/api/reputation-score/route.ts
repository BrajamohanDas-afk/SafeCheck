import { NextRequest, NextResponse } from "next/server";
import { analyzeDownloadReputation } from "@/server/reputation-score";

export const runtime = "nodejs";

export async function GET(request: NextRequest) {
  const input = request.nextUrl.searchParams.get("input");
  if (!input) {
    return NextResponse.json({ error: "Missing input query parameter" }, { status: 400 });
  }

  try {
    const result = await analyzeDownloadReputation(input);
    return NextResponse.json(result, { status: 200 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to score download reputation";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}

