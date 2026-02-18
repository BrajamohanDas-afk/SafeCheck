import { NextRequest, NextResponse } from "next/server";
import { checkSource } from "@/server/source-db";

export const runtime = "nodejs";

export async function GET(request: NextRequest) {
  const input = request.nextUrl.searchParams.get("input");
  if (!input) {
    return NextResponse.json({ error: "Missing input query parameter" }, { status: 400 });
  }

  try {
    const result = await checkSource(input);
    return NextResponse.json(result, { status: 200 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to check source";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
