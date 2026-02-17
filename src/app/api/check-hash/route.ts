import { NextRequest, NextResponse } from "next/server";
import { getVirusTotalService, VirusTotalServiceError } from "@/server/virustotal";

export const runtime = "nodejs";

export async function GET(request: NextRequest) {
  const hash = request.nextUrl.searchParams.get("hash");
  if (!hash) {
    return NextResponse.json({ error: "Missing hash query parameter" }, { status: 400 });
  }

  try {
    const virusTotal = getVirusTotalService();
    const result = await virusTotal.lookupFileByHash(hash);

    if (!result) {
      return NextResponse.json(null, { status: 200 });
    }

    return NextResponse.json(result, { status: 200 });
  } catch (error) {
    if (error instanceof VirusTotalServiceError) {
      return NextResponse.json({ error: error.message }, { status: error.statusCode });
    }

    console.error("Unexpected /api/check-hash error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
