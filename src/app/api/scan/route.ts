import { NextResponse } from "next/server";
import { persistScanHistoryIfConfigured } from "@/server/scan-history";
import { getVirusTotalService, VirusTotalServiceError } from "@/server/virustotal";

export const runtime = "nodejs";

const MAX_FILE_SIZE = 32 * 1024 * 1024;

export async function POST(request: Request) {
  try {
    const formData = await request.formData();
    const file = formData.get("file");

    if (!(file instanceof File)) {
      return NextResponse.json({ error: "No file uploaded" }, { status: 400 });
    }

    if (file.size > MAX_FILE_SIZE) {
      return NextResponse.json({ error: "File exceeds 32MB limit" }, { status: 400 });
    }

    const virusTotal = getVirusTotalService();
    const report = await virusTotal.scanFileAndFetchReport(file);

    void persistScanHistoryIfConfigured(report);

    return NextResponse.json(report, { status: 200 });
  } catch (error) {
    if (error instanceof VirusTotalServiceError) {
      return NextResponse.json({ error: error.message }, { status: error.statusCode });
    }

    console.error("Unexpected /api/scan error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
