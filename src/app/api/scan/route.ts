import { NextResponse } from "next/server";
import { persistScanHistoryIfConfigured } from "@/server/scan-history";
import { enqueueScanUpload, getScanQueueSnapshot, ScanUploadQueueError } from "@/server/scan-upload-queue";
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

    const queueBefore = getScanQueueSnapshot();
    const analysisId = await enqueueScanUpload(async () => {
      const virusTotal = getVirusTotalService();
      return virusTotal.createFileAnalysis(file);
    });

    return NextResponse.json(
      {
        analysisId,
        queue: queueBefore,
      },
      { status: 202 }
    );
  } catch (error) {
    if (error instanceof ScanUploadQueueError) {
      return NextResponse.json({ error: error.message }, { status: error.statusCode });
    }

    if (error instanceof VirusTotalServiceError) {
      return NextResponse.json({ error: error.message }, { status: error.statusCode });
    }

    console.error("Unexpected /api/scan error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const analysisId = searchParams.get("analysisId");

  if (!analysisId) {
    return NextResponse.json({ error: "Missing analysisId query parameter" }, { status: 400 });
  }

  try {
    const virusTotal = getVirusTotalService();
    const analysis = await virusTotal.getAnalysisStatus(analysisId);

    if (analysis.state !== "completed" || !analysis.fileId) {
      return NextResponse.json({ status: analysis.state }, { status: 202 });
    }

    try {
      const report = await virusTotal.getFileReportById(analysis.fileId);
      void persistScanHistoryIfConfigured(report);

      return NextResponse.json({ status: "completed", report }, { status: 200 });
    } catch (error) {
      if (error instanceof VirusTotalServiceError && error.statusCode === 404) {
        return NextResponse.json({ status: "in-progress" }, { status: 202 });
      }

      throw error;
    }
  } catch (error) {
    if (error instanceof VirusTotalServiceError) {
      return NextResponse.json({ error: error.message }, { status: error.statusCode });
    }

    console.error("Unexpected GET /api/scan error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
