import { NextRequest, NextResponse } from "next/server";
import {
  listSiteReports,
  moderateSiteReport,
  submitSiteReport,
  type SiteReportModerationInput,
} from "@/server/source-db";

export const runtime = "nodejs";

function assertModerationToken(request: NextRequest): NextResponse | null {
  const configured = process.env.SITE_MODERATION_TOKEN;
  if (!configured) {
    return NextResponse.json(
      { error: "SITE_MODERATION_TOKEN is not configured on the server." },
      { status: 503 }
    );
  }

  const provided = request.headers.get("x-moderation-token");
  if (!provided || provided !== configured) {
    return NextResponse.json({ error: "Unauthorized moderation token." }, { status: 401 });
  }

  return null;
}

export async function POST(request: NextRequest) {
  try {
    const body = (await request.json()) as {
      input?: string;
      notes?: string;
      createdBy?: string;
    };

    const input = body.input?.trim() ?? "";
    const notes = body.notes?.trim() ?? "";
    const createdBy = body.createdBy?.trim() || null;

    const result = await submitSiteReport(input, notes, createdBy);
    return NextResponse.json(result, { status: 201 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to submit site report";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}

export async function GET(request: NextRequest) {
  const authError = assertModerationToken(request);
  if (authError) return authError;

  const status = request.nextUrl.searchParams.get("status");
  const limitRaw = Number(request.nextUrl.searchParams.get("limit") ?? 50);
  const limit = Number.isFinite(limitRaw) ? limitRaw : 50;

  try {
    const reports = await listSiteReports(status, limit);
    return NextResponse.json({ reports }, { status: 200 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to load site reports";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}

export async function PATCH(request: NextRequest) {
  const authError = assertModerationToken(request);
  if (authError) return authError;

  try {
    const body = (await request.json()) as SiteReportModerationInput;
    const result = await moderateSiteReport(body);
    return NextResponse.json(result, { status: 200 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to moderate site report";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
