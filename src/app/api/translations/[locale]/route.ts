import { promises as fs } from "node:fs";
import path from "node:path";
import { NextResponse } from "next/server";

const CACHE_DIR = path.join(process.cwd(), ".lingo", "cache");

async function readTranslation(locale: string): Promise<unknown | null> {
  const filePath = path.join(CACHE_DIR, `${locale}.json`);
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export async function GET(
  _request: Request,
  { params }: { params: { locale: string } },
) {
  const locale = (params.locale || "en").toLowerCase();
  const localized = await readTranslation(locale);
  if (localized) return NextResponse.json(localized);

  const english = await readTranslation("en");
  if (english) return NextResponse.json(english);

  return NextResponse.json({ entries: {} });
}

