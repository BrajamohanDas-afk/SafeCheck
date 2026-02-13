import type { TorrentAnalysisResult, TorrentAnomaly, TorrentFileEntry } from "../types";

type BencodeValue =
  | number
  | Uint8Array
  | BencodeValue[]
  | {
      [key: string]: BencodeValue;
    };

class BencodeDecoder {
  private readonly bytes: Uint8Array;
  private index = 0;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  decode(): BencodeValue {
    const value = this.decodeValue();
    if (this.index !== this.bytes.length) {
      throw new Error("Unexpected trailing data in torrent file.");
    }
    return value;
  }

  private decodeValue(): BencodeValue {
    const current = this.bytes[this.index];

    if (current === 105) return this.decodeInteger(); // i
    if (current === 108) return this.decodeList(); // l
    if (current === 100) return this.decodeDictionary(); // d
    if (current >= 48 && current <= 57) return this.decodeBytes();

    throw new Error("Invalid bencode format.");
  }

  private decodeInteger(): number {
    this.index += 1;
    const end = this.findByte(101); // e
    const raw = this.sliceToString(this.index, end);
    this.index = end + 1;
    const parsed = Number(raw);

    if (!Number.isFinite(parsed)) {
      throw new Error("Invalid integer in torrent file.");
    }

    return parsed;
  }

  private decodeList(): BencodeValue[] {
    this.index += 1;
    const list: BencodeValue[] = [];

    while (this.bytes[this.index] !== 101) {
      list.push(this.decodeValue());
    }

    this.index += 1;
    return list;
  }

  private decodeDictionary(): Record<string, BencodeValue> {
    this.index += 1;
    const dict: Record<string, BencodeValue> = {};

    while (this.bytes[this.index] !== 101) {
      const keyBytes = this.decodeBytes();
      const key = new TextDecoder().decode(keyBytes);
      dict[key] = this.decodeValue();
    }

    this.index += 1;
    return dict;
  }

  private decodeBytes(): Uint8Array {
    const separator = this.findByte(58); // :
    const lengthRaw = this.sliceToString(this.index, separator);
    const length = Number(lengthRaw);

    if (!Number.isInteger(length) || length < 0) {
      throw new Error("Invalid byte-string length in torrent file.");
    }

    const start = separator + 1;
    const end = start + length;
    if (end > this.bytes.length) {
      throw new Error("Torrent file ended unexpectedly.");
    }

    this.index = end;
    return this.bytes.slice(start, end);
  }

  private findByte(target: number): number {
    const found = this.bytes.indexOf(target, this.index);
    if (found === -1) {
      throw new Error("Malformed torrent file.");
    }
    return found;
  }

  private sliceToString(start: number, end: number): string {
    const slice = this.bytes.slice(start, end);
    return new TextDecoder().decode(slice);
  }
}

function decodeText(value: BencodeValue | undefined, fallback = ""): string {
  if (!value) return fallback;
  if (value instanceof Uint8Array) return new TextDecoder().decode(value);
  return fallback;
}

function asNumber(value: BencodeValue | undefined, fallback = 0): number {
  return typeof value === "number" ? value : fallback;
}

function isDictionary(value: BencodeValue): value is Record<string, BencodeValue> {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array);
}

function getFileExtension(path: string): string {
  const lastSegment = path.split("/").pop() ?? "";
  const parts = lastSegment.split(".");
  return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : "";
}

function buildAnomalies(files: TorrentFileEntry[]): TorrentAnomaly[] {
  const anomalies: TorrentAnomaly[] = [];
  const exeFiles = files.filter((file) => file.extension === "exe");
  const largeDlls = files.filter((file) => file.extension === "dll" && file.size > 2 * 1024 * 1024);
  const genericExecutableNames = new Set(["update.exe", "patch.exe", "setup.exe", "installer.exe"]);
  const genericNameHits = files.filter((file) => {
    const lowerName = file.path.toLowerCase().split("/").pop() ?? "";
    return genericExecutableNames.has(lowerName);
  });

  if (exeFiles.length > 1) {
    anomalies.push({
      id: "extra-exe",
      label: "Extra executable files detected",
      details: `Found ${exeFiles.length} executable files. Extra executables can be benign, but should be scanned individually.`,
    });
  }

  if (largeDlls.length > 0) {
    anomalies.push({
      id: "large-dll",
      label: "Large DLL files detected",
      details: `${largeDlls.length} DLL files are larger than 2MB. This is advisory and should trigger deeper scanning.`,
    });
  }

  if (genericNameHits.length > 0) {
    anomalies.push({
      id: "generic-exe-name",
      label: "Generic executable naming pattern",
      details: `Files like ${genericNameHits
        .slice(0, 3)
        .map((file) => `"${file.path.split("/").pop()}"`)
        .join(", ")} were found. Generic names are common in malware droppers.`,
    });
  }

  return anomalies;
}

function parseTorrentDictionary(root: Record<string, BencodeValue>): TorrentAnalysisResult {
  const info = root.info;
  if (!info || !isDictionary(info)) {
    throw new Error("Torrent file is missing a valid info dictionary.");
  }

  const baseName = decodeText(info.name, "Unnamed torrent");
  const trackerCount = Array.isArray(root["announce-list"]) ? root["announce-list"].length : root.announce ? 1 : 0;
  const files: TorrentFileEntry[] = [];

  if (Array.isArray(info.files)) {
    for (const entry of info.files) {
      if (!isDictionary(entry)) continue;

      const pathParts = Array.isArray(entry.path)
        ? entry.path.map((segment) => decodeText(segment)).filter(Boolean)
        : [];

      const relativePath = pathParts.join("/");
      const fullPath = relativePath ? `${baseName}/${relativePath}` : baseName;
      const size = asNumber(entry.length, 0);

      files.push({
        path: fullPath,
        size,
        extension: getFileExtension(fullPath),
      });
    }
  } else {
    const fileName = decodeText(info.name, "unknown.bin");
    const size = asNumber(info.length, 0);
    files.push({
      path: fileName,
      size,
      extension: getFileExtension(fileName),
    });
  }

  const totalSize = files.reduce((sum, file) => sum + file.size, 0);

  return {
    source: "torrent-file",
    name: baseName,
    trackerCount,
    totalSize,
    files,
    anomalies: buildAnomalies(files),
  };
}

function parseMagnetLink(magnetLink: string): TorrentAnalysisResult {
  const trimmed = magnetLink.trim();
  if (!trimmed.startsWith("magnet:?")) {
    throw new Error("Magnet link must start with magnet:?");
  }

  const params = new URLSearchParams(trimmed.replace(/^magnet:\?/, ""));
  const xt = params.get("xt") || "";
  const infoHashMatch = xt.match(/urn:btih:([a-zA-Z0-9]+)/i);
  const infoHash = infoHashMatch ? infoHashMatch[1] : undefined;
  const trackers = params.getAll("tr");
  const displayName = params.get("dn") || "Magnet source";

  const anomalies: TorrentAnomaly[] = [
    {
      id: "magnet-limited",
      label: "Magnet-only metadata",
      details: "Magnet links do not contain file lists. Download the .torrent file for full anomaly checks.",
    },
  ];

  return {
    source: "magnet-link",
    name: decodeURIComponent(displayName),
    infoHash,
    trackerCount: trackers.length,
    totalSize: 0,
    files: [],
    anomalies,
  };
}

export async function analyzeTorrentFile(file: File): Promise<TorrentAnalysisResult> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const decoded = new BencodeDecoder(bytes).decode();

  if (!isDictionary(decoded)) {
    throw new Error("Invalid torrent file format.");
  }

  return parseTorrentDictionary(decoded);
}

export function analyzeMagnetLink(magnetLink: string): TorrentAnalysisResult {
  return parseMagnetLink(magnetLink);
}
