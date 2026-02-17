const VT_BASE_URL = "https://www.virustotal.com/api/v3";
const MAX_FILE_SIZE = 32 * 1024 * 1024;

function readPositiveIntEnv(name: string, fallback: number, minValue: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;

  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < minValue) {
    return fallback;
  }

  return parsed;
}

const POLL_INTERVAL_MS = readPositiveIntEnv("VIRUSTOTAL_POLL_INTERVAL_MS", 5000, 1000);
const MAX_POLL_TIME_MS = readPositiveIntEnv("VIRUSTOTAL_MAX_POLL_TIME_MS", 300000, 5000);

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null;
}

function getNestedString(value: unknown, path: string[]): string | null {
  let current: unknown = value;
  for (const key of path) {
    if (!isRecord(current)) return null;
    current = current[key];
  }
  return typeof current === "string" ? current : null;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

export class VirusTotalServiceError extends Error {
  statusCode: number;
  details?: unknown;

  constructor(message: string, statusCode: number, details?: unknown) {
    super(message);
    this.statusCode = statusCode;
    this.details = details;
  }
}

export type VirusTotalAnalysisState = "queued" | "in-progress" | "completed";

export interface VirusTotalAnalysisStatus {
  state: VirusTotalAnalysisState;
  fileId?: string;
}

export class VirusTotalService {
  constructor(private readonly apiKey: string) {}

  private getHeaders(additionalHeaders: HeadersInit = {}): HeadersInit {
    return {
      "x-apikey": this.apiKey,
      ...additionalHeaders,
    };
  }

  private async parseJson(response: Response): Promise<unknown> {
    try {
      return await response.json();
    } catch {
      return null;
    }
  }

  private extractErrorMessage(payload: unknown): string | null {
    if (!isRecord(payload)) return null;
    const error = payload.error;
    if (!isRecord(error)) return null;
    return typeof error.message === "string" ? error.message : null;
  }

  private async request(path: string, init: RequestInit = {}): Promise<unknown> {
    const response = await fetch(`${VT_BASE_URL}${path}`, {
      ...init,
      headers: this.getHeaders(init.headers ?? {}),
      cache: "no-store",
    });

    const payload = await this.parseJson(response);
    if (!response.ok) {
      const message = this.extractErrorMessage(payload) || `VirusTotal request failed (${response.status})`;
      throw new VirusTotalServiceError(message, response.status, payload);
    }

    return payload;
  }

  async lookupFileByHash(hash: string): Promise<unknown | null> {
    try {
      return await this.request(`/files/${hash}`);
    } catch (error) {
      if (error instanceof VirusTotalServiceError && error.statusCode === 404) {
        return null;
      }
      throw error;
    }
  }

  private async uploadFile(file: File): Promise<string> {
    if (file.size > MAX_FILE_SIZE) {
      throw new VirusTotalServiceError("File exceeds 32MB limit", 400);
    }

    const formData = new FormData();
    formData.append("file", file, file.name);

    const payload = await this.request("/files", {
      method: "POST",
      body: formData,
    });

    const analysisId = getNestedString(payload, ["data", "id"]);
    if (!analysisId) {
      throw new VirusTotalServiceError("VirusTotal did not return an analysis id", 502, payload);
    }

    return analysisId;
  }

  private async getAnalysis(analysisId: string): Promise<unknown> {
    return this.request(`/analyses/${analysisId}`);
  }

  private extractFileIdFromAnalysis(analysisPayload: unknown): string {
    const fileLink = getNestedString(analysisPayload, ["data", "links", "item"]);
    if (fileLink && fileLink.includes("/files/")) {
      const [, fileId] = fileLink.split("/files/");
      if (fileId) return fileId;
    }

    const metaHash =
      getNestedString(analysisPayload, ["meta", "file_info", "sha256"]) ||
      getNestedString(analysisPayload, ["data", "meta", "file_info", "sha256"]);

    if (metaHash) return metaHash;

    throw new VirusTotalServiceError(
      "VirusTotal analysis completed but no file id/hash was returned",
      502,
      analysisPayload
    );
  }

  private async waitForAnalysisCompletion(analysisId: string): Promise<unknown> {
    const startTime = Date.now();

    while (Date.now() - startTime < MAX_POLL_TIME_MS) {
      const analysisPayload = await this.getAnalysis(analysisId);
      const status = getNestedString(analysisPayload, ["data", "attributes", "status"]);

      if (status === "completed") {
        return analysisPayload;
      }

      await delay(POLL_INTERVAL_MS);
    }

    throw new VirusTotalServiceError(
      `VirusTotal scan timed out before completion (${Math.round(MAX_POLL_TIME_MS / 1000)}s timeout)`,
      504
    );
  }

  private async getFileReport(fileId: string): Promise<unknown> {
    return this.request(`/files/${fileId}`);
  }

  async createFileAnalysis(file: File): Promise<string> {
    return this.uploadFile(file);
  }

  async getAnalysisStatus(analysisId: string): Promise<VirusTotalAnalysisStatus> {
    const analysisPayload = await this.getAnalysis(analysisId);
    const status = getNestedString(analysisPayload, ["data", "attributes", "status"]);

    if (status === "completed") {
      return {
        state: "completed",
        fileId: this.extractFileIdFromAnalysis(analysisPayload),
      };
    }

    if (status === "queued" || status === "in-progress") {
      return { state: status };
    }

    return { state: "in-progress" };
  }

  async getFileReportById(fileId: string): Promise<unknown> {
    return this.getFileReport(fileId);
  }

  async scanFileAndFetchReport(file: File): Promise<unknown> {
    const analysisId = await this.uploadFile(file);
    const analysisPayload = await this.waitForAnalysisCompletion(analysisId);
    const fileId = this.extractFileIdFromAnalysis(analysisPayload);
    return this.getFileReport(fileId);
  }
}

export function getVirusTotalService(): VirusTotalService {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    throw new VirusTotalServiceError("VIRUSTOTAL_API_KEY is not configured", 500);
  }

  return new VirusTotalService(apiKey);
}
