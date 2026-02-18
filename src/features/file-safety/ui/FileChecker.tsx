"use client";

import { useMemo, useState, useCallback } from "react";
import { motion } from "framer-motion";
import {
  Upload,
  FileCheck,
  Shield,
  AlertTriangle,
  XCircle,
  Loader2,
  X,
  FileArchive,
  Search,
  Link2,
  Flag,
  ListChecks,
  ShieldCheck,
  ShieldAlert,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { computeSHA256, formatFileSize } from "../crypto/sha256";
import { checkHashCache, uploadFileToScan } from "../virustotal/client";
import { scoreVirusTotalResult } from "../verdict/scoring";
import { compareKnownHash } from "../hash/compare";
import { analyzeMagnetLink, analyzeTorrentFile } from "../torrent/analyzer";
import { detectMissingFiles } from "../missing/detector";
import {
  checkSourceInput,
  loadPendingSiteReports,
  moderatePendingSiteReport,
  submitSourceReport,
} from "../source/client";
import type {
  ScanStatus,
  Verdict,
  VerdictScoreBreakdown,
  VirusTotalFileResult,
  TorrentAnalysisResult,
  SourceCheckResult,
  SiteReportItem,
} from "../types";

const MAX_FILE_SIZE = 32 * 1024 * 1024; // 32MB
const MAX_TORRENT_PREVIEW_FILES = 25;

interface FileCheckerProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function FileChecker({ isOpen, onClose }: FileCheckerProps) {
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState<ScanStatus>("idle");
  const [progress, setProgress] = useState(0);
  const [scanError, setScanError] = useState<string | null>(null);
  const [result, setResult] = useState<VirusTotalFileResult | null>(null);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [verdictBreakdown, setVerdictBreakdown] = useState<VerdictScoreBreakdown | null>(null);
  const [fileHash, setFileHash] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [knownHashInput, setKnownHashInput] = useState("");

  const [magnetInput, setMagnetInput] = useState("");
  const [torrentResult, setTorrentResult] = useState<TorrentAnalysisResult | null>(null);
  const [torrentError, setTorrentError] = useState<string | null>(null);
  const [isParsingTorrent, setIsParsingTorrent] = useState(false);

  const [sourceInput, setSourceInput] = useState("");
  const [sourceResult, setSourceResult] = useState<SourceCheckResult | null>(null);
  const [sourceError, setSourceError] = useState<string | null>(null);
  const [isCheckingSource, setIsCheckingSource] = useState(false);
  const [reportNotes, setReportNotes] = useState("");
  const [reportMessage, setReportMessage] = useState<string | null>(null);
  const [isSubmittingReport, setIsSubmittingReport] = useState(false);

  const [moderationToken, setModerationToken] = useState("");
  const [pendingReports, setPendingReports] = useState<SiteReportItem[]>([]);
  const [isLoadingPendingReports, setIsLoadingPendingReports] = useState(false);
  const [moderationMessage, setModerationMessage] = useState<string | null>(null);

  const [expectedFilesInput, setExpectedFilesInput] = useState("");
  const [actualFilesInput, setActualFilesInput] = useState("");

  const resetScanState = () => {
    setFile(null);
    setStatus("idle");
    setProgress(0);
    setScanError(null);
    setResult(null);
    setVerdict(null);
    setVerdictBreakdown(null);
    setFileHash(null);
  };

  const applyVerdictFromResult = (scanResult: VirusTotalFileResult) => {
    const breakdown = scoreVirusTotalResult(scanResult);
    setResult(scanResult);
    setVerdict(breakdown.verdict);
    setVerdictBreakdown(breakdown);
  };

  const handleFileScan = useCallback(async (selectedFile: File) => {
    setScanError(null);
    setResult(null);
    setVerdict(null);
    setVerdictBreakdown(null);

    if (selectedFile.size > MAX_FILE_SIZE) {
      setScanError(
        `File is too large. Maximum size is 32MB, your file is ${formatFileSize(selectedFile.size)}`
      );
      return;
    }

    setFile(selectedFile);
    setStatus("hashing");
    setProgress(10);

    try {
      const hash = await computeSHA256(selectedFile);
      setFileHash(hash);
      setProgress(30);

      setStatus("checking-cache");
      setProgress(50);

      const cachedResult = await checkHashCache(hash);
      if (cachedResult?.data) {
        applyVerdictFromResult(cachedResult);
        setStatus("complete");
        setProgress(100);
        return;
      }

      setStatus("uploading");
      setProgress(70);

      const scanResult = await uploadFileToScan(selectedFile);
      applyVerdictFromResult(scanResult);
      setStatus("complete");
      setProgress(100);
    } catch (error) {
      setStatus("error");
      setScanError(error instanceof Error ? error.message : "An unknown scan error occurred.");
    }
  }, []);

  const handleDrop = useCallback(
    (event: React.DragEvent<HTMLDivElement>) => {
      event.preventDefault();
      setIsDragging(false);

      const droppedFile = event.dataTransfer.files[0];
      if (droppedFile) {
        void handleFileScan(droppedFile);
      }
    },
    [handleFileScan]
  );

  const handleDragOver = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(false);
  }, []);

  const handleScanFileInput = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      const selectedFile = event.target.files?.[0];
      if (selectedFile) {
        void handleFileScan(selectedFile);
      }
    },
    [handleFileScan]
  );

  const handleTorrentFileInput = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = event.target.files?.[0];
    if (!selectedFile) return;

    setIsParsingTorrent(true);
    setTorrentError(null);

    try {
      const parsed = await analyzeTorrentFile(selectedFile);
      setTorrentResult(parsed);
    } catch (error) {
      setTorrentResult(null);
      setTorrentError(error instanceof Error ? error.message : "Failed to parse torrent file.");
    } finally {
      setIsParsingTorrent(false);
    }
  };

  const handleMagnetAnalyze = () => {
    setTorrentError(null);

    try {
      const parsed = analyzeMagnetLink(magnetInput);
      setTorrentResult(parsed);
    } catch (error) {
      setTorrentResult(null);
      setTorrentError(error instanceof Error ? error.message : "Failed to parse magnet link.");
    }
  };

  const handleSourceCheck = useCallback(async () => {
    setSourceError(null);
    setReportMessage(null);
    setSourceResult(null);

    if (!sourceInput.trim()) {
      setSourceError("Enter a URL or domain to check.");
      return;
    }

    setIsCheckingSource(true);
    try {
      const checked = await checkSourceInput(sourceInput);
      setSourceResult(checked);
    } catch (error) {
      setSourceError(error instanceof Error ? error.message : "Failed to check source.");
    } finally {
      setIsCheckingSource(false);
    }
  }, [sourceInput]);

  const handleReportSite = useCallback(async () => {
    setReportMessage(null);
    setSourceError(null);

    if (!sourceInput.trim()) {
      setSourceError("Run a source check first, then report if needed.");
      return;
    }

    setIsSubmittingReport(true);
    try {
      const submitted = await submitSourceReport(sourceInput, reportNotes, "ui-user");
      setReportMessage(
        submitted.autoFlaggedForReview
          ? `Report submitted. Domain moved to pending review (${submitted.reportCountForDomain} reports).`
          : `Report submitted. Current report count for ${submitted.domain}: ${submitted.reportCountForDomain}.`
      );
      setReportNotes("");
    } catch (error) {
      setSourceError(error instanceof Error ? error.message : "Failed to submit report.");
    } finally {
      setIsSubmittingReport(false);
    }
  }, [sourceInput, reportNotes]);

  const handleLoadPendingReports = useCallback(async () => {
    setModerationMessage(null);

    if (!moderationToken.trim()) {
      setModerationMessage("Enter moderation token first.");
      return;
    }

    setIsLoadingPendingReports(true);
    try {
      const reports = await loadPendingSiteReports(moderationToken.trim());
      setPendingReports(reports);
      setModerationMessage(`Loaded ${reports.length} pending reports.`);
    } catch (error) {
      setModerationMessage(error instanceof Error ? error.message : "Failed to load pending reports.");
    } finally {
      setIsLoadingPendingReports(false);
    }
  }, [moderationToken]);

  const handleModerateReport = useCallback(
    async (reportId: string, decision: "approve" | "reject", sourceStatus?: "legitimate" | "fake" | "unknown") => {
      setModerationMessage(null);

      if (!moderationToken.trim()) {
        setModerationMessage("Enter moderation token first.");
        return;
      }

      try {
        await moderatePendingSiteReport(moderationToken.trim(), {
          reportId,
          decision,
          sourceStatus,
          confidence: sourceStatus ? "high" : undefined,
          reviewedBy: "ui-moderator",
        });

        setPendingReports((prev) => prev.filter((item) => item.id !== reportId));
        setModerationMessage(`Report ${reportId} marked as ${decision}.`);
      } catch (error) {
        setModerationMessage(error instanceof Error ? error.message : "Failed to moderate report.");
      }
    },
    [moderationToken]
  );

  const hashComparison = useMemo(
    () => compareKnownHash(knownHashInput, fileHash),
    [knownHashInput, fileHash]
  );

  const missingDetection = useMemo(
    () => detectMissingFiles(expectedFilesInput, actualFilesInput),
    [expectedFilesInput, actualFilesInput]
  );

  if (!isOpen) return null;

  const verdictConfig = {
    safe: {
      icon: FileCheck,
      color: "text-safe",
      bg: "bg-safe/10",
      border: "border-safe/30",
      title: "Safe",
      description: "Only expected/generic detections were found.",
      action: "Proceed carefully and verify file integrity before running.",
    },
    suspicious: {
      icon: AlertTriangle,
      color: "text-suspicious",
      bg: "bg-suspicious/10",
      border: "border-suspicious/30",
      title: "Suspicious",
      description: "Suspicious engine signals were found.",
      action: "Do not run yet. Re-check the file hash and run deeper scans.",
    },
    dangerous: {
      icon: XCircle,
      color: "text-dangerous",
      bg: "bg-dangerous/10",
      border: "border-dangerous/30",
      title: "Dangerous",
      description: "Multiple dangerous signals were detected.",
      action: "Delete the file and do not execute it.",
    },
  };

  const hashStatusStyle = {
    idle: "text-muted-foreground",
    invalid: "text-dangerous",
    "waiting-file-hash": "text-suspicious",
    match: "text-safe",
    mismatch: "text-dangerous",
  };

  const sourceVerdictConfig = {
    verified: {
      icon: ShieldCheck,
      color: "text-safe",
      bg: "bg-safe/10",
      border: "border-safe/30",
      title: "Verified Source",
    },
    "known-fake": {
      icon: ShieldAlert,
      color: "text-dangerous",
      bg: "bg-dangerous/10",
      border: "border-dangerous/30",
      title: "Known Fake Source",
    },
    unknown: {
      icon: AlertTriangle,
      color: "text-suspicious",
      bg: "bg-suspicious/10",
      border: "border-suspicious/30",
      title: "Unknown Source",
    },
  };

  const analysisStats = result?.data?.attributes?.last_analysis_stats;

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.95, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.95, opacity: 0 }}
        className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto mx-4 p-8 rounded-2xl border border-border bg-card shadow-2xl"
        onClick={(event) => event.stopPropagation()}
      >
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-2 rounded-lg hover:bg-muted transition-colors"
          aria-label="Close"
        >
          <X className="w-5 h-5 text-muted-foreground" />
        </button>

        <div className="text-center mb-8 pr-8">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-primary/30 bg-primary/10 mb-4">
            <Shield className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium text-primary">File Safety Toolkit</span>
          </div>
          <h2 className="text-2xl font-bold font-display">Scan + Hash + Torrent Checks</h2>
          <p className="text-muted-foreground mt-2">
            Use multiple checks together for better judgment, not blind trust.
          </p>
        </div>

        <Tabs defaultValue="scan" className="space-y-4">
          <TabsList className="grid w-full grid-cols-2 md:grid-cols-4 gap-1 h-auto">
            <TabsTrigger value="source" className="gap-2">
              <Link2 className="w-4 h-4" />
              Source URL
            </TabsTrigger>
            <TabsTrigger value="scan" className="gap-2">
              <Search className="w-4 h-4" />
              File Scan + Hash
            </TabsTrigger>
            <TabsTrigger value="torrent" className="gap-2">
              <FileArchive className="w-4 h-4" />
              Torrent Analyzer
            </TabsTrigger>
            <TabsTrigger value="missing" className="gap-2">
              <ListChecks className="w-4 h-4" />
              Missing Files
            </TabsTrigger>
          </TabsList>

          <TabsContent value="source" className="space-y-4">
            <div className="rounded-xl border border-border p-4 bg-background/40 space-y-3">
              <label className="text-sm font-medium">Check download source URL</label>
              <div className="flex gap-2">
                <Input
                  placeholder="https://example.com/download or example.com"
                  value={sourceInput}
                  onChange={(event) => setSourceInput(event.target.value)}
                />
                <Button onClick={() => void handleSourceCheck()} disabled={isCheckingSource}>
                  {isCheckingSource ? "Checking..." : "Check Source"}
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Statuses: Verified, Known Fake, or Unknown. Unknown means not in DB or low confidence.
              </p>
            </div>

            {sourceError && (
              <div className="rounded-xl border border-dangerous/30 bg-dangerous/10 p-4 text-sm text-dangerous">
                {sourceError}
              </div>
            )}

            {sourceResult && (
              <div
                className={`rounded-xl border p-4 ${sourceVerdictConfig[sourceResult.verdict].bg} ${sourceVerdictConfig[sourceResult.verdict].border}`}
              >
                <div className="flex items-start gap-3">
                  {(() => {
                    const Icon = sourceVerdictConfig[sourceResult.verdict].icon;
                    return <Icon className={`w-5 h-5 mt-0.5 ${sourceVerdictConfig[sourceResult.verdict].color}`} />;
                  })()}
                  <div className="space-y-1">
                    <p className={`font-semibold ${sourceVerdictConfig[sourceResult.verdict].color}`}>
                      {sourceVerdictConfig[sourceResult.verdict].title}
                    </p>
                    <p className="text-sm text-muted-foreground">{sourceResult.note}</p>
                    <p className="text-xs text-muted-foreground">
                      Domain: <span className="font-mono">{sourceResult.domain}</span>
                      {sourceResult.matchedDomain ? ` | Matched: ${sourceResult.matchedDomain}` : ""}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Confidence: {sourceResult.confidence} | Reports: {sourceResult.reports}
                      {sourceResult.stale ? " | Stale record" : ""}
                    </p>
                  </div>
                </div>
              </div>
            )}

            <div className="rounded-xl border border-border p-4 bg-background/40 space-y-3">
              <label className="text-sm font-medium flex items-center gap-2">
                <Flag className="w-4 h-4" />
                Report this site for review
              </label>
              <Textarea
                placeholder="Why should this source be reviewed?"
                value={reportNotes}
                onChange={(event) => setReportNotes(event.target.value)}
              />
              <div className="flex justify-end">
                <Button
                  variant="outline"
                  onClick={() => void handleReportSite()}
                  disabled={isSubmittingReport}
                >
                  {isSubmittingReport ? "Submitting..." : "Submit Report"}
                </Button>
              </div>
              {reportMessage && <p className="text-xs text-safe">{reportMessage}</p>}
            </div>

            <details className="rounded-xl border border-border p-4 bg-background/40">
              <summary className="cursor-pointer text-sm font-medium">
                Moderation Panel (Admin Token Required)
              </summary>
              <div className="space-y-3 mt-3">
                <div className="flex gap-2">
                  <Input
                    placeholder="Enter moderation token"
                    value={moderationToken}
                    onChange={(event) => setModerationToken(event.target.value)}
                  />
                  <Button
                    variant="outline"
                    onClick={() => void handleLoadPendingReports()}
                    disabled={isLoadingPendingReports}
                  >
                    {isLoadingPendingReports ? "Loading..." : "Load Queue"}
                  </Button>
                </div>

                {moderationMessage && (
                  <p className="text-xs text-muted-foreground">{moderationMessage}</p>
                )}

                {pendingReports.length > 0 && (
                  <div className="space-y-3">
                    {pendingReports.map((report) => (
                      <div key={report.id} className="rounded-lg border border-border p-3 space-y-2">
                        <p className="text-xs font-mono">{report.domain}</p>
                        <p className="text-xs text-muted-foreground">{report.notes}</p>
                        <div className="flex gap-2 flex-wrap">
                          <Button
                            size="sm"
                            onClick={() => void handleModerateReport(report.id, "approve", "fake")}
                          >
                            Approve as Fake
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => void handleModerateReport(report.id, "approve", "legitimate")}
                          >
                            Approve as Legit
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => void handleModerateReport(report.id, "reject")}
                          >
                            Reject
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </details>
          </TabsContent>

          <TabsContent value="scan" className="space-y-4">
            {status === "idle" && (
              <div
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                className={`relative border-2 border-dashed rounded-xl p-10 text-center transition-all cursor-pointer ${
                  isDragging
                    ? "border-primary bg-primary/5"
                    : "border-border hover:border-primary/50 hover:bg-muted/50"
                }`}
              >
                <input
                  type="file"
                  onChange={handleScanFileInput}
                  className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                />
                <Upload
                  className={`w-10 h-10 mx-auto mb-3 ${isDragging ? "text-primary" : "text-muted-foreground"}`}
                />
                <p className="text-base font-medium mb-1">
                  {isDragging ? "Drop your file here" : "Drag and drop file to scan"}
                </p>
                <p className="text-sm text-muted-foreground">or click to browse (max 32MB)</p>
              </div>
            )}

            {(status === "hashing" || status === "checking-cache" || status === "uploading") && (
              <div className="text-center py-8 rounded-xl border border-border bg-background/40">
                <Loader2 className="w-10 h-10 mx-auto mb-3 text-primary animate-spin" />
                <p className="text-base font-medium mb-2">
                  {status === "hashing" && "Computing file hash..."}
                  {status === "checking-cache" && "Checking VirusTotal hash cache..."}
                  {status === "uploading" && "Uploading and waiting for final VirusTotal report..."}
                </p>
                {file && (
                  <p className="text-sm text-muted-foreground mb-4">
                    {file.name} ({formatFileSize(file.size)})
                  </p>
                )}
                <Progress value={progress} className="w-full max-w-xs mx-auto" />
              </div>
            )}

            {status === "error" && (
              <div className="rounded-xl border border-dangerous/30 bg-dangerous/10 p-4">
                <p className="text-dangerous font-medium">Scan failed</p>
                <p className="text-sm text-muted-foreground mt-1">{scanError}</p>
                <Button onClick={resetScanState} variant="outline" className="mt-3">
                  Try Again
                </Button>
              </div>
            )}

            {status === "complete" && verdict && (
              <div className={`rounded-xl p-6 ${verdictConfig[verdict].bg} ${verdictConfig[verdict].border} border`}>
                <div className="flex items-start gap-4">
                  <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${verdictConfig[verdict].bg}`}>
                    {(() => {
                      const Icon = verdictConfig[verdict].icon;
                      return <Icon className={`w-6 h-6 ${verdictConfig[verdict].color}`} />;
                    })()}
                  </div>
                  <div className="flex-1">
                    <h3 className={`text-xl font-bold font-display ${verdictConfig[verdict].color}`}>
                      {verdictConfig[verdict].title}
                    </h3>
                    <p className="text-muted-foreground mt-1">{verdictConfig[verdict].description}</p>
                    <p className="text-sm mt-2 font-medium">{verdictConfig[verdict].action}</p>
                  </div>
                </div>

                {analysisStats && (
                  <div className="mt-5 grid grid-cols-4 gap-3 text-center">
                    <div className="p-3 rounded-lg bg-background/50">
                      <p className="text-xl font-bold text-dangerous">{analysisStats.malicious}</p>
                      <p className="text-xs text-muted-foreground">Malicious</p>
                    </div>
                    <div className="p-3 rounded-lg bg-background/50">
                      <p className="text-xl font-bold text-suspicious">{analysisStats.suspicious}</p>
                      <p className="text-xs text-muted-foreground">Suspicious</p>
                    </div>
                    <div className="p-3 rounded-lg bg-background/50">
                      <p className="text-xl font-bold text-safe">{analysisStats.undetected}</p>
                      <p className="text-xs text-muted-foreground">Undetected</p>
                    </div>
                    <div className="p-3 rounded-lg bg-background/50">
                      <p className="text-xl font-bold text-muted-foreground">{analysisStats.harmless}</p>
                      <p className="text-xs text-muted-foreground">Harmless</p>
                    </div>
                  </div>
                )}

                {verdictBreakdown && (
                  <details className="mt-4 rounded-lg bg-background/50 p-3">
                    <summary className="cursor-pointer text-sm font-medium">Why this verdict?</summary>
                    <p className="text-xs text-muted-foreground mt-2">
                      Weighted score: <strong>{verdictBreakdown.totalScore.toFixed(1)}</strong>
                    </p>
                    {verdictBreakdown.topContributors.length > 0 ? (
                      <div className="mt-2 space-y-1">
                        {verdictBreakdown.topContributors.map((item) => (
                          <p key={`${item.engine}-${item.result}`} className="text-xs">
                            {item.engine}: "{item.result}" {"->"} {item.points.toFixed(1)} pts ({item.reason})
                          </p>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs mt-2">No suspicious/dangerous contributors above zero points.</p>
                    )}
                    {verdictBreakdown.ignoredGenericFlags.length > 0 && (
                      <p className="text-xs text-muted-foreground mt-2">
                        Ignored as generic:{" "}
                        {verdictBreakdown.ignoredGenericFlags
                          .map((item) => `${item.engine} (${item.result})`)
                          .join(", ")}
                      </p>
                    )}
                  </details>
                )}

                <div className="mt-4 p-3 rounded-lg border border-border/50 bg-background/60">
                  <p className="text-xs text-muted-foreground">
                    SafeCheck cannot guarantee a file is safe. This is risk assessment based on available signals.
                  </p>
                </div>
              </div>
            )}

            <div className="rounded-xl border border-border p-4 bg-background/40">
              <label className="text-sm font-medium">Known-good SHA-256 hash compare</label>
              <Input
                className="mt-2 font-mono text-xs"
                placeholder="Paste expected SHA-256 hash from source page"
                value={knownHashInput}
                onChange={(event) => setKnownHashInput(event.target.value)}
              />
              <p className={`text-xs mt-2 ${hashStatusStyle[hashComparison.status]}`}>{hashComparison.message}</p>
              {fileHash && (
                <p className="text-xs mt-2">
                  Computed file hash: <span className="font-mono break-all">{fileHash}</span>
                </p>
              )}
            </div>

            <div className="flex gap-3">
              <Button onClick={resetScanState} variant="outline" className="flex-1">
                Reset Scan State
              </Button>
              <Button onClick={onClose} className="flex-1">
                Close
              </Button>
            </div>
          </TabsContent>

          <TabsContent value="torrent" className="space-y-4">
            <div className="rounded-xl border border-border p-4 bg-background/40">
              <label className="text-sm font-medium">Analyze .torrent file</label>
              <Input type="file" accept=".torrent" className="mt-2" onChange={handleTorrentFileInput} />
              <p className="text-xs text-muted-foreground mt-2">
                Parsed client-side only. Torrent anomalies are advisory, not proof of malware.
              </p>
            </div>

            <div className="rounded-xl border border-border p-4 bg-background/40">
              <label className="text-sm font-medium">Analyze magnet link</label>
              <Textarea
                className="mt-2"
                placeholder="magnet:?xt=urn:btih:..."
                value={magnetInput}
                onChange={(event) => setMagnetInput(event.target.value)}
              />
              <div className="mt-2 flex justify-end">
                <Button onClick={handleMagnetAnalyze}>Analyze Magnet</Button>
              </div>
            </div>

            {isParsingTorrent && (
              <div className="rounded-xl border border-border bg-background/40 p-4 text-sm flex items-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin text-primary" />
                Parsing torrent metadata...
              </div>
            )}

            {torrentError && (
              <div className="rounded-xl border border-dangerous/30 bg-dangerous/10 p-4 text-sm text-dangerous">
                {torrentError}
              </div>
            )}

            {torrentResult && (
              <div className="rounded-xl border border-border p-4 bg-background/40 space-y-4">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div className="p-3 rounded-lg bg-muted/50">
                    <p className="text-xs text-muted-foreground">Source Type</p>
                    <p className="text-sm font-medium">{torrentResult.source}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/50">
                    <p className="text-xs text-muted-foreground">Trackers</p>
                    <p className="text-sm font-medium">{torrentResult.trackerCount}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/50">
                    <p className="text-xs text-muted-foreground">Files</p>
                    <p className="text-sm font-medium">{torrentResult.files.length}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/50">
                    <p className="text-xs text-muted-foreground">Total Size</p>
                    <p className="text-sm font-medium">{formatFileSize(torrentResult.totalSize)}</p>
                  </div>
                </div>

                <div>
                  <p className="text-sm font-medium">Name</p>
                  <p className="text-sm text-muted-foreground">{torrentResult.name}</p>
                  {torrentResult.infoHash && (
                    <p className="text-xs text-muted-foreground mt-1">
                      Info hash: <span className="font-mono">{torrentResult.infoHash}</span>
                    </p>
                  )}
                </div>

                <div className="rounded-lg border border-suspicious/30 bg-suspicious/10 p-3">
                  <p className="text-sm font-medium text-suspicious">Anomaly advisories</p>
                  {torrentResult.anomalies.length === 0 ? (
                    <p className="text-xs mt-1">No anomaly rules triggered from current metadata.</p>
                  ) : (
                    <div className="mt-2 space-y-2">
                      {torrentResult.anomalies.map((anomaly) => (
                        <div key={anomaly.id} className="text-xs">
                          <p className="font-medium">{anomaly.label}</p>
                          <p>{anomaly.details}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {torrentResult.files.length > 0 && (
                  <div>
                    <p className="text-sm font-medium mb-2">
                      File list preview ({Math.min(torrentResult.files.length, MAX_TORRENT_PREVIEW_FILES)} of{" "}
                      {torrentResult.files.length})
                    </p>
                    <div className="max-h-56 overflow-auto rounded-lg border border-border">
                      <table className="w-full text-xs">
                        <thead className="bg-muted/40 sticky top-0">
                          <tr>
                            <th className="text-left p-2">Path</th>
                            <th className="text-left p-2">Size</th>
                          </tr>
                        </thead>
                        <tbody>
                          {torrentResult.files.slice(0, MAX_TORRENT_PREVIEW_FILES).map((entry) => (
                            <tr key={`${entry.path}-${entry.size}`} className="border-t border-border/50">
                              <td className="p-2 font-mono">{entry.path}</td>
                              <td className="p-2">{formatFileSize(entry.size)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            )}
          </TabsContent>

          <TabsContent value="missing" className="space-y-4">
            <div className="rounded-xl border border-border p-4 bg-background/40 space-y-3">
              <label className="text-sm font-medium">Expected file list</label>
              <Textarea
                className="font-mono text-xs min-h-28"
                placeholder={"Paste one expected file path per line\nExample:\nbin/steam_api64.dll\nsetup.exe"}
                value={expectedFilesInput}
                onChange={(event) => setExpectedFilesInput(event.target.value)}
              />
            </div>

            <div className="rounded-xl border border-border p-4 bg-background/40 space-y-3">
              <label className="text-sm font-medium">Actual files present</label>
              <Textarea
                className="font-mono text-xs min-h-28"
                placeholder={"Paste one actual file path per line\nExample:\nsetup.exe\nbin/game.exe"}
                value={actualFilesInput}
                onChange={(event) => setActualFilesInput(event.target.value)}
              />
            </div>

            <div className="rounded-xl border border-border p-4 bg-background/40 space-y-3">
              <p className="text-sm font-medium">Comparison summary</p>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
                <div className="p-3 rounded-lg bg-muted/50">
                  <p className="text-xs text-muted-foreground">Expected</p>
                  <p className="text-base font-semibold">{missingDetection.expectedCount}</p>
                </div>
                <div className="p-3 rounded-lg bg-muted/50">
                  <p className="text-xs text-muted-foreground">Actual</p>
                  <p className="text-base font-semibold">{missingDetection.actualCount}</p>
                </div>
                <div className="p-3 rounded-lg bg-muted/50">
                  <p className="text-xs text-muted-foreground">Missing</p>
                  <p className="text-base font-semibold text-dangerous">
                    {missingDetection.missingFiles.length}
                  </p>
                </div>
                <div className="p-3 rounded-lg bg-muted/50">
                  <p className="text-xs text-muted-foreground">Likely Quarantined</p>
                  <p className="text-base font-semibold text-suspicious">
                    {missingDetection.likelyQuarantined.length}
                  </p>
                </div>
              </div>

              {missingDetection.missingFiles.length > 0 && (
                <div className="rounded-lg border border-dangerous/30 bg-dangerous/10 p-3">
                  <p className="text-xs font-medium text-dangerous">Missing files</p>
                  <p className="text-xs mt-1 font-mono break-all">
                    {missingDetection.missingFiles.slice(0, 12).join(", ")}
                    {missingDetection.missingFiles.length > 12 ? " ..." : ""}
                  </p>
                </div>
              )}

              {missingDetection.likelyQuarantined.length > 0 && (
                <div className="rounded-lg border border-suspicious/30 bg-suspicious/10 p-3">
                  <p className="text-xs font-medium text-suspicious">
                    Likely antivirus quarantine candidates
                  </p>
                  <p className="text-xs mt-1 font-mono break-all">
                    {missingDetection.likelyQuarantined.join(", ")}
                  </p>
                  <p className="text-xs text-muted-foreground mt-2">
                    Check antivirus quarantine and restore only if hash/verdict checks are trusted.
                  </p>
                </div>
              )}

              {missingDetection.missingFiles.length === 0 &&
                missingDetection.expectedCount > 0 &&
                missingDetection.actualCount > 0 && (
                  <div className="rounded-lg border border-safe/30 bg-safe/10 p-3">
                    <p className="text-xs font-medium text-safe">
                      No missing files detected from current lists.
                    </p>
                  </div>
                )}
            </div>
          </TabsContent>
        </Tabs>
      </motion.div>
    </motion.div>
  );
}
