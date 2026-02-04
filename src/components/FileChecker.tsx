import { useState, useCallback } from "react";
import { motion } from "framer-motion";
import { Upload, FileCheck, Shield, AlertTriangle, XCircle, Loader2, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { computeSHA256, formatFileSize } from "@/lib/hash";
import { checkHashCache, uploadFileToScan, type VirusTotalFileResult } from "@/lib/virustotal";

const MAX_FILE_SIZE = 32 * 1024 * 1024; // 32MB

type ScanStatus = "idle" | "hashing" | "checking-cache" | "uploading" | "complete" | "error";
type Verdict = "safe" | "suspicious" | "dangerous" | null;

interface FileCheckerProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function FileChecker({ isOpen, onClose }: FileCheckerProps) {
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState<ScanStatus>("idle");
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<VirusTotalFileResult | null>(null);
  const [verdict, setVerdict] = useState<Verdict>(null);
  const [fileHash, setFileHash] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const resetState = () => {
    setFile(null);
    setStatus("idle");
    setProgress(0);
    setError(null);
    setResult(null);
    setVerdict(null);
    setFileHash(null);
  };

  const calculateVerdict = (data: VirusTotalFileResult): Verdict => {
    const stats = data.data?.attributes?.last_analysis_stats;
    if (!stats) return null;

    const { malicious, suspicious } = stats;
    const total = malicious + suspicious;

    if (total === 0) return "safe";
    if (malicious >= 5 || total >= 10) return "dangerous";
    return "suspicious";
  };

  const handleFile = useCallback(async (selectedFile: File) => {
    setError(null);
    setResult(null);
    setVerdict(null);

    // Validate file size
    if (selectedFile.size > MAX_FILE_SIZE) {
      setError(`File is too large. Maximum size is 32MB, your file is ${formatFileSize(selectedFile.size)}`);
      return;
    }

    setFile(selectedFile);
    setStatus("hashing");
    setProgress(10);

    try {
      // Step 1: Compute hash locally
      const hash = await computeSHA256(selectedFile);
      setFileHash(hash);
      setProgress(30);

      // Step 2: Check cache first (doesn't consume quota)
      setStatus("checking-cache");
      setProgress(50);

      const cachedResult = await checkHashCache(hash);

      if (cachedResult && cachedResult.data) {
        // File found in cache!
        setResult(cachedResult);
        setVerdict(calculateVerdict(cachedResult));
        setStatus("complete");
        setProgress(100);
        return;
      }

      // Step 3: Not in cache, upload for scanning
      setStatus("uploading");
      setProgress(70);

      const scanResult = await uploadFileToScan(selectedFile);
      setResult(scanResult);
      setVerdict(calculateVerdict(scanResult));
      setStatus("complete");
      setProgress(100);
    } catch (err) {
      setStatus("error");
      setError(err instanceof Error ? err.message : "An unknown error occurred");
    }
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      setIsDragging(false);

      const droppedFile = e.dataTransfer.files[0];
      if (droppedFile) {
        handleFile(droppedFile);
      }
    },
    [handleFile]
  );

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleFileInput = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const selectedFile = e.target.files?.[0];
      if (selectedFile) {
        handleFile(selectedFile);
      }
    },
    [handleFile]
  );

  if (!isOpen) return null;

  const verdictConfig = {
    safe: {
      icon: FileCheck,
      color: "text-safe",
      bg: "bg-safe/10",
      border: "border-safe/30",
      title: "Safe",
      description: "No threats detected. This file appears to be safe.",
    },
    suspicious: {
      icon: AlertTriangle,
      color: "text-suspicious",
      bg: "bg-suspicious/10",
      border: "border-suspicious/30",
      title: "Suspicious",
      description: "Some security engines flagged this file. Exercise caution.",
    },
    dangerous: {
      icon: XCircle,
      color: "text-dangerous",
      bg: "bg-dangerous/10",
      border: "border-dangerous/30",
      title: "Dangerous",
      description: "Multiple threats detected. Do not run this file.",
    },
  };

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
        className="relative w-full max-w-2xl mx-4 p-8 rounded-2xl border border-border bg-card shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Close button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-2 rounded-lg hover:bg-muted transition-colors"
        >
          <X className="w-5 h-5 text-muted-foreground" />
        </button>

        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-primary/30 bg-primary/10 mb-4">
            <Shield className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium text-primary">File Safety Scanner</span>
          </div>
          <h2 className="text-2xl font-bold font-display">Check if your file is safe</h2>
          <p className="text-muted-foreground mt-2">
            Drop a file below to scan it against 70+ antivirus engines
          </p>
        </div>

        {/* Drop zone */}
        {status === "idle" && (
          <div
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            className={`relative border-2 border-dashed rounded-xl p-12 text-center transition-all cursor-pointer ${
              isDragging
                ? "border-primary bg-primary/5"
                : "border-border hover:border-primary/50 hover:bg-muted/50"
            }`}
          >
            <input
              type="file"
              onChange={handleFileInput}
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
            />
            <Upload className={`w-12 h-12 mx-auto mb-4 ${isDragging ? "text-primary" : "text-muted-foreground"}`} />
            <p className="text-lg font-medium mb-2">
              {isDragging ? "Drop your file here" : "Drag & drop a file here"}
            </p>
            <p className="text-sm text-muted-foreground">or click to browse (max 32MB)</p>
          </div>
        )}

        {/* Progress state */}
        {(status === "hashing" || status === "checking-cache" || status === "uploading") && (
          <div className="text-center py-8">
            <Loader2 className="w-12 h-12 mx-auto mb-4 text-primary animate-spin" />
            <p className="text-lg font-medium mb-2">
              {status === "hashing" && "Computing file hash..."}
              {status === "checking-cache" && "Checking VirusTotal cache..."}
              {status === "uploading" && "Uploading to VirusTotal..."}
            </p>
            {file && (
              <p className="text-sm text-muted-foreground mb-4">
                {file.name} ({formatFileSize(file.size)})
              </p>
            )}
            <Progress value={progress} className="w-full max-w-xs mx-auto" />
          </div>
        )}

        {/* Error state */}
        {status === "error" && (
          <div className="text-center py-8">
            <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-dangerous/10 flex items-center justify-center">
              <XCircle className="w-8 h-8 text-dangerous" />
            </div>
            <p className="text-lg font-medium text-dangerous mb-2">Scan Failed</p>
            <p className="text-sm text-muted-foreground mb-6">{error}</p>
            <Button onClick={resetState} variant="outline">
              Try Again
            </Button>
          </div>
        )}

        {/* Result state */}
        {status === "complete" && verdict && (
          <div className="py-4">
            <div className={`rounded-xl p-6 ${verdictConfig[verdict].bg} ${verdictConfig[verdict].border} border`}>
              <div className="flex items-start gap-4">
                <div className={`w-14 h-14 rounded-xl flex items-center justify-center ${verdictConfig[verdict].bg}`}>
                  {(() => {
                    const Icon = verdictConfig[verdict].icon;
                    return <Icon className={`w-7 h-7 ${verdictConfig[verdict].color}`} />;
                  })()}
                </div>
                <div className="flex-1">
                  <h3 className={`text-xl font-bold font-display ${verdictConfig[verdict].color}`}>
                    {verdictConfig[verdict].title}
                  </h3>
                  <p className="text-muted-foreground mt-1">{verdictConfig[verdict].description}</p>
                </div>
              </div>

              {result?.data?.attributes?.last_analysis_stats && (
                <div className="mt-6 grid grid-cols-4 gap-4 text-center">
                  <div className="p-3 rounded-lg bg-background/50">
                    <p className="text-2xl font-bold text-dangerous">
                      {result.data.attributes.last_analysis_stats.malicious}
                    </p>
                    <p className="text-xs text-muted-foreground">Malicious</p>
                  </div>
                  <div className="p-3 rounded-lg bg-background/50">
                    <p className="text-2xl font-bold text-suspicious">
                      {result.data.attributes.last_analysis_stats.suspicious}
                    </p>
                    <p className="text-xs text-muted-foreground">Suspicious</p>
                  </div>
                  <div className="p-3 rounded-lg bg-background/50">
                    <p className="text-2xl font-bold text-safe">
                      {result.data.attributes.last_analysis_stats.undetected}
                    </p>
                    <p className="text-xs text-muted-foreground">Undetected</p>
                  </div>
                  <div className="p-3 rounded-lg bg-background/50">
                    <p className="text-2xl font-bold text-muted-foreground">
                      {result.data.attributes.last_analysis_stats.harmless}
                    </p>
                    <p className="text-xs text-muted-foreground">Harmless</p>
                  </div>
                </div>
              )}

              {fileHash && (
                <div className="mt-4 p-3 rounded-lg bg-background/50">
                  <p className="text-xs text-muted-foreground mb-1">SHA-256 Hash</p>
                  <p className="text-xs font-mono break-all">{fileHash}</p>
                </div>
              )}
            </div>

            <div className="flex gap-3 mt-6">
              <Button onClick={resetState} variant="outline" className="flex-1">
                Scan Another File
              </Button>
              <Button onClick={onClose} className="flex-1">
                Done
              </Button>
            </div>
          </div>
        )}
      </motion.div>
    </motion.div>
  );
}
