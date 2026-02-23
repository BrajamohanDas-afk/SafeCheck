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
  Gauge,
  ShieldCheck,
  ShieldAlert,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useLingoContext } from "@lingo.dev/compiler/react";
import { computeSHA256, formatFileSize } from "../crypto/sha256";
import { checkHashCache, uploadFileToScan } from "../virustotal/client";
import { scoreVirusTotalResult } from "../verdict/scoring";
import { compareKnownHash } from "../hash/compare";
import { analyzeMagnetLink, analyzeTorrentFile } from "../torrent/analyzer";
import { scoreDownloadReputation } from "../reputation/client";
import {
  checkSourceInput,
  submitSourceReport,
} from "../source/client";
import type {
  ScanStatus,
  Verdict,
  VerdictScoreBreakdown,
  VirusTotalFileResult,
  TorrentAnalysisResult,
  SourceCheckResult,
  SmartDownloadReputationResult,
} from "../types";

const MAX_FILE_SIZE = 32 * 1024 * 1024; // 32MB
const MAX_TORRENT_PREVIEW_FILES = 25;

const FILE_CHECKER_TEXT = {
  en: {
    close: "Close",
    toolkitBadge: "File Safety Toolkit",
    toolkitTitle: "Scan + Hash + Reputation Checks",
    toolkitSubtitle: "Use multiple checks together for better judgment, not blind trust.",
    tabSource: "Source URL",
    tabScan: "File Scan + Hash",
    tabTorrent: "Torrent Analyzer",
    tabScore: "Smart Score",
    sourceLabel: "Check download source URL",
    sourcePlaceholder: "https://example.com/download or example.com",
    checkSource: "Check Source",
    checking: "Checking...",
    sourceHelp: "Statuses: Verified, Known Fake, or Unknown. Unknown means not in DB or low confidence.",
    reportLabel: "Report this site for review",
    reportPlaceholder: "Why should this source be reviewed?",
    submitReport: "Submit Report",
    submitting: "Submitting...",
    autoModeration:
      "Auto-moderation is enabled. Reports are processed automatically using threat-intel signals and consensus thresholds.",
    dropFile: "Drag and drop file to scan",
    dropFileActive: "Drop your file here",
    browseHelp: "or click to browse (max 32MB)",
    hashing: "Computing file hash...",
    checkingCache: "Checking VirusTotal hash cache...",
    uploading: "Uploading and waiting for final VirusTotal report...",
    scanFailed: "Scan failed",
    tryAgain: "Try Again",
    safeTitle: "Safe",
    safeDescription: "Only expected/generic detections were found.",
    safeAction: "Proceed carefully and verify file integrity before running.",
    suspiciousTitle: "Suspicious",
    suspiciousDescription: "Suspicious engine signals were found.",
    suspiciousAction: "Do not run yet. Re-check the file hash and run deeper scans.",
    dangerousTitle: "Dangerous",
    dangerousDescription: "Multiple dangerous signals were detected.",
    dangerousAction: "Delete the file and do not execute it.",
    malicious: "Malicious",
    suspicious: "Suspicious",
    undetected: "Undetected",
    harmless: "Harmless",
    whyVerdict: "Why this verdict?",
    weightedScore: "Weighted score",
    noContributors: "No suspicious/dangerous contributors above zero points.",
    ignoredGeneric: "Ignored as generic:",
    disclaimer:
      "SafeCheck cannot guarantee a file is safe. This is risk assessment based on available signals.",
    knownHashLabel: "Known-good SHA-256 hash compare",
    knownHashPlaceholder: "Paste expected SHA-256 hash from source page",
    resetScan: "Reset Scan State",
    torrentFileLabel: "Analyze .torrent file",
    torrentHelp: "Parsed client-side only. Torrent anomalies are advisory, not proof of malware.",
    magnetLabel: "Analyze magnet link",
    magnetPlaceholder: "magnet:?xt=urn:btih:...",
    analyzeMagnet: "Analyze Magnet",
    parsingTorrent: "Parsing torrent metadata...",
    sourceType: "Source Type",
    trackers: "Trackers",
    files: "Files",
    totalSize: "Total Size",
    name: "Name",
    infoHash: "Info hash:",
    anomalyAdvisories: "Anomaly advisories",
    noAnomalies: "No anomaly rules triggered from current metadata.",
    fileListPreview: "File list preview",
    path: "Path",
    size: "Size",
    scoreLabel: "Smart download reputation score",
    scorePlaceholder: "https://example.com/download/file.zip",
    scoreUrl: "Score URL",
    scoring: "Scoring...",
    scoreHelp: "Score combines source reputation, threat intel, TLS/redirect behavior, and metadata anomalies.",
    lowRisk: "Low Risk",
    mediumRisk: "Medium Risk",
    highRisk: "High Risk",
    topReasons: "Top risk reasons",
    noHighRisk: "No high-risk signals were triggered from available checks.",
    signalSummary: "Signal summary",
    riskScoreSuffix: "/100 risk score",
    sourceVerdict: "Source verdict:",
    sourceConfidence: "Source confidence:",
    threatTypes: "Threat types:",
    tlsStatus: "TLS status:",
    redirectDepth: "Redirect depth:",
    mimeMismatch: "MIME mismatch:",
    domainAge: "Domain age:",
    popularity: "Popularity:",
    yes: "yes",
    no: "no",
    none: "none",
    verifiedSource: "Verified Source",
    knownFakeSource: "Known Fake Source",
    unknownSource: "Unknown Source",
    enterUrlErr: "Enter a URL or domain to check.",
    reportFirstErr: "Run a source check first, then report if needed.",
    enterDownloadErr: "Enter a download URL to score.",
  },
  fr: {
    close: "Fermer",
    toolkitBadge: "Outils de securite fichier",
    toolkitTitle: "Scan + Hash + Verification de reputation",
    toolkitSubtitle: "Combinez plusieurs verifications pour mieux juger, sans confiance aveugle.",
    tabSource: "URL source",
    tabScan: "Scan + Hash fichier",
    tabTorrent: "Analyseur Torrent",
    tabScore: "Score intelligent",
    sourceLabel: "Verifier l'URL de telechargement",
    sourcePlaceholder: "https://example.com/download ou example.com",
    checkSource: "Verifier la source",
    checking: "Verification...",
    sourceHelp: "Statuts: Verifiee, Fausse connue ou Inconnue. Inconnue = absente de la DB ou faible confiance.",
    reportLabel: "Signaler ce site pour revision",
    reportPlaceholder: "Pourquoi cette source doit etre revisee ?",
    submitReport: "Envoyer le signalement",
    submitting: "Envoi...",
    autoModeration:
      "La moderation auto est activee. Les signalements sont traites automatiquement via signaux threat-intel et consensus.",
    dropFile: "Glissez-deposez un fichier a scanner",
    dropFileActive: "Deposez votre fichier ici",
    browseHelp: "ou cliquez pour parcourir (max 32MB)",
    hashing: "Calcul du hash fichier...",
    checkingCache: "Verification du cache hash VirusTotal...",
    uploading: "Televersement et attente du rapport final VirusTotal...",
    scanFailed: "Echec du scan",
    tryAgain: "Reessayer",
    safeTitle: "Sain",
    safeDescription: "Seules des detections attendues/generiques ont ete trouvees.",
    safeAction: "Continuez prudemment et verifiez l'integrite avant execution.",
    suspiciousTitle: "Suspect",
    suspiciousDescription: "Des signaux suspects ont ete detectes.",
    suspiciousAction: "Ne lancez pas encore. Re-verifiez le hash et faites des scans plus profonds.",
    dangerousTitle: "Dangereux",
    dangerousDescription: "Des signaux dangereux multiples ont ete detectes.",
    dangerousAction: "Supprimez le fichier et ne l'executez pas.",
    malicious: "Malveillant",
    suspicious: "Suspect",
    undetected: "Non detecte",
    harmless: "Inoffensif",
    whyVerdict: "Pourquoi ce verdict ?",
    weightedScore: "Score pondere",
    noContributors: "Aucun contributeur suspect/dangereux au-dessus de zero.",
    ignoredGeneric: "Ignore comme generique :",
    disclaimer: "SafeCheck ne peut pas garantir qu'un fichier est sur. C'est une evaluation de risque.",
    knownHashLabel: "Comparaison SHA-256 de reference",
    knownHashPlaceholder: "Collez le hash SHA-256 attendu depuis la source",
    resetScan: "Reinitialiser l'etat du scan",
    torrentFileLabel: "Analyser un fichier .torrent",
    torrentHelp: "Analyse cote client uniquement. Les anomalies torrent sont indicatives, pas preuve de malware.",
    magnetLabel: "Analyser un lien magnet",
    magnetPlaceholder: "magnet:?xt=urn:btih:...",
    analyzeMagnet: "Analyser le magnet",
    parsingTorrent: "Analyse des metadonnees torrent...",
    sourceType: "Type de source",
    trackers: "Trackers",
    files: "Fichiers",
    totalSize: "Taille totale",
    name: "Nom",
    infoHash: "Info hash :",
    anomalyAdvisories: "Alertes d'anomalie",
    noAnomalies: "Aucune regle d'anomalie declenchee.",
    fileListPreview: "Apercu de la liste de fichiers",
    path: "Chemin",
    size: "Taille",
    scoreLabel: "Score intelligent de reputation",
    scorePlaceholder: "https://example.com/download/file.zip",
    scoreUrl: "Noter l'URL",
    scoring: "Calcul...",
    scoreHelp: "Le score combine reputation source, threat intel, TLS/redirections et anomalies metadata.",
    lowRisk: "Risque faible",
    mediumRisk: "Risque moyen",
    highRisk: "Risque eleve",
    topReasons: "Principales raisons de risque",
    noHighRisk: "Aucun signal de risque eleve detecte.",
    signalSummary: "Resume des signaux",
    riskScoreSuffix: "/100 score de risque",
    sourceVerdict: "Verdict source :",
    sourceConfidence: "Confiance source :",
    threatTypes: "Types de menace :",
    tlsStatus: "Etat TLS :",
    redirectDepth: "Profondeur de redirection :",
    mimeMismatch: "MIME incoherent :",
    domainAge: "Age du domaine :",
    popularity: "Popularite :",
    yes: "oui",
    no: "non",
    none: "aucun",
    verifiedSource: "Source verifiee",
    knownFakeSource: "Fausse source connue",
    unknownSource: "Source inconnue",
    enterUrlErr: "Entrez une URL ou un domaine a verifier.",
    reportFirstErr: "Lancez d'abord une verification de source, puis signalez si besoin.",
    enterDownloadErr: "Entrez une URL de telechargement a noter.",
  },
  es: {
    close: "Cerrar",
    toolkitBadge: "Kit de seguridad de archivos",
    toolkitTitle: "Escaneo + Hash + Reputacion",
    toolkitSubtitle: "Usa multiples verificaciones para decidir mejor, sin confianza ciega.",
    tabSource: "URL fuente",
    tabScan: "Escaneo + Hash",
    tabTorrent: "Analizador Torrent",
    tabScore: "Puntuacion",
    sourceLabel: "Verificar URL de descarga",
    sourcePlaceholder: "https://example.com/download o example.com",
    checkSource: "Verificar fuente",
    checking: "Verificando...",
    sourceHelp: "Estados: Verificada, Falsa conocida o Desconocida. Desconocida = no esta en DB o baja confianza.",
    reportLabel: "Reportar este sitio para revision",
    reportPlaceholder: "Por que esta fuente debe revisarse?",
    submitReport: "Enviar reporte",
    submitting: "Enviando...",
    autoModeration:
      "La moderacion automatica esta activa. Los reportes se procesan automaticamente con threat-intel y consenso.",
    dropFile: "Arrastra y suelta un archivo para escanear",
    dropFileActive: "Suelta tu archivo aqui",
    browseHelp: "o haz clic para buscar (max 32MB)",
    hashing: "Calculando hash del archivo...",
    checkingCache: "Revisando cache de hash de VirusTotal...",
    uploading: "Subiendo y esperando reporte final de VirusTotal...",
    scanFailed: "Escaneo fallido",
    tryAgain: "Intentar de nuevo",
    safeTitle: "Seguro",
    safeDescription: "Solo se encontraron detecciones esperadas/genericas.",
    safeAction: "Procede con cuidado y verifica la integridad antes de ejecutar.",
    suspiciousTitle: "Sospechoso",
    suspiciousDescription: "Se encontraron senales sospechosas.",
    suspiciousAction: "No ejecutes aun. Revisa hash y haz escaneos mas profundos.",
    dangerousTitle: "Peligroso",
    dangerousDescription: "Se detectaron multiples senales peligrosas.",
    dangerousAction: "Elimina el archivo y no lo ejecutes.",
    malicious: "Malicioso",
    suspicious: "Sospechoso",
    undetected: "No detectado",
    harmless: "Inofensivo",
    whyVerdict: "Por que este veredicto?",
    weightedScore: "Puntuacion ponderada",
    noContributors: "No hubo contribuyentes sospechosos/peligrosos sobre cero puntos.",
    ignoredGeneric: "Ignorado como generico:",
    disclaimer:
      "SafeCheck no puede garantizar que un archivo sea seguro. Es una evaluacion de riesgo basada en senales.",
    knownHashLabel: "Comparar hash SHA-256 confiable",
    knownHashPlaceholder: "Pega el hash SHA-256 esperado desde la fuente",
    resetScan: "Reiniciar estado de escaneo",
    torrentFileLabel: "Analizar archivo .torrent",
    torrentHelp: "Analisis solo en cliente. Las anomalias torrent son orientativas, no prueba de malware.",
    magnetLabel: "Analizar enlace magnet",
    magnetPlaceholder: "magnet:?xt=urn:btih:...",
    analyzeMagnet: "Analizar magnet",
    parsingTorrent: "Analizando metadatos torrent...",
    sourceType: "Tipo de fuente",
    trackers: "Trackers",
    files: "Archivos",
    totalSize: "Tamano total",
    name: "Nombre",
    infoHash: "Info hash:",
    anomalyAdvisories: "Avisos de anomalias",
    noAnomalies: "No se activaron reglas de anomalia.",
    fileListPreview: "Vista previa de archivos",
    path: "Ruta",
    size: "Tamano",
    scoreLabel: "Puntuacion inteligente de reputacion",
    scorePlaceholder: "https://example.com/download/file.zip",
    scoreUrl: "Puntuar URL",
    scoring: "Puntuando...",
    scoreHelp: "La puntuacion combina reputacion de fuente, threat intel, TLS/redirecciones y anomalias de metadata.",
    lowRisk: "Riesgo bajo",
    mediumRisk: "Riesgo medio",
    highRisk: "Riesgo alto",
    topReasons: "Principales razones de riesgo",
    noHighRisk: "No se detectaron senales de alto riesgo.",
    signalSummary: "Resumen de senales",
    riskScoreSuffix: "/100 puntuacion de riesgo",
    sourceVerdict: "Veredicto de fuente:",
    sourceConfidence: "Confianza de fuente:",
    threatTypes: "Tipos de amenaza:",
    tlsStatus: "Estado TLS:",
    redirectDepth: "Profundidad de redireccion:",
    mimeMismatch: "MIME no coincide:",
    domainAge: "Edad del dominio:",
    popularity: "Popularidad:",
    yes: "si",
    no: "no",
    none: "ninguno",
    verifiedSource: "Fuente verificada",
    knownFakeSource: "Fuente falsa conocida",
    unknownSource: "Fuente desconocida",
    enterUrlErr: "Ingresa una URL o dominio para verificar.",
    reportFirstErr: "Primero verifica la fuente y luego reporta si hace falta.",
    enterDownloadErr: "Ingresa una URL de descarga para puntuar.",
  },
} as const;

interface FileCheckerProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function FileChecker({ isOpen, onClose }: FileCheckerProps) {
  const { locale } = useLingoContext();
  const activeLocale = locale === "fr" || locale === "es" ? locale : "en";
  const text = FILE_CHECKER_TEXT[activeLocale];

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

  const [reputationInput, setReputationInput] = useState("");
  const [reputationResult, setReputationResult] = useState<SmartDownloadReputationResult | null>(null);
  const [reputationError, setReputationError] = useState<string | null>(null);
  const [isScoringReputation, setIsScoringReputation] = useState(false);

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
      setSourceError(text.enterUrlErr);
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
  }, [sourceInput, text.enterUrlErr]);

  const handleReportSite = useCallback(async () => {
    setReportMessage(null);
    setSourceError(null);

    if (!sourceInput.trim()) {
      setSourceError(text.reportFirstErr);
      return;
    }

    setIsSubmittingReport(true);
    try {
      const submitted = await submitSourceReport(sourceInput, reportNotes, "ui-user");
      setReportMessage(
        `${submitted.moderationSummary} (reports for ${submitted.domain}: ${submitted.reportCountForDomain})`
      );
      setReportNotes("");
    } catch (error) {
      setSourceError(error instanceof Error ? error.message : "Failed to submit report.");
    } finally {
      setIsSubmittingReport(false);
    }
  }, [sourceInput, reportNotes, text.reportFirstErr]);

  const handleReputationScore = useCallback(async () => {
    setReputationError(null);
    setReputationResult(null);

    if (!reputationInput.trim()) {
      setReputationError(text.enterDownloadErr);
      return;
    }

    setIsScoringReputation(true);
    try {
      const scored = await scoreDownloadReputation(reputationInput);
      setReputationResult(scored);
    } catch (error) {
      setReputationError(
        error instanceof Error ? error.message : "Failed to score download reputation."
      );
    } finally {
      setIsScoringReputation(false);
    }
  }, [reputationInput, text.enterDownloadErr]);

  const hashComparison = useMemo(
    () => compareKnownHash(knownHashInput, fileHash),
    [knownHashInput, fileHash]
  );

  if (!isOpen) return null;

  const verdictConfig = {
    safe: {
      icon: FileCheck,
      color: "text-safe",
      bg: "bg-safe/10",
      border: "border-safe/30",
      title: text.safeTitle,
      description: text.safeDescription,
      action: text.safeAction,
    },
    suspicious: {
      icon: AlertTriangle,
      color: "text-suspicious",
      bg: "bg-suspicious/10",
      border: "border-suspicious/30",
      title: text.suspiciousTitle,
      description: text.suspiciousDescription,
      action: text.suspiciousAction,
    },
    dangerous: {
      icon: XCircle,
      color: "text-dangerous",
      bg: "bg-dangerous/10",
      border: "border-dangerous/30",
      title: text.dangerousTitle,
      description: text.dangerousDescription,
      action: text.dangerousAction,
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
      title: text.verifiedSource,
    },
    "known-fake": {
      icon: ShieldAlert,
      color: "text-dangerous",
      bg: "bg-dangerous/10",
      border: "border-dangerous/30",
      title: text.knownFakeSource,
    },
    unknown: {
      icon: AlertTriangle,
      color: "text-suspicious",
      bg: "bg-suspicious/10",
      border: "border-suspicious/30",
      title: text.unknownSource,
    },
  };

  const reputationLevelConfig = {
    low: {
      label: text.lowRisk,
      color: "text-safe",
      bg: "bg-safe/10",
      border: "border-safe/30",
    },
    medium: {
      label: text.mediumRisk,
      color: "text-suspicious",
      bg: "bg-suspicious/10",
      border: "border-suspicious/30",
    },
    high: {
      label: text.highRisk,
      color: "text-dangerous",
      bg: "bg-dangerous/10",
      border: "border-dangerous/30",
    },
  };

  const analysisStats = result?.data?.attributes?.last_analysis_stats;

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm"
      onClick={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
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
          aria-label={text.close}
        >
          <X className="w-5 h-5 text-muted-foreground" />
        </button>

        <div className="text-center mb-8 pr-8">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-primary/30 bg-primary/10 mb-4">
            <Shield className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium text-primary">{text.toolkitBadge}</span>
          </div>
          <h2 className="text-2xl font-bold font-display">{text.toolkitTitle}</h2>
          <p className="text-muted-foreground mt-2">{text.toolkitSubtitle}</p>
        </div>

        <Tabs defaultValue="source" className="space-y-4">
          <TabsList className="grid w-full grid-cols-2 md:grid-cols-4 gap-1 h-auto">
            <TabsTrigger value="source" className="gap-2">
              <Link2 className="w-4 h-4" />
              {text.tabSource}
            </TabsTrigger>
            <TabsTrigger value="scan" className="gap-2">
              <Search className="w-4 h-4" />
              {text.tabScan}
            </TabsTrigger>
            <TabsTrigger value="torrent" className="gap-2">
              <FileArchive className="w-4 h-4" />
              {text.tabTorrent}
            </TabsTrigger>
            <TabsTrigger value="reputation" className="gap-2">
              <Gauge className="w-4 h-4" />
              {text.tabScore}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="source" className="space-y-4">
            <div className="rounded-xl border border-border p-4 bg-background/40 space-y-3">
              <label className="text-sm font-medium">{text.sourceLabel}</label>
              <div className="flex gap-2">
                <Input
                  placeholder={text.sourcePlaceholder}
                  value={sourceInput}
                  onChange={(event) => setSourceInput(event.target.value)}
                />
                <Button onClick={() => void handleSourceCheck()} disabled={isCheckingSource}>
                  {isCheckingSource ? text.checking : text.checkSource}
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">{text.sourceHelp}</p>
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
                    {sourceResult.categories.length > 0 && (
                      <p className="text-xs text-muted-foreground">
                        Risk categories: {sourceResult.categories.join(" | ")}
                      </p>
                    )}
                    {sourceResult.threatTypes.length > 0 && (
                      <p className="text-xs text-muted-foreground">
                        Threat intel: {sourceResult.intelProvider ?? "provider"} (
                        {sourceResult.threatTypes.join(", ")})
                      </p>
                    )}
                  </div>
                </div>
              </div>
            )}

            <div className="rounded-xl border border-border p-4 bg-background/40 space-y-3">
              <label className="text-sm font-medium flex items-center gap-2">
                <Flag className="w-4 h-4" />
                {text.reportLabel}
              </label>
              <Textarea
                placeholder={text.reportPlaceholder}
                value={reportNotes}
                onChange={(event) => setReportNotes(event.target.value)}
              />
              <div className="flex justify-end">
                <Button
                  variant="outline"
                  onClick={() => void handleReportSite()}
                  disabled={isSubmittingReport}
                >
                  {isSubmittingReport ? text.submitting : text.submitReport}
                </Button>
              </div>
              {reportMessage && <p className="text-xs text-safe">{reportMessage}</p>}
            </div>

            <div className="rounded-xl border border-border p-4 bg-background/40 text-xs text-muted-foreground">
              {text.autoModeration}
            </div>
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
                  {isDragging ? text.dropFileActive : text.dropFile}
                </p>
                <p className="text-sm text-muted-foreground">{text.browseHelp}</p>
              </div>
            )}

            {(status === "hashing" || status === "checking-cache" || status === "uploading") && (
              <div className="text-center py-8 rounded-xl border border-border bg-background/40">
                <Loader2 className="w-10 h-10 mx-auto mb-3 text-primary animate-spin" />
                <p className="text-base font-medium mb-2">
                  {status === "hashing" && text.hashing}
                  {status === "checking-cache" && text.checkingCache}
                  {status === "uploading" && text.uploading}
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
                <p className="text-dangerous font-medium">{text.scanFailed}</p>
                <p className="text-sm text-muted-foreground mt-1">{scanError}</p>
                <Button onClick={resetScanState} variant="outline" className="mt-3">
                  {text.tryAgain}
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
                      <p className="text-xs text-muted-foreground">{text.malicious}</p>
                    </div>
                    <div className="p-3 rounded-lg bg-background/50">
                      <p className="text-xl font-bold text-suspicious">{analysisStats.suspicious}</p>
                      <p className="text-xs text-muted-foreground">{text.suspicious}</p>
                    </div>
                    <div className="p-3 rounded-lg bg-background/50">
                      <p className="text-xl font-bold text-safe">{analysisStats.undetected}</p>
                      <p className="text-xs text-muted-foreground">{text.undetected}</p>
                    </div>
                    <div className="p-3 rounded-lg bg-background/50">
                      <p className="text-xl font-bold text-muted-foreground">{analysisStats.harmless}</p>
                      <p className="text-xs text-muted-foreground">{text.harmless}</p>
                    </div>
                  </div>
                )}

                {verdictBreakdown && (
                  <details className="mt-4 rounded-lg bg-background/50 p-3">
                    <summary className="cursor-pointer text-sm font-medium">{text.whyVerdict}</summary>
                    <p className="text-xs text-muted-foreground mt-2">
                      {text.weightedScore}: <strong>{verdictBreakdown.totalScore.toFixed(1)}</strong>
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
                      <p className="text-xs mt-2">{text.noContributors}</p>
                    )}
                    {verdictBreakdown.ignoredGenericFlags.length > 0 && (
                      <p className="text-xs text-muted-foreground mt-2">
                        {text.ignoredGeneric}{" "}
                        {verdictBreakdown.ignoredGenericFlags
                          .map((item) => `${item.engine} (${item.result})`)
                          .join(", ")}
                      </p>
                    )}
                  </details>
                )}

                <div className="mt-4 p-3 rounded-lg border border-border/50 bg-background/60">
                  <p className="text-xs text-muted-foreground">{text.disclaimer}</p>
                </div>
              </div>
            )}

            <div className="rounded-xl border border-border p-4 bg-background/40">
              <label className="text-sm font-medium">{text.knownHashLabel}</label>
              <Input
                className="mt-2 font-mono text-xs"
                placeholder={text.knownHashPlaceholder}
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
                {text.resetScan}
              </Button>
              <Button onClick={onClose} className="flex-1">
                {text.close}
              </Button>
            </div>
          </TabsContent>

          <TabsContent value="torrent" className="space-y-4">
            <div className="rounded-xl border border-border p-4 bg-background/40">
              <label className="text-sm font-medium">{text.torrentFileLabel}</label>
              <Input type="file" accept=".torrent" className="mt-2" onChange={handleTorrentFileInput} />
              <p className="text-xs text-muted-foreground mt-2">{text.torrentHelp}</p>
            </div>

            <div className="rounded-xl border border-border p-4 bg-background/40">
              <label className="text-sm font-medium">{text.magnetLabel}</label>
              <Textarea
                className="mt-2"
                placeholder={text.magnetPlaceholder}
                value={magnetInput}
                onChange={(event) => setMagnetInput(event.target.value)}
              />
              <div className="mt-2 flex justify-end">
                <Button onClick={handleMagnetAnalyze}>{text.analyzeMagnet}</Button>
              </div>
            </div>

            {isParsingTorrent && (
              <div className="rounded-xl border border-border bg-background/40 p-4 text-sm flex items-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin text-primary" />
                {text.parsingTorrent}
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
                    <p className="text-xs text-muted-foreground">{text.sourceType}</p>
                    <p className="text-sm font-medium">{torrentResult.source}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/50">
                    <p className="text-xs text-muted-foreground">{text.trackers}</p>
                    <p className="text-sm font-medium">{torrentResult.trackerCount}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/50">
                    <p className="text-xs text-muted-foreground">{text.files}</p>
                    <p className="text-sm font-medium">{torrentResult.files.length}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/50">
                    <p className="text-xs text-muted-foreground">{text.totalSize}</p>
                    <p className="text-sm font-medium">{formatFileSize(torrentResult.totalSize)}</p>
                  </div>
                </div>

                <div>
                  <p className="text-sm font-medium">{text.name}</p>
                  <p className="text-sm text-muted-foreground">{torrentResult.name}</p>
                  {torrentResult.infoHash && (
                    <p className="text-xs text-muted-foreground mt-1">
                      {text.infoHash} <span className="font-mono">{torrentResult.infoHash}</span>
                    </p>
                  )}
                </div>

                <div className="rounded-lg border border-suspicious/30 bg-suspicious/10 p-3">
                  <p className="text-sm font-medium text-suspicious">{text.anomalyAdvisories}</p>
                  {torrentResult.anomalies.length === 0 ? (
                    <p className="text-xs mt-1">{text.noAnomalies}</p>
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
                      {text.fileListPreview} ({Math.min(torrentResult.files.length, MAX_TORRENT_PREVIEW_FILES)} of{" "}
                      {torrentResult.files.length})
                    </p>
                    <div className="max-h-56 overflow-auto rounded-lg border border-border">
                      <table className="w-full text-xs">
                        <thead className="bg-muted/40 sticky top-0">
                          <tr>
                            <th className="text-left p-2">{text.path}</th>
                            <th className="text-left p-2">{text.size}</th>
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

          <TabsContent value="reputation" className="space-y-4">
            <div className="rounded-xl border border-border p-4 bg-background/40 space-y-3">
              <label className="text-sm font-medium">{text.scoreLabel}</label>
              <div className="flex gap-2">
                <Input
                  placeholder={text.scorePlaceholder}
                  value={reputationInput}
                  onChange={(event) => setReputationInput(event.target.value)}
                />
                <Button onClick={() => void handleReputationScore()} disabled={isScoringReputation}>
                  {isScoringReputation ? text.scoring : text.scoreUrl}
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">{text.scoreHelp}</p>
            </div>

            {reputationError && (
              <div className="rounded-xl border border-dangerous/30 bg-dangerous/10 p-4 text-sm text-dangerous">
                {reputationError}
              </div>
            )}

            {reputationResult && (
              <div className="space-y-4">
                <div
                  className={`rounded-xl border p-4 ${reputationLevelConfig[reputationResult.level].bg} ${reputationLevelConfig[reputationResult.level].border}`}
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <p className={`text-sm font-semibold ${reputationLevelConfig[reputationResult.level].color}`}>
                        {reputationLevelConfig[reputationResult.level].label}
                      </p>
                      <p className="text-xs text-muted-foreground mt-1">
                        Domain: <span className="font-mono">{reputationResult.domain}</span>
                      </p>
                    </div>
                    <div className="text-right">
                      <p className={`text-3xl font-bold ${reputationLevelConfig[reputationResult.level].color}`}>
                        {reputationResult.score}
                      </p>
                      <p className="text-xs text-muted-foreground">{text.riskScoreSuffix}</p>
                    </div>
                  </div>
                </div>

                <div className="rounded-xl border border-border p-4 bg-background/40 space-y-3">
                  <p className="text-sm font-medium">{text.topReasons}</p>
                  {reputationResult.reasons.length > 0 ? (
                    <div className="space-y-2">
                      {reputationResult.reasons.slice(0, 5).map((reason) => (
                        <div key={reason.id} className="rounded-lg border border-border p-3">
                          <div className="flex items-start justify-between gap-3">
                            <p className="text-sm font-medium">{reason.label}</p>
                            <p className="text-xs font-semibold text-muted-foreground">+{reason.points}</p>
                          </div>
                          <p className="text-xs text-muted-foreground mt-1">{reason.detail}</p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-safe">{text.noHighRisk}</p>
                  )}
                </div>

                <div className="rounded-xl border border-border p-4 bg-background/40">
                  <p className="text-sm font-medium mb-2">{text.signalSummary}</p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs text-muted-foreground">
                    <p>
                      {text.sourceVerdict} <span className="font-medium">{reputationResult.signals.sourceVerdict}</span>
                    </p>
                    <p>
                      {text.sourceConfidence}{" "}
                      <span className="font-medium">{reputationResult.signals.sourceConfidence}</span>
                    </p>
                    <p>
                      {text.threatTypes}{" "}
                      <span className="font-medium">
                        {reputationResult.signals.threatTypes.length > 0
                          ? reputationResult.signals.threatTypes.join(", ")
                          : text.none}
                      </span>
                    </p>
                    <p>
                      {text.tlsStatus} <span className="font-medium">{reputationResult.signals.tlsStatus}</span>
                    </p>
                    <p>
                      {text.redirectDepth} <span className="font-medium">{reputationResult.signals.redirectDepth}</span>
                    </p>
                    <p>
                      {text.mimeMismatch}{" "}
                      <span className="font-medium">
                        {reputationResult.signals.mimeMismatch ? text.yes : text.no}
                      </span>
                    </p>
                    <p>
                      {text.domainAge}{" "}
                      <span className="font-medium">{reputationResult.signals.domainAgeStatus}</span>
                    </p>
                    <p>
                      {text.popularity}{" "}
                      <span className="font-medium">{reputationResult.signals.popularityStatus}</span>
                    </p>
                  </div>
                </div>
              </div>
            )}
          </TabsContent>
        </Tabs>
      </motion.div>
    </motion.div>
  );
}
