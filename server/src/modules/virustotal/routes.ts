import { Router, type Response } from "express";
import multer from "multer";
import { VirusTotalService, VirusTotalServiceError } from "./service";

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 32 * 1024 * 1024 },
});

function handleRouteError(error: unknown, res: Response): void {
  if (error instanceof VirusTotalServiceError) {
    res.status(error.statusCode).json({ error: error.message });
    return;
  }

  console.error("Unexpected API error:", error);
  res.status(500).json({ error: "Internal server error" });
}

export function createVirusTotalRouter(service: VirusTotalService): Router {
  const router = Router();

  router.get("/check-hash", async (req, res) => {
    const { hash } = req.query;
    if (!hash || typeof hash !== "string") {
      res.status(400).json({ error: "Missing or invalid hash parameter" });
      return;
    }

    try {
      const result = await service.lookupFileByHash(hash);
      if (!result) {
        res.status(404).json({ error: "File not found in VirusTotal database" });
        return;
      }

      res.status(200).json(result);
    } catch (error) {
      handleRouteError(error, res);
    }
  });

  router.post("/scan", upload.single("file"), async (req, res) => {
    if (!req.file) {
      res.status(400).json({ error: "No file uploaded" });
      return;
    }

    try {
      const result = await service.scanFileAndFetchReport(req.file);
      res.status(200).json(result);
    } catch (error) {
      handleRouteError(error, res);
    }
  });

  return router;
}
