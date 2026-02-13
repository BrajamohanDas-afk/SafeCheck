import express from "express";
import cors from "cors";
import { createHealthRouter } from "./modules/health/routes";
import { createVirusTotalRouter } from "./modules/virustotal/routes";
import { VirusTotalService } from "./modules/virustotal/service";

interface CreateAppOptions {
  vtApiKey: string;
}

export function createApp({ vtApiKey }: CreateAppOptions) {
  const app = express();
  const virusTotalService = new VirusTotalService(vtApiKey);

  app.use(cors());
  app.use(express.json());

  app.use(createHealthRouter(Boolean(vtApiKey)));
  app.use("/api", createVirusTotalRouter(virusTotalService));

  return app;
}
