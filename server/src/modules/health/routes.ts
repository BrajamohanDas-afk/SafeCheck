import { Router } from "express";

export function createHealthRouter(vtKeyLoaded: boolean): Router {
  const router = Router();

  router.get("/health", (_req, res) => {
    res.json({
      status: "The server is running",
      timeStamp: new Date().toISOString(),
      vtKeyLoaded,
    });
  });

  return router;
}
