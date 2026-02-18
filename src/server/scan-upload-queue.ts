function readPositiveIntEnv(name: string, fallback: number, minValue: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;

  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < minValue) {
    return fallback;
  }

  return parsed;
}

const MAX_CONCURRENT_UPLOADS = readPositiveIntEnv("SCAN_QUEUE_MAX_CONCURRENT", 1, 1);
const MAX_PENDING_UPLOADS = readPositiveIntEnv("SCAN_QUEUE_MAX_PENDING", 25, 1);

interface QueuedTask<T> {
  run: () => Promise<T>;
  resolve: (value: T) => void;
  reject: (error: unknown) => void;
}

let activeUploads = 0;
const uploadQueue: QueuedTask<unknown>[] = [];

export class ScanUploadQueueError extends Error {
  statusCode: number;

  constructor(message: string, statusCode: number) {
    super(message);
    this.statusCode = statusCode;
  }
}

function processQueue(): void {
  while (activeUploads < MAX_CONCURRENT_UPLOADS && uploadQueue.length > 0) {
    const task = uploadQueue.shift();
    if (!task) break;

    activeUploads += 1;
    void task
      .run()
      .then((value) => task.resolve(value))
      .catch((error) => task.reject(error))
      .finally(() => {
        activeUploads -= 1;
        processQueue();
      });
  }
}

export function enqueueScanUpload<T>(run: () => Promise<T>): Promise<T> {
  if (uploadQueue.length >= MAX_PENDING_UPLOADS) {
    throw new ScanUploadQueueError(
      "Scan queue is full right now. Please retry in a minute.",
      429
    );
  }

  return new Promise<T>((resolve, reject) => {
    uploadQueue.push({ run, resolve, reject });
    processQueue();
  });
}

export function getScanQueueSnapshot() {
  return {
    activeUploads,
    queuedUploads: uploadQueue.length,
    maxConcurrentUploads: MAX_CONCURRENT_UPLOADS,
    maxPendingUploads: MAX_PENDING_UPLOADS,
  };
}
