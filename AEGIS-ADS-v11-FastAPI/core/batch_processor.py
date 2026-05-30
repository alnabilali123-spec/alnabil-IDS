import time, threading, logging
from collections import deque

logger = logging.getLogger(__name__)

class BatchProcessor:
    def __init__(self, model, max_batch_size=32, max_wait_time=0.5):
        self.model = model
        self.max_batch_size = max_batch_size
        self.max_wait_time = max_wait_time
        self.queue = deque()
        self.lock = threading.Lock()
        self._last_process = time.time()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        logger.info(f"✅ Batch Processor started (batch_size={max_batch_size}, wait={max_wait_time}s)")

    def submit(self, payload, callback):
        with self.lock:
            self.queue.append((payload, callback))

    def _loop(self):
        while True:
            time.sleep(0.05)
            with self.lock:
                now = time.time()
                if len(self.queue) >= self.max_batch_size or (self.queue and now - self._last_process >= self.max_wait_time):
                    batch = list(self.queue)
                    self.queue.clear()
                    self._last_process = now
                    if batch:
                        payloads, callbacks = zip(*batch)
                        try:
                            results = self.model.analyze_batch(list(payloads))
                            for cb, res in zip(callbacks, results):
                                try:
                                    cb(res)
                                except Exception as e:
                                    logger.error(f"Callback error: {e}")
                        except Exception as e:
                            logger.error(f"Batch processing error: {e}")