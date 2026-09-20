import { useEffect, useRef, useState } from 'react';
import { api } from '@/services/api';
import type { ScanProgressEvent, ScanStatus } from '@/types';

const TERMINAL: ScanStatus[] = ['completed', 'failed', 'cancelled'];

/**
 * Subscribes to a scan's SSE progress stream.
 *
 * The connection closes itself when the scan reaches a terminal state, so a
 * finished scan does not hold an open stream. `onFinish` fires once.
 */
export function useScanStream(
  scanId: number | null,
  options: { enabled?: boolean; onFinish?: (status: ScanStatus) => void } = {},
) {
  const { enabled = true, onFinish } = options;
  const [event, setEvent] = useState<ScanProgressEvent | null>(null);
  const [connected, setConnected] = useState(false);
  const finishedRef = useRef(false);
  const onFinishRef = useRef(onFinish);
  onFinishRef.current = onFinish;

  useEffect(() => {
    if (scanId === null || !enabled) return;

    finishedRef.current = false;
    setEvent(null);

    const source = new EventSource(api.streamUrl(scanId));

    const settle = (status: ScanStatus) => {
      if (finishedRef.current) return;
      finishedRef.current = true;
      source.close();
      setConnected(false);
      onFinishRef.current?.(status);
    };

    source.onopen = () => setConnected(true);

    source.addEventListener('progress', (message) => {
      try {
        const payload = JSON.parse((message as MessageEvent).data) as ScanProgressEvent;
        setEvent(payload);
        if (TERMINAL.includes(payload.status)) settle(payload.status);
      } catch {
        // A malformed frame is not worth tearing the stream down for.
      }
    });

    source.addEventListener('end', () => settle('completed'));

    source.onerror = () => {
      setConnected(false);
      // EventSource retries on its own; only give up once the scan is done.
      if (finishedRef.current) source.close();
    };

    return () => {
      finishedRef.current = true;
      source.close();
    };
  }, [scanId, enabled]);

  return { event, connected };
}
