import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { CheckCircle2, X, AlertOctagon, Info } from 'lucide-react';

type ToastKind = 'success' | 'error' | 'info';

interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
}

interface ToastContextValue {
  push: (kind: ToastKind, message: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const ICONS = { success: CheckCircle2, error: AlertOctagon, info: Info } as const;
const COLORS = {
  success: 'var(--color-good)',
  error: 'var(--color-critical)',
  info: 'var(--color-accent)',
} as const;

let nextId = 1;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((t) => t.id !== id));
  }, []);

  const push = useCallback(
    (kind: ToastKind, message: string) => {
      const id = nextId++;
      setToasts((current) => [...current, { id, kind, message }]);
      window.setTimeout(() => dismiss(id), kind === 'error' ? 8000 : 4500);
    },
    [dismiss],
  );

  const value = useMemo(() => ({ push }), [push]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div
        className="pointer-events-none fixed right-4 bottom-4 z-50 flex w-full max-w-sm flex-col gap-2"
        role="status"
        aria-live="polite"
      >
        {toasts.map((toast) => {
          const Icon = ICONS[toast.kind];
          return (
            <div
              key={toast.id}
              className="pointer-events-auto flex items-start gap-3 rounded-lg border border-[var(--color-line-strong)] bg-[var(--color-overlay)] px-3.5 py-3 shadow-lg"
            >
              <Icon size={16} style={{ color: COLORS[toast.kind] }} aria-hidden />
              <p className="flex-1 text-xs leading-relaxed text-[var(--color-ink)]">
                {toast.message}
              </p>
              <button
                onClick={() => dismiss(toast.id)}
                className="text-[var(--color-ink-muted)] hover:text-[var(--color-ink)]"
                aria-label="Dismiss notification"
              >
                <X size={14} />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const context = useContext(ToastContext);
  if (!context) throw new Error('useToast must be used inside ToastProvider');
  return context;
}
