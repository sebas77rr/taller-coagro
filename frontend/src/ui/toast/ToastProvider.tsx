import React, { createContext, useCallback, useContext, useMemo, useState } from "react";

type ToastType = "success" | "error" | "info" | "warning";

export type ToastItem = {
  id: string;
  type: ToastType;
  title?: string;
  message: string;
  duration?: number; // ms
};

type ToastContextValue = {
  showToast: (toast: Omit<ToastItem, "id">) => void;
  success: (message: string, title?: string, duration?: number) => void;
  error: (message: string, title?: string, duration?: number) => void;
  info: (message: string, title?: string, duration?: number) => void;
  warning: (message: string, title?: string, duration?: number) => void;
};

const ToastContext = createContext<ToastContextValue | null>(null);

function id() {
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function typeStyles(type: ToastType) {
  switch (type) {
    case "success":
      return { wrap: "bg-emerald-50 border-emerald-200", text: "text-emerald-900", icon: "✅" };
    case "error":
      return { wrap: "bg-red-50 border-red-200", text: "text-red-900", icon: "⛔" };
    case "warning":
      return { wrap: "bg-amber-50 border-amber-200", text: "text-amber-900", icon: "⚠️" };
    default:
      return { wrap: "bg-slate-50 border-slate-200", text: "text-slate-900", icon: "ℹ️" };
  }
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const remove = useCallback((toastId: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== toastId));
  }, []);

  const showToast = useCallback((toast: Omit<ToastItem, "id">) => {
    const toastId = id();
    const duration = toast.duration ?? 2200;

    setToasts((prev) => [{ ...toast, id: toastId }, ...prev].slice(0, 4)); // máx 4 en pantalla

    window.setTimeout(() => remove(toastId), duration);
  }, [remove]);

  const api = useMemo<ToastContextValue>(() => ({
    showToast,
    success: (message, title, duration) => showToast({ type: "success", message, title, duration }),
    error: (message, title, duration) => showToast({ type: "error", message, title, duration }),
    info: (message, title, duration) => showToast({ type: "info", message, title, duration }),
    warning: (message, title, duration) => showToast({ type: "warning", message, title, duration }),
  }), [showToast]);

  return (
    <ToastContext.Provider value={api}>
      {children}

      {/* Contenedor global de toasts */}
      <div className="pointer-events-none fixed right-4 top-4 z-[9999] flex w-[92vw] max-w-sm flex-col gap-2">
        {toasts.map((t) => {
          const s = typeStyles(t.type);
          return (
            <div
              key={t.id}
              className={`pointer-events-auto flex items-start gap-3 rounded-xl border px-4 py-3 shadow-lg ${s.wrap}`}
              role="status"
            >
              <div className="text-lg leading-none">{s.icon}</div>

              <div className="min-w-0 flex-1">
                {t.title && (
                  <div className={`text-sm font-semibold ${s.text}`}>{t.title}</div>
                )}
                <div className={`text-sm ${s.text} opacity-90 break-words`}>
                  {t.message}
                </div>
              </div>

              <button
                onClick={() => remove(t.id)}
                className="rounded-lg px-2 text-slate-500 hover:bg-white/60"
                aria-label="Cerrar"
                type="button"
              >
                ✕
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast debe usarse dentro de <ToastProvider />");
  return ctx;
}  