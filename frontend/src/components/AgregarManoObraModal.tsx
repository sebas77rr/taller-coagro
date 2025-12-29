import { useState } from "react";
import { authFetch } from "../api/client";
import { useToast } from "../ui/toast/ToastProvider";

type Props = {
  open: boolean;
  onClose: () => void;
  ordenId: number;
  onCreated: (item: any) => void;
};

export default function AgregarManoObraModal({ open, onClose, ordenId, onCreated }: Props) {
  const toast = useToast();
  const [descripcionTrabajo, setDescripcionTrabajo] = useState("");
  const [horas, setHoras] = useState("1");
  const [loading, setLoading] = useState(false);

  if (!open) return null;

  const close = () => {
    setDescripcionTrabajo("");
    setHoras("1");
    onClose();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!descripcionTrabajo.trim()) {
      toast.warning("Describe el trabajo realizado", "Falta dato");
      return;
    }

    const horasNum = Number(horas);
    if (Number.isNaN(horasNum) || horasNum <= 0) {
      toast.warning("Horas inválidas (debe ser > 0)", "Falta dato");
      return;
    }

    setLoading(true);
    try {
      const nuevo = await authFetch(`/api/ordenes/${ordenId}/mano-obra`, {
        method: "POST",
        body: JSON.stringify({
          descripcion: descripcionTrabajo.trim(), // backend recibe "descripcion"
          horas: horasNum,
        }),
      });

      toast.success("Mano de obra agregada", "Listo");
      onCreated(nuevo);
      close();
    } catch (err: any) {
      console.error(err);
      toast.error(err?.message || "No se pudo agregar mano de obra", "Error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="w-full max-w-lg rounded-2xl bg-white p-6 shadow-xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-slate-900">Agregar mano de obra</h2>
          <button
            onClick={close}
            className="rounded-full px-2 text-slate-500 hover:bg-slate-100"
            type="button"
            disabled={loading}
          >
            ✕
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">Trabajo realizado</label>
            <textarea
              value={descripcionTrabajo}
              onChange={(e) => setDescripcionTrabajo(e.target.value)}
              rows={3}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
              placeholder="Ej: Diagnóstico, ajuste carburación, cambio retenedor..."
              disabled={loading}
              required
            />
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">Horas</label>
            <input
              value={horas}
              onChange={(e) => setHoras(e.target.value)}
              type="number"
              step="0.5"
              min="0.5"
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
              disabled={loading}
              required
            />
          </div>

          <div className="mt-4 flex justify-end gap-2">
            <button
              type="button"
              onClick={close}
              className="rounded-lg border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
              disabled={loading}
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={loading}
              className="rounded-lg bg-emerald-600 px-5 py-2 text-sm font-semibold text-white shadow-sm hover:bg-emerald-700 disabled:opacity-60"
            >
              {loading ? "Guardando..." : "Agregar"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}         