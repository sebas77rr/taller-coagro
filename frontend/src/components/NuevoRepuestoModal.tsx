import { useState } from "react";
import { authFetch } from "../api/client";
import { useToast } from "../ui/toast/ToastProvider";

type Repuesto = {
  id: number;
  codigo: string;
  descripcion: string;
  costo: number;
  stockGlobal: number;
};

type Props = {
  open: boolean;
  onClose: () => void;
  onCreated: (repuesto: Repuesto) => void; // creado o existente (409)
};

export default function NuevoRepuestoModal({ open, onClose, onCreated }: Props) {
  const toast = useToast();

  const [codigo, setCodigo] = useState("");
  const [descripcion, setDescripcion] = useState("");
  const [costo, setCosto] = useState("0");
  const [stockGlobal, setStockGlobal] = useState("0");
  const [loading, setLoading] = useState(false);

  if (!open) return null;

  const reset = () => {
    setCodigo("");
    setDescripcion("");
    setCosto("0");
    setStockGlobal("0");
  };

  const close = () => {
    reset();
    onClose();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!codigo.trim() || !descripcion.trim()) {
      toast.warning("Código y descripción son obligatorios", "Falta dato");
      return;
    }

    setLoading(true);
    try {
      const res = await authFetch("/api/repuestos", {
        method: "POST",
        body: JSON.stringify({
          codigo: codigo.trim(),
          descripcion: descripcion.trim(),
          costo: Number(costo) || 0,
          stockGlobal: Number(stockGlobal) || 0,
        }),
      });

      toast.success("Repuesto creado", res.codigo);
      onCreated(res);
      close();
    } catch (err: any) {
      // si backend devolvió JSON en string (por authFetch), intentamos parsear
      const msg = err?.message || "Error creando repuesto";
      try {
        const parsed = JSON.parse(msg);
        if (parsed?.repuesto?.id) {
          toast.info("Ya existía, lo seleccioné", parsed.repuesto.codigo);
          onCreated(parsed.repuesto);
          close();
          return;
        }
        toast.error(parsed?.error || msg, "Error");
      } catch {
        toast.error(msg, "Error");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="w-full max-w-lg rounded-2xl bg-white p-6 shadow-xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-slate-900">Crear repuesto</h2>
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
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700">Código *</label>
              <input
                value={codigo}
                onChange={(e) => setCodigo(e.target.value)}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                placeholder="Ej: CG-00123"
                disabled={loading}
                required
              />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700">Costo</label>
              <input
                value={costo}
                onChange={(e) => setCosto(e.target.value)}
                type="number"
                step="0.01"
                min="0"
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                disabled={loading}
              />
            </div>
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">Descripción *</label>
            <input
              value={descripcion}
              onChange={(e) => setDescripcion(e.target.value)}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
              placeholder="Ej: Filtro de aire GX160"
              disabled={loading}
              required
            />
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">Stock global</label>
            <input
              value={stockGlobal}
              onChange={(e) => setStockGlobal(e.target.value)}
              type="number"
              step="1"
              min="0"
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
              disabled={loading}
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
              {loading ? "Guardando..." : "Guardar repuesto"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}   