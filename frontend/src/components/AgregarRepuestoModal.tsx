import { useEffect, useState } from "react";
import { authFetch } from "../api/client";
import { useToast } from "../ui/toast/ToastProvider";
import NuevoRepuestoModal from "./NuevoRepuestoModal";

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
  ordenId: number;
  onCreated: (item: any) => void; // OrdenRepuesto creado
};

export default function AgregarRepuestoModal({ open, onClose, ordenId, onCreated }: Props) {
  const toast = useToast();

  const [search, setSearch] = useState("");
  const [repuestos, setRepuestos] = useState<Repuesto[]>([]);
  const [repuestoId, setRepuestoId] = useState("");
  const [cantidad, setCantidad] = useState("1");
  const [esGarantia, setEsGarantia] = useState(false);
  const [loading, setLoading] = useState(false);

  const [openNuevo, setOpenNuevo] = useState(false);

  useEffect(() => {
    if (!open) return;

    const t = setTimeout(async () => {
      try {
        const q = search.trim() ? `?search=${encodeURIComponent(search.trim())}` : "";
        const data = await authFetch(`/api/repuestos${q}`);
        setRepuestos(data);
      } catch (e: any) {
        console.error(e);
        toast.error("No se pudieron cargar repuestos", "Error");
      }
    }, 250);

    return () => clearTimeout(t);
  }, [open, search]);

  if (!open) return null;

  const close = () => {
    setSearch("");
    setRepuestos([]);
    setRepuestoId("");
    setCantidad("1");
    setEsGarantia(false);
    onClose();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!repuestoId) {
      toast.warning("Selecciona un repuesto", "Falta dato");
      return;
    }

    const cant = Number(cantidad);
    if (Number.isNaN(cant) || cant <= 0) {
      toast.warning("Cantidad inválida", "Falta dato");
      return;
    }

    setLoading(true);
    try {
      const nuevo = await authFetch(`/api/ordenes/${ordenId}/repuestos`, {
        method: "POST",
        body: JSON.stringify({
          repuestoId: Number(repuestoId),
          cantidad: cant,
          esGarantia,
        }),
      });

      toast.success("Repuesto agregado", "Listo");
      onCreated(nuevo);
      close();
    } catch (e: any) {
      console.error(e);
      toast.error(e?.message || "No se pudo agregar el repuesto", "Error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
        <div className="w-full max-w-lg rounded-2xl bg-white p-6 shadow-xl">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-slate-900">Agregar repuesto</h2>
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
              <div className="mb-1 flex items-center justify-between">
                <label className="block text-sm font-medium text-slate-700">
                  Buscar / seleccionar repuesto
                </label>

                <button
                  type="button"
                  onClick={() => setOpenNuevo(true)}
                  className="rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-slate-800"
                >
                  + Crear repuesto
                </button>
              </div>

              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="mb-2 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                placeholder="Buscar por código o descripción..."
                disabled={loading}
              />

              <select
                value={repuestoId}
                onChange={(e) => setRepuestoId(e.target.value)}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                required
                disabled={loading}
              >
                <option value="">Selecciona un repuesto</option>
                {repuestos.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.codigo} — {r.descripcion}
                  </option>
                ))}
              </select>

              <p className="mt-1 text-xs text-slate-500">
                Si no existe, créalo en caliente y seguimos sin fricción.
              </p>
            </div>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700">
                  Cantidad
                </label>
                <input
                  value={cantidad}
                  onChange={(e) => setCantidad(e.target.value)}
                  type="number"
                  min="1"
                  step="1"
                  className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                  disabled={loading}
                  required
                />
              </div>

              <div className="flex items-end">
                <label className="flex items-center gap-2 text-sm text-slate-700">
                  <input
                    type="checkbox"
                    checked={esGarantia}
                    onChange={(e) => setEsGarantia(e.target.checked)}
                    disabled={loading}
                  />
                  Es garantía (costo $0)
                </label>
              </div>
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
                {loading ? "Agregando..." : "Agregar a la orden"}     
              </button>
            </div>
          </form>
        </div>
      </div>

      <NuevoRepuestoModal
        open={openNuevo}   
        onClose={() => setOpenNuevo(false)}
        onCreated={(r) => {
          setRepuestos((prev) => {
            const existe = prev.some((x) => x.id === r.id);
            return existe ? prev : [r, ...prev];
          });
          setRepuestoId(String(r.id));
          setOpenNuevo(false);
          setSearch("");
        }}
      />
    </>
  );
}  