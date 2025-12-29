import { useEffect, useState } from "react";
import { authFetch } from "../api/client";
import { getUsuario } from "../hooks/useAuth";
import { useToast } from "../ui/toast/ToastProvider";
import { useNavigate } from "react-router-dom";

type EquipoRow = {
  id: number;
  marca: string;
  modelo: string;
  serial: string;
  cliente: {
    id: number;
    nombre: string;
    empresa?: string | null;
  };
};

type Sede = {
  id: number;
  nombre: string;
  ciudad: string;
  direccion: string;
  activo: boolean;
};

type Props = {
  open: boolean;
  onClose: () => void;
  equipo: EquipoRow | null;
  onCreated?: () => void; // para refrescar órdenes si quieres
};

export default function NuevaOrdenModal({
  open,
  onClose,
  equipo,
  onCreated,
}: Props) {
  const toast = useToast();
  const navigate = useNavigate();
  const usuario = getUsuario();

  const [tipoIngreso, setTipoIngreso] = useState<
    "GARANTIA" | "MANTENIMIENTO" | "REPARACION"
  >("REPARACION");
  const [motivoIngreso, setMotivoIngreso] = useState("");
  const [loading, setLoading] = useState(false);

  const [sedes, setSedes] = useState<Sede[]>([]);
  const [sedeId, setSedeId] = useState<string>("");

  const esAdmin = usuario?.rol === "ADMIN";

  useEffect(() => {
    if (!open) return;

    // Reset del modal cada vez que abre
    setTipoIngreso("REPARACION");
    setMotivoIngreso("");
    setLoading(false);

    // Sede:
    // - Si NO es admin: usamos la sede del usuario (si tiene)
    // - Si es admin: dejamos seleccionar
    if (!esAdmin) {
      setSedeId(usuario?.sedeId ? String(usuario.sedeId) : "");
      return;
    }

    (async () => {
      try {
        const data = await authFetch("/api/sedes");
        setSedes(data);
        // default: primera sede activa
        const first = data?.find((s: Sede) => s.activo) || data?.[0];
        setSedeId(first ? String(first.id) : "");
      } catch (e) {
        console.error(e);
        toast.error("No se pudieron cargar las sedes", "Error");
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  if (!open || !equipo) return null;

  const close = () => {
    onClose();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!sedeId) {
      toast.warning("Debes seleccionar una sede", "Falta dato");
      return;
    }
    if (!motivoIngreso.trim()) {
      toast.warning("Escribe el motivo de ingreso", "Falta dato");
      return;
    }

    setLoading(true);
    try {
      const orden = await authFetch("/api/ordenes", {
        method: "POST",
        body: JSON.stringify({
          sedeId: Number(sedeId),
          clienteId: equipo.cliente.id,
          equipoId: equipo.id,
          tipoIngreso,
          motivoIngreso: motivoIngreso.trim(),
          tecnicoId: null,
        }),
      });   

      toast.success("Orden creada correctamente", `OS creada: ${orden.codigo}`);
      onCreated?.();
      close();

      // Aqui esta el fetch
      navigate(`/ordenes/${orden.id}`, { replace: true });
    } catch (err: any) {
      console.error(err);
      toast.error(err?.message || "No se pudo crear la orden", "Error");     
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40">
      <div className="w-full max-w-xl rounded-2xl bg-white p-6 shadow-xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-slate-900">
            Crear orden de ingreso
          </h2>
          <button
            onClick={close}
            className="rounded-full px-2 text-slate-500 hover:bg-slate-100"
            type="button"
            disabled={loading}
          >
            ✕
          </button>
        </div>

        {/* Resumen (bloqueado) */}
        <div className="mb-4 rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-xs font-semibold text-slate-600 uppercase">
            Cliente
          </div>
          <div className="text-sm font-semibold text-slate-900">
            {equipo.cliente.nombre}{" "}
            {equipo.cliente.empresa ? `· ${equipo.cliente.empresa}` : ""}
          </div>

          <div className="mt-3 text-xs font-semibold text-slate-600 uppercase">
            Equipo
          </div>
          <div className="text-sm text-slate-900">
            <span className="font-semibold">
              {equipo.marca} {equipo.modelo}
            </span>
            <span className="text-slate-500"> · Serial: {equipo.serial}</span>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Sede (solo admin elige) */}
          {esAdmin ? (
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700">
                Sede
              </label>
              <select
                value={sedeId}
                onChange={(e) => setSedeId(e.target.value)}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                required
                disabled={loading}
              >
                <option value="">Selecciona sede</option>
                {sedes.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.nombre} · {s.ciudad}
                  </option>
                ))}
              </select>
            </div>
          ) : (
            <div className="text-xs text-slate-500">
              Sede asignada automáticamente:{" "}
              <span className="font-semibold">#{usuario?.sedeId ?? "N/A"}</span>
            </div>
          )}

          {/* Tipo ingreso */}
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">
              Tipo de ingreso
            </label>
            <select
              value={tipoIngreso}
              onChange={(e) => setTipoIngreso(e.target.value as any)}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
              disabled={loading}
            >
              <option value="GARANTIA">Garantía</option>
              <option value="MANTENIMIENTO">Mantenimiento</option>
              <option value="REPARACION">Reparación</option>
            </select>
          </div>

          {/* Motivo */}
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">
              Motivo de ingreso
            </label>
            <textarea
              value={motivoIngreso}
              onChange={(e) => setMotivoIngreso(e.target.value)}
              rows={4}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
              placeholder="Describe el problema, síntomas, condiciones de garantía, etc."
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
              {loading ? "Creando..." : "Crear orden"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
