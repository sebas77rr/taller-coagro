import { useEffect, useState } from "react";
import { authFetch } from "../api/client";
import NuevoClienteModal from "./NuevoClienteModal";
import { useToast } from "../ui/toast/ToastProvider";

type Cliente = {
  id: number;
  nombre: string;
  empresa: string | null;
  documento?: string | null;
  telefono?: string | null;
  correo?: string | null;
};

type Props = {
  open: boolean;
  onClose: () => void;
  onCreated?: () => void; // para refrescar lista de equipos si quieres
};

export default function NuevoEquipoModal({ open, onClose, onCreated }: Props) {
  const toast = useToast();

  const [clientes, setClientes] = useState<Cliente[]>([]);
  const [clienteId, setClienteId] = useState("");
  const [marca, setMarca] = useState("");
  const [modelo, setModelo] = useState("");
  const [serial, setSerial] = useState("");
  const [descripcion, setDescripcion] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [openCliente, setOpenCliente] = useState(false);
  const [searchCliente, setSearchCliente] = useState("");

  useEffect(() => {
    if (!open) return;

    const t = setTimeout(async () => {
      try {
        setError("");
        const q = searchCliente.trim()
          ? `?search=${encodeURIComponent(searchCliente.trim())}`
          : "";
        const data = await authFetch(`/api/clientes${q}`);
        setClientes(data);
      } catch (err) {
        console.error(err);
        setError("No se pudieron cargar los clientes");
        toast.error("No se pudieron cargar los clientes", "Error");
      }
    }, 250);

    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, searchCliente]);

  if (!open) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      await authFetch("/api/equipos", {
        method: "POST",
        body: JSON.stringify({
          clienteId: Number(clienteId),
          marca,
          modelo,
          serial,
          descripcion,
        }),
      });

      toast.success("Maquinaria registrada correctamente", "Equipo creado");

      // limpiar y cerrar
      setClienteId("");
      setMarca("");
      setModelo("");
      setSerial("");
      setDescripcion("");
      setSearchCliente("");

      onCreated?.();
      onClose();
    } catch (err: any) {
      console.error(err);
      const msg = err?.message || "Error creando equipo";
      setError(msg);
      toast.error(msg, "No se pudo guardar");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <div className="fixed inset-0 z-30 flex items-center justify-center bg-black/40">
        <div className="w-full max-w-lg rounded-2xl bg-white p-6 shadow-xl">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-slate-900">
              Registrar nueva maquinaria
            </h2>
            <button
              onClick={onClose}
              className="rounded-full px-2 text-slate-500 hover:bg-slate-100"
              type="button"
            >
              ✕
            </button>
          </div>

          {error && (
            <div className="mb-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Cliente + buscar + crear */}
            <div>
              <div className="mb-1 flex items-center justify-between">
                <label className="block text-sm font-medium text-slate-700">
                  Cliente
                </label>

                <button
                  type="button"
                  onClick={() => setOpenCliente(true)}
                  className="rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-slate-800"
                  disabled={loading}
                >
                  + Crear cliente
                </button>
              </div>

              <input
                type="text"
                value={searchCliente}
                onChange={(e) => setSearchCliente(e.target.value)}
                className="mb-2 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                placeholder="Buscar por nombre, teléfono, documento, correo..."
                disabled={loading}
              />

              <select
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                value={clienteId}
                onChange={(e) => setClienteId(e.target.value)}
                required
                disabled={loading}
              >
                <option value="">Selecciona un cliente</option>
                {clientes.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.nombre} {c.empresa ? `- ${c.empresa}` : ""}
                  </option>
                ))}
              </select>

              <p className="mt-1 text-xs text-slate-500">
                Bug : Revisar el api de Maquinaria y quitar retraso de guardado
              </p>
            </div>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700">
                  Marca
                </label>
                <input
                  type="text"
                  value={marca}
                  onChange={(e) => setMarca(e.target.value)}
                  required
                  disabled={loading}
                  className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                />
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700">
                  Modelo
                </label>
                <input
                  type="text"
                  value={modelo}
                  onChange={(e) => setModelo(e.target.value)}
                  required
                  disabled={loading}
                  className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                />
              </div>
            </div>

            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700">
                Serial
              </label>
              <input
                type="text"
                value={serial}
                onChange={(e) => setSerial(e.target.value)}
                required
                disabled={loading}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
              />
            </div>

            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700">
                Descripción / notas
              </label>
              <textarea
                value={descripcion}
                onChange={(e) => setDescripcion(e.target.value)}
                rows={3}
                disabled={loading}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                placeholder="Datos adicionales de la máquina, ubicación, referencia interna, etc."
              />
            </div>

            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={onClose}
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
                {loading ? "Guardando..." : "Guardar equipo"}
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* Modal crear cliente */}
      <NuevoClienteModal
        open={openCliente}
        onClose={() => setOpenCliente(false)}
        onCreated={(cliente) => {
          // Agrega (si no existe) y selecciona automático
          setClientes((prev) => {
            const existe = prev.some((x) => x.id === cliente.id);
            return existe ? prev : [cliente, ...prev];
          });      
          setClienteId(String(cliente.id));
          setOpenCliente(false);
          setSearchCliente("");
        }}
      />
    </>
  );
}         