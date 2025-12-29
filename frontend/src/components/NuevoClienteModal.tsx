import { useState } from "react";
import { authFetch } from "../api/client";
import { useToast } from "../ui/toast/ToastProvider";

type Cliente = {
  id: number;
  nombre: string;
  documento?: string | null;
  telefono?: string | null;
  correo?: string | null;
  empresa?: string | null;
};

type Props = {
  open: boolean;
  onClose: () => void;
  onCreated: (cliente: Cliente) => void;
};

export default function NuevoClienteModal({ open, onClose, onCreated }: Props) {
  const toast = useToast();

  const [nombre, setNombre] = useState("");
  const [documento, setDocumento] = useState("");
  const [telefono, setTelefono] = useState("");
  const [correo, setCorreo] = useState("");
  const [empresa, setEmpresa] = useState("");
  const [loading, setLoading] = useState(false);

  // mantenemos el bloque amarillo para 409 y/o mensajes útiles
  const [error, setError] = useState("");
  const [clienteExistente, setClienteExistente] = useState<Cliente | null>(
    null
  );

  if (!open) return null;

  const reset = () => {
    setNombre("");
    setDocumento("");
    setTelefono("");
    setCorreo("");
    setEmpresa("");
    setError("");
    setClienteExistente(null);
  };

  const close = () => {
    reset();
    onClose();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setClienteExistente(null);
    setLoading(true);

    try {
      const res = await authFetch("/api/clientes", {
        method: "POST",
        body: JSON.stringify({
          nombre,
          documento: documento || null,
          telefono: telefono || null,
          correo: correo || null,
          empresa: empresa || null,
        }),
      });

      // ✅ toast global
      toast.success("Cliente creado y seleccionado", "Listo");

      onCreated(res);
      close();
    } catch (err: any) {
      const msg = err?.message || "Error creando cliente";

      // Intentamos parsear 409 (viene como string desde authFetch)
      try {
        const parsed = JSON.parse(msg);
        if (parsed?.error && parsed?.cliente && parsed?.cliente?.id) {
          setClienteExistente(parsed.cliente);
          setError(parsed.error);

          // ℹ️ toast para duplicado
          toast.info("Ya existía un cliente con esos datos", "Sin duplicados");
        } else {
          setError(msg);
          toast.error(msg, "Error");
        }
      } catch {
        setError(msg);
        toast.error(msg, "Error");
      }
    } finally {
      setLoading(false);
    }
  };

  const seleccionarExistente = () => {
    if (!clienteExistente) return;
    onCreated(clienteExistente);

    // ℹ️ toast selección existente
    toast.info("Cliente existente seleccionado", "Listo");

    close();
  };

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40">
      <div className="w-full max-w-lg rounded-2xl bg-white p-6 shadow-xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-slate-900">
            Crear cliente
          </h2>
          <button
            onClick={close}
            className="rounded-full px-2 text-slate-500 hover:bg-slate-100"
          >
            ✕
          </button>
        </div>

        {error && (
          <div className="mb-3 rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-800">
            {error}
            {clienteExistente && (
              <div className="mt-2 rounded-md bg-white p-2 text-xs text-slate-700">
                <div className="font-semibold">{clienteExistente.nombre}</div>
                <div className="opacity-80">
                  {clienteExistente.empresa
                    ? `Empresa: ${clienteExistente.empresa} · `
                    : ""}
                  {clienteExistente.telefono
                    ? `Tel: ${clienteExistente.telefono} · `
                    : ""}
                  {clienteExistente.documento
                    ? `Doc: ${clienteExistente.documento}`
                    : ""}
                </div>
                <button
                  type="button"
                  onClick={seleccionarExistente}
                  className="mt-2 rounded-lg bg-emerald-600 px-3 py-2 text-xs font-semibold text-white hover:bg-emerald-700"
                >
                  Seleccionar este cliente
                </button>
              </div>
            )}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">
              Nombre *
            </label>
            <input
              type="text"
              value={nombre}
              onChange={(e) => setNombre(e.target.value)}
              required
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
              placeholder="Nombre del cliente"
            />
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700">
                Teléfono
              </label>
              <input
                type="text"
                value={telefono}
                onChange={(e) => setTelefono(e.target.value)}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                placeholder="310..."
              />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700">
                Documento
              </label>
              <input
                type="text"
                value={documento}
                onChange={(e) => setDocumento(e.target.value)}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                placeholder="CC / NIT"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700">
                Correo
              </label>
              <input
                type="email"
                value={correo}
                onChange={(e) => setCorreo(e.target.value)}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                placeholder="correo@..."
              />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700">
                Empresa
              </label>
              <input
                type="text"
                value={empresa}
                onChange={(e) => setEmpresa(e.target.value)}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                placeholder="Opcional"
              />
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
              {loading ? "Guardando..." : "Guardar cliente"}
            </button>  
          </div>
        </form>
      </div>
    </div>
  );
}
