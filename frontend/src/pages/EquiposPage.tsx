import { useEffect, useState } from "react";
import { authFetch } from "../api/client";
import NuevoEquipoModal from "../components/NuevoEquipoModal";
import { useToast } from "../ui/toast/ToastProvider";
import NuevaOrdenModal from "../components/NuevaOrdenModal";

type Equipo = {
  id: number;
  marca: string;
  modelo: string;
  serial: string;
  descripcion?: string | null;
  cliente: {
    id: number;
    nombre: string;
    empresa?: string | null;
  };
};

export default function EquiposPage() {
  const toast = useToast();

  const [equipos, setEquipos] = useState<Equipo[]>([]);
  const [loading, setLoading] = useState(true);

  const [openNuevoEquipo, setOpenNuevoEquipo] = useState(false);

  // ✅ NUEVO: modal de orden
  const [openNuevaOrden, setOpenNuevaOrden] = useState(false);
  const [equipoSeleccionado, setEquipoSeleccionado] = useState<Equipo | null>(null);

  const cargarEquipos = async () => {
    try {
      setLoading(true);
      const data = await authFetch("/api/equipos");
      setEquipos(data);
    } catch (err) {
      console.error(err);
      toast.error("No se pudieron cargar los equipos", "Error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    cargarEquipos();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold text-slate-900">
          Equipos / Maquinaria
        </h1>

        <button
          onClick={() => setOpenNuevoEquipo(true)}
          className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-700"
        >
          + Registrar equipo
        </button>
      </div>

      {/* Tabla */}
      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
        <table className="min-w-full divide-y divide-slate-200">
          <thead className="bg-slate-50">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-slate-600">
                Cliente
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-slate-600">
                Equipo
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-slate-600">
                Serial
              </th>
              <th className="px-4 py-3 text-right text-xs font-semibold uppercase text-slate-600">
                Acciones
              </th>
            </tr>
          </thead>

          <tbody className="divide-y divide-slate-100">
            {loading && (
              <tr>
                <td
                  colSpan={4}
                  className="px-4 py-6 text-center text-sm text-slate-500"
                >
                  Cargando equipos...
                </td>
              </tr>
            )}

            {!loading && equipos.length === 0 && (
              <tr>
                <td
                  colSpan={4}
                  className="px-4 py-6 text-center text-sm text-slate-500"
                >
                  No hay equipos registrados
                </td>
              </tr>
            )}

            {equipos.map((eq) => (
              <tr key={eq.id} className="hover:bg-slate-50">
                <td className="px-4 py-3 text-sm text-slate-800">
                  <div className="font-medium">{eq.cliente.nombre}</div>
                  {eq.cliente.empresa && (
                    <div className="text-xs text-slate-500">
                      {eq.cliente.empresa}
                    </div>
                  )}
                </td>

                <td className="px-4 py-3 text-sm text-slate-800">
                  {eq.marca} {eq.modelo}
                </td>

                <td className="px-4 py-3 text-sm text-slate-600">{eq.serial}</td>

                <td className="px-4 py-3 text-right">
                  <button
                    onClick={() => {
                      setEquipoSeleccionado(eq);
                      setOpenNuevaOrden(true);
                    }}
                    className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-100"
                  >
                    Crear orden   
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Modal nuevo equipo */}
      <NuevoEquipoModal
        open={openNuevoEquipo}
        onClose={() => setOpenNuevoEquipo(false)}
        onCreated={() => {
          setOpenNuevoEquipo(false);
          cargarEquipos();
          toast.success("Equipo registrado correctamente", "Listo");
        }}
      />

      {/* ✅ Modal nueva orden */}
      <NuevaOrdenModal
        open={openNuevaOrden}
        onClose={() => setOpenNuevaOrden(false)}    
        equipo={equipoSeleccionado}
        onCreated={() => {
          setOpenNuevaOrden(false);
        }}
      />
    </div>
  );
}  