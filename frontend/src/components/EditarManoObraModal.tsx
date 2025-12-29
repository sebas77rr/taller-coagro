import { useEffect, useState } from "react";
import { authFetch } from "../api/client";
import { useToast } from "../ui/toast/ToastProvider";

type Props = {
  open: boolean;
  onClose: () => void;
  ordenId: number;
  item: any | null; // mano de obra seleccionada
  esCerrada: boolean;
  onSaved: (updatedItem: any) => void; // callback para actualizar UI
};

export default function EditarManoObraModal({
  open,
  onClose,
  ordenId,
  item,
  esCerrada,
  onSaved,
}: Props) {
  const toast = useToast();

  const [descripcion, setDescripcion] = useState("");
  const [horas, setHoras] = useState<string>("1");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open || !item) return;

    setDescripcion(item.descripcionTrabajo || item.descripcion || "");
    setHoras(String(item.horas ?? 1));
  }, [open, item]);

  if (!open) return null;

  const handleGuardar = async () => {
    if (esCerrada) {
      toast.info("Orden cerrada", "Solo lectura");
      return;
    }
    if (!item) return;

    const desc = descripcion.trim();
    const horasNum = Number(horas);

    if (!desc) {
      toast.warning("Descripción requerida", "Validación");
      return;
    }
    if (Number.isNaN(horasNum) || horasNum <= 0) {
      toast.warning("Horas inválidas", "Validación");
      return;
    }

    try {
      setSaving(true);

      const upd = await authFetch(
        `/api/ordenes/${ordenId}/mano-obra/${item.id}`,
        {
          method: "PATCH",
          body: JSON.stringify({
            descripcion: desc,
            horas: horasNum,
          }),
        }
      );

      toast.success("Mano de obra actualizada", "Listo");
      onSaved(upd);
      onClose();
    } catch (e: any) {
      console.error(e);
      toast.error(e?.message || "No se pudo actualizar", "Error");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="w-full max-w-lg rounded-xl bg-white p-5 shadow-xl">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="text-base font-semibold text-slate-900">
              Editar mano de obra
            </h3>
            <p className="text-xs text-slate-500">
              Actualiza descripción y horas (queda auditado en timeline)
            </p>
          </div>

          <button
            type="button"
            className="rounded-md px-2 py-1 text-sm text-slate-500 hover:bg-slate-100"
            onClick={onClose}
            disabled={saving}
            aria-label="Cerrar"
          >
            ✕
          </button>
        </div>

        <div className="space-y-3">
          <div>
            <label className="mb-1 block text-xs font-semibold text-slate-700">
              Descripción
            </label>
            <input
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none focus:border-slate-400"
              value={descripcion}
              onChange={(e) => setDescripcion(e.target.value)}
              placeholder="Ej: Cambio de aceite, ajuste carburación..."
              disabled={saving}
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-semibold text-slate-700">
              Horas
            </label>
            <input
              type="number"
              min={0.1}
              step={0.1}
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none focus:border-slate-400"
              value={horas}
              onChange={(e) => setHoras(e.target.value)}
              disabled={saving}
            />
          </div>
        </div>

        <div className="mt-5 flex justify-end gap-2">
          <button
            type="button"
            className="rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50"
            onClick={onClose}
            disabled={saving}
          >
            Cancelar
          </button>

          <button
            type="button"
            className="rounded-lg bg-slate-900 px-3 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-60"
            onClick={handleGuardar}
            disabled={saving}
          >
            {saving ? "Guardando..." : "Guardar cambios"}
          </button>
        </div>
      </div>
    </div>
  );
}     