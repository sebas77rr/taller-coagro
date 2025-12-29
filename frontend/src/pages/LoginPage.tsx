import { useState } from "react";
import { useNavigate } from "react-router-dom";

export default function LoginPage() {
  const [email, setEmail] = useState("admin@coagro.com.co");
  const [password, setPassword] = useState("Admin2025*");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await fetch("http://localhost:4000/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || "Credenciales inválidas");
        return;
      }

      localStorage.setItem("taller_token", data.token);
      localStorage.setItem("taller_usuario", JSON.stringify(data.usuario));

      navigate("/", { replace: true });
    } catch (err) {
      console.error(err);
      setError("No se pudo conectar con el servidor");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-emerald-900 flex items-center justify-center px-4">
      <div className="w-full max-w-4xl bg-white rounded-2xl shadow-xl overflow-hidden grid md:grid-cols-2">
        
        {/* Panel izquierdo */}
        <div className="bg-slate-900 text-white p-10 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-3 mb-8">
              <div className="h-10 w-10 bg-emerald-500 rounded-xl flex items-center justify-center font-bold">
                TC
              </div>
              <div>
                <p className="text-xs text-slate-300">PLATAFORMA INTERNA</p>
                <h2 className="text-sm font-semibold">Taller Coagro</h2>
              </div>
            </div>

            <h1 className="text-2xl font-semibold mb-3">
              Control de órdenes de servicio
            </h1>
            <p className="text-sm text-slate-300">
              Centraliza garantías, mantenimientos y reparaciones de todas las
              sedes en un solo panel.
            </p>
          </div>

          <p className="text-xs text-slate-400">
            Trazabilidad por sede · Técnicos · Historial
          </p>
        </div>

        {/* Panel derecho */}
        <div className="p-10">
          <p className="text-xs text-emerald-600 font-medium mb-2">
            Acceso restringido
          </p>

          <h2 className="text-xl font-semibold mb-2">
            Inicia sesión en Taller Coagro
          </h2>

          <p className="text-xs text-slate-500 mb-6">
            Usa tu correo corporativo. Si tienes problemas para ingresar,
            contacta a sistemas.
          </p>

          {error && (
            <div className="mb-4 text-xs text-red-700 bg-red-50 border border-red-200 rounded-md px-3 py-2">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-xs text-slate-600">
                Correo corporativo
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-emerald-600"
              />
            </div>
    
            <div>
              <label className="text-xs text-slate-600">Contraseña</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-emerald-600"
              />
            </div>    

            <button    
              type="submit"
              disabled={loading}
              className="w-full bg-emerald-600 hover:bg-emerald-700 disabled:opacity-60 text-white rounded-lg py-2 text-sm font-medium transition"
            >
              {loading ? "Verificando..." : "Ingresar al sistema"}
            </button>
          </form>

          <p className="mt-6 text-[11px] text-slate-400">
            Uso exclusivo interno de Coagro Internacional.
          </p>
        </div>   
      </div>      
    </div>
  );
}       