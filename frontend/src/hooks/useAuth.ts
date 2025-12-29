export type UsuarioAuth = {
  id: number;
  nombre: string;
  email: string;
  rol: "ADMIN" | "TECNICO" | "RECEPCION";
  sedeId: number | null;
};

export function getToken() {
  return localStorage.getItem("taller_token");
}      

export function getUsuario(): UsuarioAuth | null {
  const raw = localStorage.getItem("taller_usuario");
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }               
}

export function isAuthenticated() {
  return !!getToken() && !!getUsuario();
}

export function logout() {
  localStorage.removeItem("taller_token");
  localStorage.removeItem("taller_usuario");
}   