// src/api/client.ts
import { getToken, logout } from "../hooks/useAuth";

const API_URL = "http://localhost:4000";

export async function authFetch(
  path: string,
  options: RequestInit = {}
): Promise<any> {
  const token = getToken();

  const res = await fetch(`${API_URL}${path}`, {
    ...options,       
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });

  // Si el backend dice 401 → token malo o vencido
  if (res.status === 401) {
    console.warn("Token inválido o expirado, cerrando sesión...");
    logout();
    window.location.href = "/login";
    throw new Error("Token inválido o expirado");
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Error HTTP ${res.status}`);
  }

  return res.json();
}   