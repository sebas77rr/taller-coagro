import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import LoginPage from "./pages/LoginPage";
import OrdersPage from "./pages/OrdersPage";
import EquiposPage from "./pages/EquiposPage";
import OrderDetailPage from "./pages/OrderDetailPage";
import OrderPrintPage from "./pages/OrderPrintPage";
import ProtectedRoute from "./components/ProtectedRoute";
import AppLayout from "./layouts/AppLayout";   
import { isAuthenticated } from "./hooks/useAuth";
  
function App() {
  return (  
    <BrowserRouter>
      <Routes>
        {/* Login */}    
        <Route
          path="/login"
          element={isAuthenticated() ? <Navigate to="/" replace /> : <LoginPage />}
        />

        {/* Rutas protegidas dentro del layout */}
        <Route
          path="/"
          element={
            <ProtectedRoute>
              <AppLayout />
            </ProtectedRoute>
          }
        >
          {/* Home */}
          <Route index element={<OrdersPage />} />

          {/* Equipos */}
          <Route path="equipos" element={<EquiposPage />} />

          {/* Detalle orden */}
          <Route path="ordenes/:id" element={<OrderDetailPage />} />

          {/* ✅ Imprimir orden */}
          <Route path="ordenes/:id/print" element={<OrderPrintPage />} />
        </Route>

        {/* Cualquier otra ruta → al login */}
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </BrowserRouter>
  );    
}

export default App;