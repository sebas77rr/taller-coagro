import { Navigate } from "react-router-dom";
import { isAuthenticated } from "../hooks/useAuth";

type Props = {
  children: React.ReactElement;
};

export default function ProtectedRoute({ children }: Props) {
  if (!isAuthenticated()) {
    return <Navigate to="/login" replace />;
  }
  return children;
} 