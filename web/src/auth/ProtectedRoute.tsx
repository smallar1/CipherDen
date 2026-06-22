import { Navigate, Outlet } from 'react-router-dom'
import { useAuth } from './AuthContext'

export function ProtectedRoute() {
  const { token } = useAuth()
  if (token === null) {
    return <Navigate to="/unlock" replace />
  }
  return <Outlet />
}
