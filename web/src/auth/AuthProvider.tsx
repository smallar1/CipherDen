import { useState, type ReactNode } from 'react'
import { AuthContext } from './authContext'

export { type AuthContextValue, AuthContext } from './authContext'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(null)
  return <AuthContext.Provider value={{ token, setToken }}>{children}</AuthContext.Provider>
}
