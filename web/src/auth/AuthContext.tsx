import { createContext, useContext, useState, type ReactNode } from 'react'

export interface AuthContextValue {
  token: string | null
  setToken: (token: string | null) => void
}

export const AuthContext = createContext<AuthContextValue | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(null)
  return <AuthContext.Provider value={{ token, setToken }}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
