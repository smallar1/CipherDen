import { createContext } from 'react'

export interface AuthContextValue {
  token: string | null
  setToken: (token: string | null) => void
}

export const AuthContext = createContext<AuthContextValue | undefined>(undefined)
