import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { unlock } from '../api/client'
import { useAuth } from '../auth/AuthContext'

export function UnlockPage() {
  const [masterPassword, setMasterPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const { setToken } = useAuth()
  const navigate = useNavigate()

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)
    try {
      const { token } = await unlock(masterPassword)
      setToken(token)
      navigate('/')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unlock failed.')
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <h1>Unlock CipherDen</h1>
      <label htmlFor="master-password">Master password</label>
      <input
        id="master-password"
        type="password"
        value={masterPassword}
        onChange={(event) => setMasterPassword(event.target.value)}
      />
      <button type="submit">Unlock</button>
      {error !== null && <p role="alert">{error}</p>}
    </form>
  )
}
