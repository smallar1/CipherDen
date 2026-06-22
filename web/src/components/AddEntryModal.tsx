import { useState, type FormEvent } from 'react'
import { createEntry } from '../api/client'
import { useAuth } from '../auth/AuthContext'

interface AddEntryModalProps {
  initialPassword: string
  onClose: () => void
}

export function AddEntryModal({ initialPassword, onClose }: AddEntryModalProps) {
  const { token } = useAuth()
  const [title, setTitle] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState(initialPassword)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)
    if (token === null) {
      setError('You must be unlocked to save an entry.')
      return
    }
    try {
      await createEntry(token, { title, username, password })
      setSaved(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save entry.')
    }
  }

  if (saved) {
    return (
      <div role="dialog">
        <p>Entry saved.</p>
        <button type="button" onClick={onClose}>
          Close
        </button>
      </div>
    )
  }

  return (
    <div role="dialog">
      <form onSubmit={handleSubmit}>
        <h2>Add Entry</h2>
        <label htmlFor="entry-title">Title</label>
        <input id="entry-title" value={title} onChange={(event) => setTitle(event.target.value)} />

        <label htmlFor="entry-username">Username</label>
        <input
          id="entry-username"
          value={username}
          onChange={(event) => setUsername(event.target.value)}
        />

        <label htmlFor="entry-password">Password</label>
        <input
          id="entry-password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
        />

        {error !== null && <p role="alert">{error}</p>}

        <button type="submit">Save</button>
        <button type="button" onClick={onClose}>
          Cancel
        </button>
      </form>
    </div>
  )
}
