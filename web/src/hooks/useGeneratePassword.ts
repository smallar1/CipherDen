import { useEffect, useState } from 'react'
import { generatePassword, type GenerateParams } from '../api/client'

interface GeneratePasswordResult {
  password: string
  error: string | null
  regenerate: () => void
}

export function useGeneratePassword(params: GenerateParams): GeneratePasswordResult {
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [nonce, setNonce] = useState(0)

  useEffect(() => {
    let cancelled = false

    generatePassword(params)
      .then((result) => {
        if (!cancelled) {
          setError(null)
          setPassword(result)
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to generate password.')
        }
      })

    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params.length, params.useSymbols, params.useNumbers, nonce])

  return { password, error, regenerate: () => setNonce((n) => n + 1) }
}
