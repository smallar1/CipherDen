import { useState } from 'react'
import { AddEntryModal } from '../components/AddEntryModal'
import { useDebouncedValue } from '../hooks/useDebouncedValue'
import { useGeneratePassword } from '../hooks/useGeneratePassword'

const DEBOUNCE_MS = 300
const MIN_LENGTH = 8
const MAX_LENGTH = 128

export function GeneratorPage() {
  const [length, setLength] = useState(16)
  const [useSymbols, setUseSymbols] = useState(true)
  const [useNumbers, setUseNumbers] = useState(true)
  const [isModalOpen, setIsModalOpen] = useState(false)

  const debouncedLength = useDebouncedValue(length, DEBOUNCE_MS)
  const { password, error, regenerate } = useGeneratePassword({
    length: debouncedLength,
    useSymbols,
    useNumbers,
  })

  return (
    <div>
      <h1>Password Generator</h1>
      <p>{password}</p>
      <button type="button" onClick={regenerate}>
        Regenerate
      </button>
      <button type="button" onClick={() => navigator.clipboard.writeText(password)}>
        Copy
      </button>

      <div>
        <label htmlFor="length">Length</label>
        <input
          id="length"
          type="number"
          min={MIN_LENGTH}
          max={MAX_LENGTH}
          value={length}
          onChange={(event) => setLength(Number(event.target.value))}
        />
        <label>
          <input
            type="checkbox"
            checked={useSymbols}
            onChange={(event) => setUseSymbols(event.target.checked)}
          />
          Symbols
        </label>
        <label>
          <input
            type="checkbox"
            checked={useNumbers}
            onChange={(event) => setUseNumbers(event.target.checked)}
          />
          Numbers
        </label>
      </div>

      {error !== null && <p role="alert">{error}</p>}

      <button type="button" onClick={() => setIsModalOpen(true)} disabled={password === ''}>
        Use this password
      </button>

      {isModalOpen && (
        <AddEntryModal initialPassword={password} onClose={() => setIsModalOpen(false)} />
      )}
    </div>
  )
}
