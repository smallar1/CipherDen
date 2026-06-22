export const BASE_URL = 'http://127.0.0.1:8765'

async function readErrorDetail(response: Response, fallback: string): Promise<string> {
  const body = await response.json()
  return typeof body.detail === 'string' ? body.detail : fallback
}

export interface UnlockResult {
  token: string
}

export async function unlock(masterPassword: string): Promise<UnlockResult> {
  const response = await fetch(`${BASE_URL}/unlock`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ master_password: masterPassword }),
  })
  if (!response.ok) {
    throw new Error(await readErrorDetail(response, 'Unlock failed.'))
  }
  return response.json()
}

export interface GenerateParams {
  length: number
  useSymbols: boolean
  useNumbers: boolean
}

export async function generatePassword(params: GenerateParams): Promise<string> {
  const url = new URL(`${BASE_URL}/generate`)
  url.searchParams.set('length', String(params.length))
  url.searchParams.set('use_symbols', String(params.useSymbols))
  url.searchParams.set('use_numbers', String(params.useNumbers))
  const response = await fetch(url.toString())
  if (!response.ok) {
    throw new Error(await readErrorDetail(response, 'Failed to generate password.'))
  }
  const data = await response.json()
  return data.password
}

export interface EntryInput {
  title: string
  username: string
  password: string
}

export async function createEntry(token: string, entry: EntryInput): Promise<void> {
  const response = await fetch(`${BASE_URL}/entries`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(entry),
  })
  if (!response.ok) {
    throw new Error(await readErrorDetail(response, 'Failed to save entry.'))
  }
}
