import { afterEach, describe, expect, it, vi } from 'vitest'
import { BASE_URL, createEntry, generatePassword, unlock } from './client'

describe('unlock', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('returns the token on success', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ token: 'abc123' }),
    })
    vi.stubGlobal('fetch', mockFetch)

    const result = await unlock('correct-password')

    expect(result).toEqual({ token: 'abc123' })
    expect(mockFetch).toHaveBeenCalledWith(
      `${BASE_URL}/unlock`,
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ master_password: 'correct-password' }),
      }),
    )
  })

  it('throws the backend detail message on failure', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        json: async () => ({ detail: 'Incorrect master password.' }),
      }),
    )

    await expect(unlock('wrong-password')).rejects.toThrow('Incorrect master password.')
  })
})

describe('generatePassword', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('returns the generated password and sends the right query params', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ password: 'xK9!mPq2vT@nL8wZ' }), // pragma: allowlist secret
    })
    vi.stubGlobal('fetch', mockFetch)

    const result = await generatePassword({ length: 16, useSymbols: true, useNumbers: false })

    expect(result).toBe('xK9!mPq2vT@nL8wZ')
    const calledUrl = mockFetch.mock.calls[0][0] as string
    expect(calledUrl).toContain(`${BASE_URL}/generate?`)
    expect(calledUrl).toContain('length=16')
    expect(calledUrl).toContain('use_symbols=true')
    expect(calledUrl).toContain('use_numbers=false')
  })

  it('throws the backend detail message on failure', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        json: async () => ({ detail: 'Internal server error.' }),
      }),
    )

    await expect(
      generatePassword({ length: 16, useSymbols: true, useNumbers: true }),
    ).rejects.toThrow('Internal server error.')
  })
})

describe('createEntry', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('sends the Bearer token and entry payload', async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) })
    vi.stubGlobal('fetch', mockFetch)

    await createEntry('token-123', {
      title: 'Example',
      username: 'me',
      password: 'xK9!mPq2vT@nL8wZ', // pragma: allowlist secret
    })

    expect(mockFetch).toHaveBeenCalledWith(
      `${BASE_URL}/entries`,
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({ Authorization: 'Bearer token-123' }),
        body: JSON.stringify({
          title: 'Example',
          username: 'me',
          password: 'xK9!mPq2vT@nL8wZ', // pragma: allowlist secret
        }),
      }),
    )
  })

  it('throws the backend detail message on failure', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        json: async () => ({ detail: 'Invalid or expired session token.' }),
      }),
    )

    await expect(
      createEntry('bad-token', { title: 'Example', username: '', password: 'x' }),
    ).rejects.toThrow('Invalid or expired session token.')
  })
})
