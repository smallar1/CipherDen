import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as client from '../api/client'
import { useGeneratePassword } from './useGeneratePassword'

describe('useGeneratePassword', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('fetches a password on mount', async () => {
    vi.spyOn(client, 'generatePassword').mockResolvedValue('xK9!mPq2vT@nL8wZ')
    const { result } = renderHook(() =>
      useGeneratePassword({ length: 16, useSymbols: true, useNumbers: true }),
    )
    await waitFor(() => expect(result.current.password).toBe('xK9!mPq2vT@nL8wZ'))
  })

  it('re-fetches when params change', async () => {
    const spy = vi
      .spyOn(client, 'generatePassword')
      .mockResolvedValueOnce('first-password')
      .mockResolvedValueOnce('second-password')
    const { result, rerender } = renderHook(
      ({ length }) => useGeneratePassword({ length, useSymbols: true, useNumbers: true }),
      { initialProps: { length: 16 } },
    )
    await waitFor(() => expect(result.current.password).toBe('first-password'))

    rerender({ length: 20 })

    await waitFor(() => expect(result.current.password).toBe('second-password'))
    expect(spy).toHaveBeenCalledTimes(2)
  })

  it('re-fetches when regenerate is called with unchanged params', async () => {
    vi.spyOn(client, 'generatePassword')
      .mockResolvedValueOnce('first-password')
      .mockResolvedValueOnce('second-password')
    const { result } = renderHook(() =>
      useGeneratePassword({ length: 16, useSymbols: true, useNumbers: true }),
    )
    await waitFor(() => expect(result.current.password).toBe('first-password'))

    act(() => {
      result.current.regenerate()
    })

    await waitFor(() => expect(result.current.password).toBe('second-password'))
  })

  it('sets an inline error and keeps the previous password when a request fails', async () => {
    vi.spyOn(client, 'generatePassword')
      .mockResolvedValueOnce('first-password')
      .mockRejectedValueOnce(new Error('Failed to generate password.'))
    const { result } = renderHook(() =>
      useGeneratePassword({ length: 16, useSymbols: true, useNumbers: true }),
    )
    await waitFor(() => expect(result.current.password).toBe('first-password'))

    act(() => {
      result.current.regenerate()
    })

    await waitFor(() => expect(result.current.error).toBe('Failed to generate password.'))
    expect(result.current.password).toBe('first-password')
  })
})
