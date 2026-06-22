import { act, renderHook } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { AuthProvider, useAuth } from './AuthContext'

describe('useAuth', () => {
  it('starts with a null token', () => {
    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider })
    expect(result.current.token).toBeNull()
  })

  it('updates the token via setToken', () => {
    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider })
    act(() => {
      result.current.setToken('abc123')
    })
    expect(result.current.token).toBe('abc123')
  })

  it('throws when used outside an AuthProvider', () => {
    expect(() => renderHook(() => useAuth())).toThrow(
      'useAuth must be used within an AuthProvider',
    )
  })
})
