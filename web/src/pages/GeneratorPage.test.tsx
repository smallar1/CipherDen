import { act, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as client from '../api/client'
import { AuthContext } from '../auth/AuthContext'
import { GeneratorPage } from './GeneratorPage'

function renderGeneratorPage() {
  return render(
    <AuthContext.Provider value={{ token: 'token-123', setToken: vi.fn() }}>
      <GeneratorPage />
    </AuthContext.Provider>,
  )
}

describe('GeneratorPage', () => {
  beforeEach(() => {
    // shouldAdvanceTime keeps Testing Library's setTimeout-based polling
    // (used internally by findBy*/waitFor) working under fake timers,
    // while still letting us manually fast-forward the debounce delay below.
    vi.useFakeTimers({ shouldAdvanceTime: true })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('fetches a password on mount', async () => {
    vi.spyOn(client, 'generatePassword').mockResolvedValue('xK9!mPq2vT@nL8wZ')
    renderGeneratorPage()
    expect(await screen.findByText('xK9!mPq2vT@nL8wZ')).toBeInTheDocument()
  })

  it('refetches immediately when a checkbox is toggled', async () => {
    const user = userEvent.setup({ delay: null })
    const spy = vi
      .spyOn(client, 'generatePassword')
      .mockResolvedValueOnce('first-password')
      .mockResolvedValueOnce('second-password')
    renderGeneratorPage()
    await screen.findByText('first-password')

    await user.click(screen.getByLabelText('Symbols'))

    expect(await screen.findByText('second-password')).toBeInTheDocument()
    expect(spy).toHaveBeenCalledTimes(2)
  })

  it('debounces the length input before refetching', async () => {
    const user = userEvent.setup({ delay: null })
    const spy = vi
      .spyOn(client, 'generatePassword')
      .mockResolvedValueOnce('first-password')
      .mockResolvedValueOnce('second-password')
    renderGeneratorPage()
    await screen.findByText('first-password')

    await user.clear(screen.getByLabelText('Length'))
    await user.type(screen.getByLabelText('Length'), '24')

    expect(spy).toHaveBeenCalledTimes(1)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(300)
    })

    expect(spy).toHaveBeenCalledTimes(2)
  })

  it('shows an inline error and keeps the previous password when a fetch fails', async () => {
    const user = userEvent.setup({ delay: null })
    vi.spyOn(client, 'generatePassword')
      .mockResolvedValueOnce('first-password')
      .mockRejectedValueOnce(new Error('Failed to generate password.'))
    renderGeneratorPage()
    await screen.findByText('first-password')

    await user.click(screen.getByLabelText('Numbers'))

    expect(await screen.findByRole('alert')).toHaveTextContent('Failed to generate password.')
    expect(screen.getByText('first-password')).toBeInTheDocument()
  })

  it('opens the add-entry modal pre-filled with the current password', async () => {
    const user = userEvent.setup({ delay: null })
    vi.spyOn(client, 'generatePassword').mockResolvedValue('xK9!mPq2vT@nL8wZ')
    renderGeneratorPage()
    await screen.findByText('xK9!mPq2vT@nL8wZ')

    await user.click(screen.getByRole('button', { name: 'Use this password' }))

    expect(screen.getByDisplayValue('xK9!mPq2vT@nL8wZ')).toBeInTheDocument()
  })
})
