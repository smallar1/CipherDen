import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as client from '../api/client'
import { AuthContext } from '../auth/AuthProvider'
import { UnlockPage } from './UnlockPage'

function renderUnlockPage(setToken = vi.fn()) {
  return render(
    <AuthContext.Provider value={{ token: null, setToken }}>
      <MemoryRouter>
        <UnlockPage />
      </MemoryRouter>
    </AuthContext.Provider>,
  )
}

describe('UnlockPage', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('calls setToken with the returned token on success', async () => {
    vi.spyOn(client, 'unlock').mockResolvedValue({ token: 'abc123' })
    const setToken = vi.fn()
    renderUnlockPage(setToken)

    await userEvent.type(screen.getByLabelText('Master password'), 'correct-password')
    await userEvent.click(screen.getByRole('button', { name: 'Unlock' }))

    await waitFor(() => expect(setToken).toHaveBeenCalledWith('abc123'))
  })

  it('shows an inline error message on failure', async () => {
    vi.spyOn(client, 'unlock').mockRejectedValue(new Error('Incorrect master password.'))
    renderUnlockPage()

    await userEvent.type(screen.getByLabelText('Master password'), 'wrong-password')
    await userEvent.click(screen.getByRole('button', { name: 'Unlock' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Incorrect master password.')
  })
})
