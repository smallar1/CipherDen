import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as client from '../api/client'
import { AuthContext } from '../auth/AuthContext'
import { AddEntryModal } from './AddEntryModal'

const TEST_PASSWORD = 'xK9!mPq2vT@nL8wZ' // pragma: allowlist secret

function renderModal(token: string | null = 'token-123', onClose = vi.fn()) {
  return render(
    <AuthContext.Provider value={{ token, setToken: vi.fn() }}>
      <AddEntryModal initialPassword={TEST_PASSWORD} onClose={onClose} />
    </AuthContext.Provider>,
  )
}

describe('AddEntryModal', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('pre-fills the password field with the generated password', () => {
    renderModal()
    expect(screen.getByLabelText('Password')).toHaveValue(TEST_PASSWORD)
  })

  it('saves the entry and shows a confirmation on success', async () => {
    const user = userEvent.setup()
    const spy = vi.spyOn(client, 'createEntry').mockResolvedValue(undefined)
    renderModal('token-123')

    await user.type(screen.getByLabelText('Title'), 'Example Site')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    expect(await screen.findByText('Entry saved.')).toBeInTheDocument()
    expect(spy).toHaveBeenCalledWith('token-123', {
      title: 'Example Site',
      username: '',
      password: TEST_PASSWORD,
    })
  })

  it('shows an inline error and keeps the modal open on failure', async () => {
    const user = userEvent.setup()
    vi.spyOn(client, 'createEntry').mockRejectedValue(
      new Error('Invalid or expired session token.'),
    )
    renderModal('token-123')

    await user.type(screen.getByLabelText('Title'), 'Example Site')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Invalid or expired session token.',
    )
    expect(screen.getByLabelText('Title')).toHaveValue('Example Site')
  })

  it('calls onClose when Cancel is clicked', async () => {
    const user = userEvent.setup()
    const onClose = vi.fn()
    renderModal('token-123', onClose)

    await user.click(screen.getByRole('button', { name: 'Cancel' }))

    expect(onClose).toHaveBeenCalled()
  })

  it('shows error and does not call createEntry when token is null', async () => {
    const user = userEvent.setup()
    const spy = vi.spyOn(client, 'createEntry')
    renderModal(null)

    await user.type(screen.getByLabelText('Title'), 'Example Site')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'You must be unlocked to save an entry.',
    )
    expect(spy).not.toHaveBeenCalled()
  })
})
