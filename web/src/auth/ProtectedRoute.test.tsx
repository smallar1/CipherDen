import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { AuthContext } from './AuthContext'
import { ProtectedRoute } from './ProtectedRoute'

function renderWithToken(token: string | null) {
  return render(
    <AuthContext.Provider value={{ token, setToken: vi.fn() }}>
      <MemoryRouter initialEntries={['/']}>
        <Routes>
          <Route path="/unlock" element={<div>Unlock page</div>} />
          <Route element={<ProtectedRoute />}>
            <Route path="/" element={<div>Protected content</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    </AuthContext.Provider>,
  )
}

describe('ProtectedRoute', () => {
  it('redirects to /unlock when there is no token', () => {
    renderWithToken(null)
    expect(screen.getByText('Unlock page')).toBeInTheDocument()
  })

  it('renders the protected content when a token is present', () => {
    renderWithToken('abc123')
    expect(screen.getByText('Protected content')).toBeInTheDocument()
  })
})
