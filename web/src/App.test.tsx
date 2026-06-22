import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import App from './App'

describe('App', () => {
  it('redirects to the unlock screen when there is no token', () => {
    render(<App />)
    expect(screen.getByRole('heading', { name: 'Unlock CipherDen' })).toBeInTheDocument()
  })
})
