import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from './auth/AuthContext'
import { ProtectedRoute } from './auth/ProtectedRoute'
import { GeneratorPage } from './pages/GeneratorPage'
import { UnlockPage } from './pages/UnlockPage'

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/unlock" element={<UnlockPage />} />
          <Route element={<ProtectedRoute />}>
            <Route path="/" element={<GeneratorPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}

export default App
