import axios from 'axios'

// Same-origin base for direct fetch() calls (downloads, etc.). Empty string =>
// relative URLs like `/api/...`, which Vite/nginx proxy to the backend.
export const API_BASE = ''

export const api = axios.create({
  baseURL: '/api',
  timeout: 60000,
  withCredentials: true,
})

// On any 401, drop to the login screen. A custom event lets AuthProvider
// react without this module importing React.
let redirectingToLogin = false
api.interceptors.response.use(
  r => r,
  err => {
    if (err?.response?.status === 401 && !redirectingToLogin) {
      redirectingToLogin = true
      window.dispatchEvent(new CustomEvent('auth:unauthorized'))
      setTimeout(() => { redirectingToLogin = false }, 500)
    }
    return Promise.reject(err)
  },
)

export default api
