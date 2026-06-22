type ApiErrorLike = {
  response?: { status?: number; data?: { detail?: unknown; message?: unknown } }
  message?: string
}

function detailToText(detail: unknown): string | null {
  if (!detail) return null
  if (typeof detail === 'string') return detail
  if (typeof detail === 'object') {
    const value = detail as { message?: unknown; detail?: unknown }
    if (typeof value.message === 'string') return value.message
    if (typeof value.detail === 'string') return value.detail
  }
  return null
}

export function friendlyErrorMessage(error: unknown, fallback = 'We could not complete the request. Please try again.'): string {
  const e = error as ApiErrorLike
  const status = e?.response?.status
  const serverText = detailToText(e?.response?.data?.detail) || detailToText(e?.response?.data?.message)

  if (status === 400 || status === 422) return serverText || 'The request could not be processed. Please review the input and try again.'
  if (status === 401) return 'Your session has expired. Please sign in again.'
  if (status === 403) return 'You do not have permission to access this customer data.'
  if (status === 404) return 'The requested item could not be found. It may have been deleted or moved.'
  if (status === 409) return serverText || 'This action conflicts with the current state. Refresh and try again.'
  if (status && status >= 500) return 'The server could not complete the request. Please try again later.'

  if (e?.message === 'Network Error') return 'PolicyInsight cannot reach the backend. Check connectivity and try again.'
  if (e?.message?.includes('timeout')) return 'The request took too long. Please try again.'
  if (e?.message && !/^Request failed/i.test(e.message) && !/^HTTP\b/i.test(e.message)) return e.message
  return serverText || fallback
}

export async function fetchFailureMessage(response: Response, fallback = 'Download failed. Please try again.'): Promise<string> {
  try {
    const body = await response.clone().json()
    const detail = detailToText(body?.detail) || detailToText(body?.message)
    if (detail) return detail
  } catch {
    // Non-JSON error response.
  }
  if (response.status === 401) return 'Your session has expired. Please sign in again.'
  if (response.status === 403) return 'You do not have permission to download this file.'
  if (response.status === 404) return 'The requested file is no longer available.'
  if (response.status >= 500) return 'The server could not prepare the file. Please try again later.'
  return fallback
}
