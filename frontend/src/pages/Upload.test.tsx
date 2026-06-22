import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { Upload, uploadDetailMessage, uploadFileExtension, validateUploadFile } from './Upload'

const navigate = vi.fn()

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return {
    ...actual,
    useNavigate: () => navigate,
  }
})

vi.mock('../api/client', () => ({
  getCustomers: vi.fn(() => Promise.resolve([
    { id: 'cust-1', name: 'ACME', total_policies: 2, total_findings: 7, contact_name: 'Alex' },
  ])),
  getDevices: vi.fn(() => Promise.resolve([
    { id: 'dev-1', customer_id: 'cust-1', name: 'FGT-HQ-01', vendor: 'FortiGate', host: '10.0.0.1' },
  ])),
  getPolicy: vi.fn(() => Promise.resolve({
    id: 'policy-1',
    customer_id: 'cust-1',
    analysis_status: 'completed',
  })),
  uploadPolicy: vi.fn((_fd: FormData, onProgress?: (event: { loaded: number; total?: number }) => void) => {
    onProgress?.({ loaded: 50, total: 100 })
    onProgress?.({ loaded: 100, total: 100 })
    return Promise.resolve({
      policy_id: 'policy-1',
      customer_id: 'cust-1',
      rules_parsed: 3,
      objects_parsed: 1,
      warnings: ['Unsupported field ignored'],
      import_quality: {
        rule_count: 3,
        object_count: 1,
        quality_score: 65,
        completeness_score: 40,
        incomplete_import: true,
        has_hit_counts: false,
        has_last_hit: false,
        has_comments: true,
        rules_with_hit_count: 0,
        rules_with_last_hit: 0,
        rules_with_comments: 2,
        warning_count: 1,
        data_gaps: ['No hit count data - zero-hit detection will be limited.'],
        confidence_note: 'Analysis confidence is MODERATE.',
      },
    })
  }),
}))

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

function renderUpload() {
  return render(
    <MemoryRouter>
      <Upload />
    </MemoryRouter>,
  )
}

describe('upload workflow helpers', () => {
  it('extracts lower-case extensions and validates vendor-specific file types', () => {
    expect(uploadFileExtension('CONFIG.CONF')).toBe('.conf')
    expect(validateUploadFile({ name: 'policy.txt', size: 100 } as File, 'PaloAlto')).toContain('Unsupported file type .txt')
    expect(validateUploadFile({ name: 'policy.xml', size: 0 } as File, 'PaloAlto')).toContain('selected file is empty')
    expect(validateUploadFile({ name: 'policy.xml', size: 100 } as File, 'PaloAlto')).toBeNull()
  })

  it('normalizes API error detail payloads', () => {
    expect(uploadDetailMessage('Bad file')).toBe('Bad file')
    expect(uploadDetailMessage({ message: 'No firewall rules or objects were parsed.' })).toBe('No firewall rules or objects were parsed.')
    expect(uploadDetailMessage(null)).toBe('Upload failed.')
  })
})

describe('Upload page', () => {
  it('shows a clear error before uploading an unsupported vendor file', async () => {
    const { container } = renderUpload()
    const user = userEvent.setup()

    await screen.findByText('ACME')
    await user.selectOptions(screen.getByLabelText(/Customer/i), 'cust-1')
    await user.selectOptions(screen.getByLabelText(/Vendor/i), 'PaloAlto')
    await user.type(screen.getByLabelText(/Firewall name/i), 'PA-EDGE')

    const input = container.querySelector('input[type="file"]') as HTMLInputElement
    fireEvent.change(input, { target: { files: [new File(['config'], 'policy.txt', { type: 'text/plain' })] } })
    await user.click(screen.getByRole('button', { name: /Upload and analyze/i }))

    expect((await screen.findAllByText(/Unsupported file type .txt for PaloAlto/i)).length).toBeGreaterThan(0)
  })

  it('shows import quality, warnings, and findings navigation after successful analysis', async () => {
    const { container } = renderUpload()
    const user = userEvent.setup()

    await screen.findByText('ACME')
    await user.selectOptions(screen.getByLabelText(/Customer/i), 'cust-1')
    await user.type(screen.getByLabelText(/Firewall name/i), 'FGT-HQ-01')
    const input = container.querySelector('input[type="file"]') as HTMLInputElement
    fireEvent.change(input, { target: { files: [new File(['config firewall policy'], 'policy.conf', { type: 'text/plain' })] } })
    await waitFor(() => expect(screen.getByRole('button', { name: /Upload and analyze/i })).not.toBeDisabled())
    await user.click(screen.getByRole('button', { name: /Upload and analyze/i }))

    expect(await screen.findByText(/Parsed 3 rules and 1 objects/i)).toBeInTheDocument()
    expect(screen.getByText(/Import Quality/i)).toBeInTheDocument()
    expect(screen.getByText(/Unsupported field ignored/i)).toBeInTheDocument()

    await waitFor(() => expect(screen.getByRole('button', { name: /View Findings/i })).not.toBeDisabled())
    await user.click(screen.getByRole('button', { name: /View Findings/i }))
    expect(navigate).toHaveBeenCalledWith('/findings?customer_id=cust-1&policy_id=policy-1')
  })
})
