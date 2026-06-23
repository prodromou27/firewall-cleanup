import animate from 'tailwindcss-animate'

/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ['class'],
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // Signature brand — blue, used for primary actions & accents
        brand: {
          50: '#eff6ff',
          100: '#dbeafe',
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          800: '#1e40af',
          900: '#1e3a8a',
          950: '#172554',
        },
        // Ink — slate scale for text & dark surfaces (sidebar)
        ink: {
          50: '#f8fafc',
          100: '#f1f5f9',
          200: '#e2e8f0',
          300: '#cbd5e1',
          400: '#94a3b8',
          500: '#64748b',
          600: '#475569',
          700: '#334155',
          800: '#1e293b',
          900: '#0f172a',
          950: '#020617',
        },
        // Success — green, for healthy / pass / positive states & data viz
        success: {
          400: '#34d399',
          500: '#10b981',
          600: '#059669',
        },
        severity: {
          critical: {
            DEFAULT: '#dc2626',
            bg: '#dc2626',
            fg: '#ffffff',
            border: '#b91c1c',
            soft: '#fef2f2',
            softFg: '#991b1b',
            softBorder: '#fecaca',
          },
          high: {
            DEFAULT: '#ef4444',
            bg: '#fef2f2',
            fg: '#991b1b',
            border: '#fecaca',
          },
          medium: {
            DEFAULT: '#d97706',
            bg: '#fffbeb',
            fg: '#92400e',
            border: '#fde68a',
          },
          low: {
            DEFAULT: '#0284c7',
            bg: '#f0f9ff',
            fg: '#075985',
            border: '#bae6fd',
          },
          info: {
            DEFAULT: '#64748b',
            bg: '#f1f5f9',
            fg: '#475569',
            border: '#e2e8f0',
          },
        },
        sidebar: {
          DEFAULT: '#0f172a',
          elevated: '#1e293b',
          foreground: '#f8fafc',
          muted: '#94a3b8',
          subtle: '#64748b',
          faint: '#475569',
          active: 'rgba(255, 255, 255, 0.10)',
          hover: 'rgba(255, 255, 255, 0.05)',
          border: 'rgba(255, 255, 255, 0.08)',
        },
        canvas: '#f4f5f9',

        // ── shadcn/ui semantic tokens (mapped to CSS vars in index.css) ──
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: {
          DEFAULT: 'hsl(var(--primary))',
          foreground: 'hsl(var(--primary-foreground))',
        },
        secondary: {
          DEFAULT: 'hsl(var(--secondary))',
          foreground: 'hsl(var(--secondary-foreground))',
        },
        destructive: {
          DEFAULT: 'hsl(var(--destructive))',
          foreground: 'hsl(var(--destructive-foreground))',
        },
        muted: {
          DEFAULT: 'hsl(var(--muted))',
          foreground: 'hsl(var(--muted-foreground))',
        },
        accent: {
          DEFAULT: 'hsl(var(--accent))',
          foreground: 'hsl(var(--accent-foreground))',
        },
        popover: {
          DEFAULT: 'hsl(var(--popover))',
          foreground: 'hsl(var(--popover-foreground))',
        },
        card: {
          DEFAULT: 'hsl(var(--card))',
          foreground: 'hsl(var(--card-foreground))',
        },
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
      keyframes: {
        'accordion-down': {
          from: { height: '0' },
          to: { height: 'var(--radix-accordion-content-height)' },
        },
        'accordion-up': {
          from: { height: 'var(--radix-accordion-content-height)' },
          to: { height: '0' },
        },
      },
      animation: {
        'accordion-down': 'accordion-down 0.2s ease-out',
        'accordion-up': 'accordion-up 0.2s ease-out',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
        display: ['"Space Grotesk"', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      boxShadow: {
        card: '0 1px 2px 0 rgba(15,23,42,0.04), 0 1px 3px 0 rgba(15,23,42,0.06)',
        'card-hover': '0 4px 12px -2px rgba(15,23,42,0.10), 0 2px 6px -2px rgba(15,23,42,0.06)',
        soft: '0 2px 8px -2px rgba(15,23,42,0.08)',
      },
      backgroundImage: {
        'brand-gradient': 'linear-gradient(135deg, #2563eb 0%, #3b82f6 100%)',
        'header-fade': 'linear-gradient(180deg, #ffffff 0%, #fbfbfd 100%)',
      },
    },
  },
  plugins: [animate],
}
