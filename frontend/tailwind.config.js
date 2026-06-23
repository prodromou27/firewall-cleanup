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
          50: '#ecfeff',
          100: '#cffafe',
          200: '#a5f3fc',
          300: '#67e8f9',
          400: '#22d3ee',
          500: '#06b6d4',
          600: '#0891b2',
          700: '#0e7490',
          800: '#155e75',
          900: '#164e63',
          950: '#083344',
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
          DEFAULT: '#101719',
          elevated: '#172123',
          foreground: '#f8fafc',
          muted: '#a5b4b6',
          subtle: '#6f7f82',
          faint: '#425052',
          active: 'rgba(255, 255, 255, 0.10)',
          hover: 'rgba(255, 255, 255, 0.05)',
          border: 'rgba(255, 255, 255, 0.08)',
        },
        canvas: '#f5f7f6',

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
        card: '0 1px 0 0 rgba(16,23,25,0.04), 0 10px 30px -28px rgba(16,23,25,0.45)',
        'card-hover': '0 16px 36px -30px rgba(8,51,68,0.55), 0 0 0 1px rgba(8,145,178,0.10)',
        soft: '0 8px 22px -18px rgba(16,23,25,0.35)',
        console: 'inset -1px 0 0 rgba(255,255,255,0.06), 1px 0 0 rgba(8,145,178,0.28)',
      },
      backgroundImage: {
        'brand-gradient': 'linear-gradient(135deg, #0e7490 0%, #06b6d4 52%, #14b8a6 100%)',
        'header-fade': 'linear-gradient(180deg, rgba(255,255,255,0.96) 0%, rgba(248,250,250,0.92) 100%)',
        'console-grid': 'linear-gradient(rgba(8,145,178,0.055) 1px, transparent 1px), linear-gradient(90deg, rgba(8,145,178,0.055) 1px, transparent 1px)',
        'sidebar-field': 'radial-gradient(circle at 35% 0%, rgba(6,182,212,0.20), transparent 32%), linear-gradient(180deg, #101719 0%, #0b1012 100%)',
      },
    },
  },
  plugins: [animate],
}
