/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // Signature brand — deep indigo, used for primary actions & accents
        brand: {
          50: '#eef2ff',
          100: '#e0e7ff',
          200: '#c7d2fe',
          300: '#a5b4fc',
          400: '#818cf8',
          500: '#6366f1',
          600: '#4f46e5',
          700: '#4338ca',
          800: '#3730a3',
          900: '#312e81',
          950: '#1e1b4b',
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
        // Accent — cyan, for highlights / data viz
        accent: {
          400: '#22d3ee',
          500: '#06b6d4',
          600: '#0891b2',
        },
        canvas: '#f4f5f9',
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
        'brand-gradient': 'linear-gradient(135deg, #4f46e5 0%, #6366f1 100%)',
        'header-fade': 'linear-gradient(180deg, #ffffff 0%, #fbfbfd 100%)',
      },
    },
  },
  plugins: [],
}
