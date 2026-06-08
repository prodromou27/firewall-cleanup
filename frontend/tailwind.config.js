/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#eff6ff',
          100: '#dbeafe',
          600: '#1e40af',
          700: '#1d4ed8',
          900: '#1e3a5f',
        },
      },
    },
  },
  plugins: [],
}
