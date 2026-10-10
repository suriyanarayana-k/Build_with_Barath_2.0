/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
    "./bola-frontend/src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          base: '#07090e',
          panel: '#0d111a',
          panelSub: '#111723',
          cardHover: '#161e2e',
          border: '#1e2638',
          borderBright: '#2a364f',
          crimson: '#f43f5e',
          crimsonMuted: '#4c111a',
          orange: '#f59e0b',
          orangeMuted: '#422006',
          emerald: '#10b981',
          cyan: '#06b6d4',
          accent: '#ff2a44',
          textMuted: '#64748b',
          textSub: '#94a3b8',
        },
        brand: {
          dark: '#0A0A0A',
          card: '#171717',
          border: '#262626',
          crimson: '#FF3B5C',
          deepred: '#DC2626',
          orange: '#F97316',
          light: '#F5F5F5',
          muted: '#A3A3A3',
          subtle: '#737373',
        },
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      boxShadow: {
        glowRed: '0 0 20px -2px rgba(244, 63, 94, 0.35)',
        glowOrange: '0 0 20px -2px rgba(245, 158, 11, 0.3)',
        glowEmerald: '0 0 20px -2px rgba(16, 185, 129, 0.35)',
        glowCyan: '0 0 20px -2px rgba(6, 182, 212, 0.3)',
        tactical: 'inset 0 1px 0 0 rgba(255, 255, 255, 0.05), 0 4px 12px rgba(0,0,0,0.6)',
      },
    },
  },
  plugins: [],
}
