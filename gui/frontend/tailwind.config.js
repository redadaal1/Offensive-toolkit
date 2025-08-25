/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{ts,tsx}',
  ],
  theme: {
    extend: {},
  },
  plugins: [require('daisyui')],
  daisyui: {
    themes: [
      {
        hacker: {
          'primary': '#00ff9c',
          'secondary': '#5eead4',
          'accent': '#7dd3fc',
          'neutral': '#0b1426',
          'base-100': '#05080f',
          'info': '#93c5fd',
          'success': '#34d399',
          'warning': '#facc15',
          'error': '#f87171',
        }
      }
    ],
    darkTheme: 'hacker'
  }
}

