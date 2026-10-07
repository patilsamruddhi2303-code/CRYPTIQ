/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        base: '#0a0d14',
        panel: '#111622',
        card: '#161d2d',
        cardHover: '#1c2538',
        borderSubtle: '#222d42',
        borderAccent: '#334466'
      }
    },
  },
  plugins: [],
}
