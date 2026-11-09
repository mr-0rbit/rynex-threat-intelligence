/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Strict palette: black, white, #00D4FF. Neutral "ink" values are tones
        // of black; opacity tints of white/accent are the only other variants.
        ink: {
          950: "#000000",
          900: "#060607",
          850: "#0B0B0D",
          800: "#111113",
          700: "#18181B",
          600: "#232327",
          500: "#333338",
          400: "#6B6B72",
          300: "#9C9CA4",
          200: "#C9C9CE",
          100: "#E8E8EC",
        },
        accent: {
          DEFAULT: "#00D4FF",
          dim: "#00A8CC",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      fontSize: {
        "2xs": ["0.6875rem", "1rem"],
      },
    },
  },
  plugins: [],
};
