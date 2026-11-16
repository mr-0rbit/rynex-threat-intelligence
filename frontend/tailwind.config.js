/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // High-fidelity dark palette with rich obsidian undertones and deep specular depth
        ink: {
          950: "#06080d",
          900: "#0b0e17",
          850: "#101420",
          800: "#151b2b",
          700: "#1c2438",
          600: "#27334d",
          500: "#41506b",
          400: "#64748b",
          300: "#94a3b8",
          200: "#cbd5e1",
          100: "#f1f5f9",
          50: "#ffffff",
        },
        accent: {
          DEFAULT: "#00D4FF",
          dim: "#00A8CC",
          glow: "rgba(0, 212, 255, 0.35)",
          light: "#67e8f9",
        },
        cyber: {
          cyan: "#00D4FF",
          rose: "#f43f5e",
          amber: "#f59e0b",
          emerald: "#10b981",
          purple: "#a855f7",
          blue: "#3b82f6",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      fontSize: {
        "2xs": ["0.6875rem", "1rem"],
      },
      boxShadow: {
        "glow-sm": "0 0 12px rgba(0, 212, 255, 0.2)",
        "glow-md": "0 0 24px rgba(0, 212, 255, 0.3)",
        "glow-lg": "0 0 40px rgba(0, 212, 255, 0.4)",
        "glow-rose": "0 0 20px rgba(244, 63, 94, 0.25)",
        "glow-amber": "0 0 20px rgba(245, 158, 11, 0.25)",
        "glow-emerald": "0 0 20px rgba(16, 185, 129, 0.25)",
        "glass": "0 8px 32px 0 rgba(0, 0, 0, 0.37)",
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "shimmer": "shimmer 2.5s infinite linear",
      },
      keyframes: {
        shimmer: {
          "0%": { transform: "translateX(-100%)" },
          "100%": { transform: "translateX(100%)" },
        },
      },
    },
  },
  plugins: [],
};
