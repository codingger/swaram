/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["-apple-system", "BlinkMacSystemFont", '"SF Pro Text"', '"SF Pro Display"', "Inter", '"Helvetica Neue"', "Helvetica", "Arial", "sans-serif"],
        mono: ['"SF Mono"', "ui-monospace", "Menlo", "Consolas", "monospace"],
      },
      colors: {
        ink: "#1d1d1f",
        muted: "#6e6e73",
        faint: "#86868b",
        line: "#d2d2d7",
        canvas: "#f5f5f7",
        accent: { DEFAULT: "#0071e3", hover: "#0077ed" },
      },
      boxShadow: {
        card: "0 1px 2px rgba(0,0,0,0.04), 0 4px 16px rgba(0,0,0,0.04)",
        pop: "0 12px 40px rgba(0,0,0,0.12), 0 2px 8px rgba(0,0,0,0.06)",
      },
    },
  },
  plugins: [],
};
