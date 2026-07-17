/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#08131f",
        panel: "#0d1d2c",
        teal: "#12B5A5",
        blue: "#0E5FD8",
      },
      boxShadow: {
        glow: "0 0 60px rgba(18,181,165,0.18)",
      },
    },
  },
  plugins: [],
};
