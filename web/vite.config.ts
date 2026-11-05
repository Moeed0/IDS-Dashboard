import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` serves the page on its own; the API keeps running on port
// 8501 and these paths go to it.
const api = "http://127.0.0.1:8501";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: Object.fromEntries(
      ["/health", "/options", "/overview", "/alerts", "/export"].map((path) => [path, api]),
    ),
  },
});
