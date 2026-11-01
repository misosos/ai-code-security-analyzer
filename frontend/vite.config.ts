import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

declare const process: { env: Record<string, string | undefined> };

const apiProxyTarget = process.env.AI_CSA_API_PROXY_TARGET ?? 'http://127.0.0.1:8765';
let parsedApiProxyTarget: URL;
try {
  parsedApiProxyTarget = new URL(apiProxyTarget);
} catch {
  throw new Error('api_proxy_target_must_be_loopback');
}
if (
  parsedApiProxyTarget.protocol !== 'http:' || parsedApiProxyTarget.hostname !== '127.0.0.1' ||
  !parsedApiProxyTarget.port || parsedApiProxyTarget.pathname !== '/' || parsedApiProxyTarget.username ||
  parsedApiProxyTarget.password || parsedApiProxyTarget.search || parsedApiProxyTarget.hash
) {
  throw new Error('api_proxy_target_must_be_loopback');
}

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    proxy: {
      '/api': { target: parsedApiProxyTarget.origin, changeOrigin: true },
    },
  },
  test: { include: ['tests/**/*.test.ts', 'tests/**/*.test.tsx'], environment: 'jsdom', setupFiles: './tests/setup.ts', restoreMocks: true },
});
