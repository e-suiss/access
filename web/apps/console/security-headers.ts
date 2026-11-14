// TN-131, §14.5: the same headers the BFF sets (crates/http/src/console/domain.rs)
export const contentSecurityPolicy = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self'",
  "img-src 'self'",
  "connect-src 'self'",
  "font-src 'self'",
  "manifest-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "require-trusted-types-for 'script'",
  "trusted-types 'none'",
].join("; ");

export const securityHeaders: Record<string, string> = {
  "Content-Security-Policy": contentSecurityPolicy,
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy":
    "publickey-credentials-get=(self), publickey-credentials-create=(self), camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()",
  "X-Frame-Options": "DENY",
};
