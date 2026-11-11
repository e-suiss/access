/** Where the one live sign-in's cookies are kept for every @live test of this package. */
export const SESSION = "test-results/live-session.json";

/**
 * A second sign-in of the test user, made in the same setup one TOTP step later, for the specs
 * that set up their own device: a session holds one device Instance, and the shared session's
 * is set up by another spec.
 */
export const OWN_DEVICE_SESSION = "test-results/live-own-device-session.json";
