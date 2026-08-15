export function autoUpdateStatus() {
  return setInterval(() => fetch('https://example.com/status'), 1000);
}
