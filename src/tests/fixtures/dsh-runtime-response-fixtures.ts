export interface DshRuntimeResponseFixture {
  name: string;
  url: string;
  contentType: string;
  body: string;
  requestHeaders?: Record<string, string>;
  expectedResponseReasons: string[];
}

/** Bounded synthetic corpus for response-policy regression testing. */
export const dshRuntimeResponseFixtures: DshRuntimeResponseFixture[] = [
  {
    name: 'ordinary JSON response',
    url: 'https://api.example.com/data',
    contentType: 'application/json',
    body: '{"ok":true,"items":[]}',
    expectedResponseReasons: [],
  },
  {
    name: 'executable markup',
    url: 'https://example.com/page',
    contentType: 'text/html',
    body: '<script>alert(document.cookie)</script>',
    expectedResponseReasons: ['RESPONSE_XSS_ECHO'],
  },
  {
    name: 'obfuscated script staging',
    url: 'https://example.com/app.js',
    contentType: 'application/javascript',
    body: 'eval(atob("Y29uc29sZS5sb2coMSk="))',
    expectedResponseReasons: ['RESPONSE_MALICIOUS_SCRIPT'],
  },
  {
    name: 'binary content-type carrying HTML',
    url: 'https://cdn.example.com/avatar.png',
    contentType: 'image/png',
    body: '<html><script>alert(1)</script></html>',
    expectedResponseReasons: ['RESPONSE_XSS_ECHO', 'RESPONSE_CONTENT_TYPE_MISMATCH'],
  },
  {
    name: 'server stack disclosure',
    url: 'https://api.example.com/fail',
    contentType: 'text/plain',
    body: 'Traceback (most recent call last): Exception: database unavailable',
    expectedResponseReasons: ['RESPONSE_ERROR_DISCLOSURE'],
  },
  {
    name: 'local file disclosure markers',
    url: 'https://example.com/download',
    contentType: 'text/plain',
    body: 'root:x:0:0:root:/root:/bin/bash',
    expectedResponseReasons: ['RESPONSE_PATH_TRAVERSAL'],
  },
  {
    name: 'request credential echoed by response',
    url: 'https://api.example.com/debug',
    contentType: 'application/json',
    body: '{"authorization":"Bearer fixture-secret-token"}',
    requestHeaders: { authorization: 'Bearer fixture-secret-token' },
    expectedResponseReasons: ['RESPONSE_CREDENTIAL_ECHO'],
  },
];
