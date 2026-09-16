import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { classifyLlmEndpoint, normalizeLlmEndpoint } from '../runtime/llm-endpoints.js';

describe('LLM endpoint classification', () => {
  it('normalizes case, default ports, trailing dots, userinfo, IPv6, and IDNs', () => {
    assert.equal(normalizeLlmEndpoint('HTTPS://API.OPENAI.COM.:443/v1').url, 'https://api.openai.com/v1');
    assert.equal(normalizeLlmEndpoint('https://api.openai.com@relay.invalid/v1').hostname, 'relay.invalid');
    assert.equal(normalizeLlmEndpoint('http://[::1]:11434/v1').hostname, '::1');
    assert.equal(normalizeLlmEndpoint('https://münich.example/v1').hostname, 'xn--mnich-kva.example');
  });

  it('classifies default endpoints with loopback precedence over IP blocking', () => {
    const cases = [
      ['http://127.0.0.1:11434/v1', 'T0'],
      ['http://[::1]:1234/v1', 'T0'],
      ['http://models.local/v1', 'T0'],
      ['http://ollama:11434/v1', 'T0'],
      ['https://api.openai.com/v1', 'T1'],
      ['https://api.anthropic.com/v1/messages', 'T1'],
      ['https://generativelanguage.googleapis.com/v1beta', 'T1'],
      ['https://team.openai.azure.com/openai/deployments/model', 'T2'],
      ['https://bedrock-runtime.us-east-1.amazonaws.com/model', 'T2'],
      ['https://us-central1-aiplatform.googleapis.com/v1', 'T2'],
      ['https://openrouter.ai/api/v1', 'T2'],
      ['https://relay.corp.invalid/v1', 'T3'],
      ['https://api.openai.com.attacker.invalid/v1', 'T3'],
      ['https://api.openai.com:8443/v1', 'T3'],
      ['https://203.0.113.8/v1', 'T4'],
      ['https://[2001:db8::8]/v1', 'T4'],
      ['https://bit.ly/model-api', 'T4'],
      ['https://relay-dangerous.top/v1', 'T4'],
    ] as const;

    for (const [url, tier] of cases) {
      assert.equal(classifyLlmEndpoint(url).tier, tier, url);
    }
  });

  it('promotes configured private endpoints but never overrides blocked domains', () => {
    assert.equal(classifyLlmEndpoint('https://llm.corp.internal/v1', {
      trustedEndpoints: ['https://llm.corp.internal'],
    }).tier, 'T2');

    assert.equal(classifyLlmEndpoint('https://llm.corp.internal/v1', {
      trustedEndpoints: ['https://llm.corp.internal'],
      blockedDomains: ['corp.internal'],
    }).tier, 'T4');
  });

  it('classifies the redirect destination instead of trusting the original URL', () => {
    const result = classifyLlmEndpoint('https://api.openai.com/v1', {
      redirectTarget: 'https://203.0.113.9/collect',
    });
    assert.equal(result.tier, 'T4');
    assert.equal(result.hostname, '203.0.113.9');
    assert.equal(result.redirected, true);
  });
});
