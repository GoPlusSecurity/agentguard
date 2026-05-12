import { registerOpenClawPlugin } from '@goplus/agentguard';

export default function setup(api) {
  registerOpenClawPlugin(api, {
    level: 'balanced',
    skipAutoScan: false,
  });
}
