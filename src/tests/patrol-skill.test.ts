import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const skillPath = resolve(__dirname, '..', '..', 'skills', 'agentguard', 'SKILL.md');

describe('AgentGuard patrol skill scheduling contract', () => {
  it('uses the existing eight-check collector for Windows and Unix schedules', () => {
    const skill = readFileSync(skillPath, 'utf8');
    const scheduledSection = skill.slice(skill.indexOf('#### Path B'), skill.indexOf('### patrol status'));

    assert.match(scheduledSection, /call "<AGENTGUARD_CLI>" checkup --json/);
    assert.match(scheduledSection, /'<NODE_EXE>' '<AGENTGUARD_CLI>' checkup --json/);
    assert.doesNotMatch(scheduledSection, /AGENTGUARD_AUTO_SCAN|scripts[\\/]auto-scan\.js/);
  });

  it('recognizes only completed eight-check events as patrol status', () => {
    const skill = readFileSync(skillPath, 'utf8');
    const statusSection = skill.slice(skill.indexOf('### patrol status'), skill.indexOf('\n---', skill.indexOf('### patrol status')));

    assert.match(statusSection, /event: "checkup"/);
    assert.match(statusSection, /`checks` value is `8`/);
    assert.match(statusSection, /Never report `event: "auto_scan"` as a completed patrol/);
  });
});
