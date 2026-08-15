import type { DshPluginScanReport } from '../dsh/types.js';

const CAPABILITY_LABELS: Record<keyof DshPluginScanReport['capabilityProfile'], string> = {
  fileRead: 'File read',
  fileWrite: 'File write',
  networkAccess: 'Network access',
  shellExec: 'Shell execution',
  envAccess: 'Environment access',
  providerAccess: 'Provider/model access',
  uiInjection: 'UI injection',
  sessionAccess: 'Session access',
  storageAccess: 'Storage access',
  toolRegistryMutation: 'Tool registry mutation',
  runtimeMutation: 'Runtime mutation',
};

const RECOMMENDATIONS: Record<DshPluginScanReport['installRecommendation'], string> = {
  'safe-to-try': 'Safe to try based on the current static scan.',
  'test-in-isolated-profile': 'Test in an isolated DSH profile before regular use.',
  'sandbox-only': 'Install only in a container or sandbox.',
  'avoid-on-primary-machine': 'Avoid installing on a primary workstation.',
  'expert-review-required': 'High risk: install only after expert source review.',
};

function markdownEscape(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function htmlEscape(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Render a portable Markdown DSH scan report. */
export function renderDshMarkdown(report: DshPluginScanReport): string {
  const scannerLabel = report.scanner
    ? `${report.scanner.name} ${report.scanner.version} (${report.scanner.phase})`
    : 'Unavailable in legacy schema-v1 report';
  const rulesBaseline = report.scanner?.rulesBaseline ?? 'Unavailable in legacy schema-v1 report';
  const runtimeSurfaceRisk = report.runtimeSurfaceRiskLevel ?? report.riskLevel;
  const runtimeSurfaceRecommendation = report.runtimeSurfaceRecommendation ?? report.installRecommendation;
  const capabilities = Object.entries(report.capabilityProfile)
    .map(([key, enabled]) => `| ${CAPABILITY_LABELS[key as keyof typeof CAPABILITY_LABELS]} | ${enabled ? 'Yes' : 'No'} |`)
    .join('\n');
  const findings = report.findings.length > 0
    ? report.findings.map(finding => {
      const count = finding.occurrenceCount ?? 1;
      const location = `${finding.line ? `${finding.file}:${finding.line}` : finding.file}${count > 1 ? ` (+${count - 1} more)` : ''}`;
      const rule = `${finding.ruleId}${count > 1 ? ` × ${count}` : ''}`;
      return `| ${finding.severity.toUpperCase()} | ${markdownEscape(rule)} | ${markdownEscape(location)} | ${finding.sourceCategory ?? 'unknown'} | ${finding.runtimeRelevance ?? 'unknown'} | ${finding.likelyGenerated ? 'Yes' : 'No'} | ${markdownEscape(finding.message)} |`;
    }).join('\n')
    : '| — | — | — | — | — | — | No findings |';
  const signals = report.detection.signals.length > 0
    ? report.detection.signals.map(signal => `- ${signal}`).join('\n')
    : '- No DSH-specific signals found';

  return `# AgentGuard for DSH — ${report.identity.name}

**Full repository risk:** ${report.riskLevel.toUpperCase()}

**Runtime-surface risk:** ${runtimeSurfaceRisk.toUpperCase()}

**Review priority:** ${(report.reviewPriority ?? 'elevated').toUpperCase()}

**Scanner:** ${scannerLabel}

**Rules baseline:** ${rulesBaseline}

**DSH project:** ${report.detection.isDshPlugin ? 'Yes' : 'No'} (${report.detection.confidence} confidence)

**Plugin kind:** ${report.identity.pluginKind}

**Conservative recommendation:** ${RECOMMENDATIONS[report.installRecommendation]}

**Runtime-surface recommendation:** ${RECOMMENDATIONS[runtimeSurfaceRecommendation]}

${report.summary}

## DSH identification

${signals}

## Permission profile

| Capability | Detected |
|---|---|
${capabilities}

## Impact layers

${report.impactLayers.length > 0 ? report.impactLayers.map(layer => `- ${layer}`).join('\n') : '- None inferred'}

## Findings

| Severity | Rule | Location | Source | Runtime relevance | Generated | Explanation |
|---|---|---|---|---|---|---|
${findings}

## Project metadata

- Description: ${report.project.description ?? 'Not provided'}
- Repository: ${report.project.repositoryUrl ?? 'Local directory'}
- Last commit: ${report.source.lastCommitAt ?? 'Unknown'}
- README install instructions: ${report.project.hasReadmeInstallInstructions ? 'Found' : 'Not found'}
- Cordis files: ${report.project.manifest.cordisFiles.join(', ') || 'None'}
- Artifact hash: ${report.identity.artifactHash ?? 'Unknown'}
- Scanned at: ${report.scannedAt}
- Files scanned: ${report.filesScanned}

> Static analysis can miss runtime-loaded behavior and cannot prove that a plugin is safe.
`;
}

/** Render a self-contained shareable HTML DSH scan report. */
export function renderDshHtml(report: DshPluginScanReport): string {
  const scannerLabel = report.scanner
    ? `${report.scanner.name} ${report.scanner.version} · ${report.scanner.phase}`
    : 'Scanner version unavailable in legacy schema-v1 report';
  const rulesBaseline = report.scanner?.rulesBaseline ?? 'unavailable';
  const risk = htmlEscape(report.riskLevel);
  const runtimeSurfaceRisk = report.runtimeSurfaceRiskLevel ?? report.riskLevel;
  const runtimeSurfaceRecommendation = report.runtimeSurfaceRecommendation ?? report.installRecommendation;
  const runtimeRisk = htmlEscape(runtimeSurfaceRisk);
  const capabilities = Object.entries(report.capabilityProfile).map(([key, enabled]) => `
    <div class="capability ${enabled ? 'enabled' : ''}">
      <span>${htmlEscape(CAPABILITY_LABELS[key as keyof typeof CAPABILITY_LABELS])}</span>
      <strong>${enabled ? 'Detected' : 'Not detected'}</strong>
    </div>`).join('');
  const findings = report.findings.length > 0
    ? report.findings.map(finding => {
      const count = finding.occurrenceCount ?? 1;
      return `
      <article class="finding">
        <span class="severity ${htmlEscape(finding.severity)}">${htmlEscape(finding.severity)}</span>
        <div><strong>${htmlEscape(finding.ruleId)}${count > 1 ? ` × ${count}` : ''}</strong><p>${htmlEscape(finding.message)}</p><p class="finding-context">${htmlEscape(finding.sourceCategory ?? 'unknown')} · runtime ${htmlEscape(finding.runtimeRelevance ?? 'unknown')}${finding.likelyGenerated ? ' · likely generated' : ''}</p><code>${htmlEscape(finding.file)}${finding.line ? `:${finding.line}` : ''}${count > 1 ? ` (+${count - 1} more)` : ''}</code>${finding.snippet ? `<pre>${htmlEscape(finding.snippet)}</pre>` : ''}</div>
      </article>`;
    }).join('')
    : '<p class="empty">No findings from the current static rules.</p>';
  const signals = report.detection.signals.map(signal => `<li>${htmlEscape(signal)}</li>`).join('');
  const impacts = report.impactLayers.map(layer => `<span class="chip">${htmlEscape(layer)}</span>`).join('');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AgentGuard for DSH — ${htmlEscape(report.identity.name)}</title>
  <style>
    :root { color-scheme: dark; --bg:#09111f; --panel:#111c2f; --muted:#95a5bd; --line:#263550; --text:#f7f9fc; --low:#42d392; --medium:#f3c969; --high:#ff8a5b; --critical:#ff5573; }
    * { box-sizing:border-box } body { margin:0; background:radial-gradient(circle at 80% 0,#172c4b 0,transparent 36%),var(--bg); color:var(--text); font:15px/1.55 Inter,ui-sans-serif,system-ui,sans-serif; }
    main { width:min(1080px,calc(100% - 32px)); margin:48px auto 72px; } .eyebrow { color:#74a7ff; font-weight:750; letter-spacing:.12em; text-transform:uppercase; }
    h1 { margin:.3rem 0 .5rem; font-size:clamp(2rem,5vw,4rem); letter-spacing:-.045em; } h2 { margin:0 0 18px; font-size:1.15rem; } .summary { max-width:780px; color:#c5d0df; font-size:1.05rem; }
    .hero { padding:34px; border:1px solid var(--line); border-radius:24px; background:rgba(17,28,47,.86); box-shadow:0 24px 80px rgba(0,0,0,.24); }
    .risk { display:inline-flex; margin:18px 8px 0 0; padding:7px 12px; border-radius:999px; font-weight:800; text-transform:uppercase; background:color-mix(in srgb,var(--${risk}) 18%,transparent); color:var(--${risk}); border:1px solid color-mix(in srgb,var(--${risk}) 42%,transparent); }
    .runtime-risk { background:color-mix(in srgb,var(--${runtimeRisk}) 18%,transparent); color:var(--${runtimeRisk}); border-color:color-mix(in srgb,var(--${runtimeRisk}) 42%,transparent); }
    .grid { display:grid; grid-template-columns:1fr 1fr; gap:18px; margin-top:18px; } section { padding:24px; border:1px solid var(--line); border-radius:18px; background:rgba(17,28,47,.72); }
    .capabilities { display:grid; grid-template-columns:1fr 1fr; gap:9px; } .capability { display:flex; justify-content:space-between; gap:12px; padding:11px 12px; border-radius:10px; background:#0b1526; color:var(--muted); }
    .capability strong { color:#6f819c; font-size:.78rem; } .capability.enabled { color:var(--text); border-left:3px solid var(--high); } .capability.enabled strong { color:var(--high); }
    .chip { display:inline-flex; padding:6px 10px; margin:0 6px 7px 0; border-radius:8px; background:#1a2a43; color:#b9cef0; }
    .finding { display:grid; grid-template-columns:82px 1fr; gap:14px; padding:16px 0; border-top:1px solid var(--line); } .finding:first-of-type { border-top:0; padding-top:0; }
    .finding p { margin:3px 0 6px; color:#c3cede; } code,pre { color:#a8bce0; background:#0a1322; border-radius:6px; } code { padding:3px 6px; } pre { padding:10px; overflow:auto; white-space:pre-wrap; }
    .finding .finding-context { color:var(--muted); font-size:.82rem; }
    .severity { align-self:start; text-align:center; border-radius:6px; padding:4px 7px; font-size:.72rem; font-weight:850; text-transform:uppercase; color:var(--text); background:var(--medium); } .severity.low{background:var(--low)} .severity.high{background:var(--high)} .severity.critical{background:var(--critical)}
    dl { display:grid; grid-template-columns:max-content 1fr; gap:8px 16px; margin:0; } dt { color:var(--muted); } dd { margin:0; overflow-wrap:anywhere; } ul { padding-left:20px; color:#c3cede; }
    .recommendation { border-left:4px solid var(--${risk}); } .recommendation strong { color:var(--${risk}); } footer { margin-top:20px; color:var(--muted); font-size:.85rem; }
    @media (max-width:760px) { .grid { grid-template-columns:1fr } .capabilities { grid-template-columns:1fr } main { margin-top:16px } .hero { padding:24px } }
  </style>
</head>
<body><main>
  <header class="hero"><div class="eyebrow">AgentGuard for DSH</div><h1>${htmlEscape(report.identity.name)}</h1><p class="summary">${htmlEscape(report.summary)}</p><span class="risk">Repository: ${risk}</span><span class="risk runtime-risk">Runtime surface: ${runtimeRisk}</span><p>Review priority: <strong>${htmlEscape(report.reviewPriority ?? 'elevated')}</strong></p><p>${htmlEscape(scannerLabel)} · rules <code>${htmlEscape(rulesBaseline)}</code></p></header>
  <div class="grid">
    <section><h2>Permission profile</h2><div class="capabilities">${capabilities}</div></section>
    <section><h2>DSH identity</h2><dl><dt>Detected</dt><dd>${report.detection.isDshPlugin ? 'Yes' : 'No'} (${htmlEscape(report.detection.confidence)})</dd><dt>Kind</dt><dd>${htmlEscape(report.identity.pluginKind)}</dd><dt>Impact</dt><dd>${impacts || 'None inferred'}</dd></dl><ul>${signals || '<li>No DSH-specific signals</li>'}</ul></section>
  </div>
  <div class="grid">
    <section style="grid-column:1/-1"><h2>Key findings</h2>${findings}</section>
    <section class="recommendation"><h2>Install recommendation</h2><strong>${htmlEscape(RECOMMENDATIONS[report.installRecommendation])}</strong><p>Runtime surface: ${htmlEscape(RECOMMENDATIONS[runtimeSurfaceRecommendation])}</p>${report.harmlessMismatch ? '<p>Looks harmless, but requests elevated capabilities.</p>' : ''}</section>
    <section><h2>Artifact</h2><dl><dt>Repository</dt><dd>${htmlEscape(report.project.repositoryUrl ?? 'Local directory')}</dd><dt>Last commit</dt><dd>${htmlEscape(report.source.lastCommitAt ?? 'Unknown')}</dd><dt>Files scanned</dt><dd>${report.filesScanned}</dd><dt>Scanned</dt><dd>${htmlEscape(report.scannedAt)}</dd><dt>Hash</dt><dd>${htmlEscape(report.identity.artifactHash ?? 'Unknown')}</dd></dl></section>
  </div>
  <footer>Static analysis can miss runtime-loaded behavior and cannot prove that a plugin is safe.</footer>
</main></body></html>`;
}
