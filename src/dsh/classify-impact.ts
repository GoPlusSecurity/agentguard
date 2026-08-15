import type { DshCapabilityProfile, DshDetection, DshImpactLayer, DshPluginKind } from './types.js';

/** Map the inferred plugin role and capabilities to user-facing DSH impact layers. */
export function classifyImpactLayers(
  kind: DshPluginKind,
  capabilities: DshCapabilityProfile,
  detection: DshDetection,
): DshImpactLayer[] {
  const layers = new Set<DshImpactLayer>();
  if (kind === 'ui' || kind === 'theme' || capabilities.uiInjection) layers.add('ui');
  if (kind === 'tool' || capabilities.toolRegistryMutation) layers.add('tool-registry');
  if (kind === 'workflow') layers.add('workflow');
  if (kind === 'provider' || capabilities.providerAccess) layers.add('models-providers');
  if (capabilities.sessionAccess || capabilities.storageAccess) layers.add('session-storage');
  if (kind === 'runtime' || kind === 'bundle' || kind === 'profile' || capabilities.runtimeMutation) {
    layers.add('runtime-core');
  }

  const rowText = detection.cordis.rows.map(row => `${row.id ?? ''} ${row.name ?? ''}`).join('\n');
  if (/tool/i.test(rowText)) layers.add('tool-registry');
  if (/(?:llm|model|provider|credentials)/i.test(rowText)) layers.add('models-providers');
  if (/(?:session|storage|persistence|settings)/i.test(rowText)) layers.add('session-storage');
  if (/(?:web|client|ui|theme)/i.test(rowText)) layers.add('ui');
  return [...layers];
}
