export {
  MAX_GITHUB_ACQUISITION_BYTES,
  MAX_GITHUB_OBJECTS,
  assertGithubAcquisitionByteBudget as assertDshAcquisitionByteBudget,
  normalizeGithubRepositoryUrl,
  removeScanTempRoot as removeDshTempRoot,
  resolveAdvertisedGithubRef,
  resolveScanSource as resolveDshSource,
  runWithScanCleanup as runWithDshCleanup,
  startScanAcquisitionMonitor as startDshAcquisitionMonitor,
} from '../scanner/source.js';

export type {
  ResolvedScanSource as ResolvedDshSource,
  ResolveScanSourceOptions as ResolveDshSourceOptions,
  ScanCleanupResult as DshCleanupResult,
} from '../scanner/source.js';
