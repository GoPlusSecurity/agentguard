export {
  MAX_GITHUB_ACQUISITION_BYTES,
  MAX_GITHUB_OBJECTS,
  assertGithubAcquisitionByteBudget as assertDshAcquisitionByteBudget,
  normalizeGithubRepositoryUrl,
  resolveAdvertisedGithubRef,
  resolveScanSource as resolveDshSource,
} from '../scanner/source.js';

export type {
  ResolvedScanSource as ResolvedDshSource,
  ResolveScanSourceOptions as ResolveDshSourceOptions,
} from '../scanner/source.js';
