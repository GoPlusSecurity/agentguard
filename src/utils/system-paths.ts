import { homedir } from 'node:os';

export type SystemPathOperation = 'read' | 'write' | 'delete' | 'move' | 'chmod' | 'chown';
export type SystemPathDecision = 'block' | 'require_approval';
export type SystemPathSeverity = 'high' | 'critical';

export interface SystemPathClassification {
  path: string;
  operation: SystemPathOperation;
  decision: SystemPathDecision;
  severity: SystemPathSeverity;
  category: 'system_boot' | 'system_config' | 'security_credentials' | 'kernel_device' | 'root';
  description: string;
}

const BOOT_PREFIXES = [
  '/bin',
  '/sbin',
  '/usr',
  '/usr/bin',
  '/usr/sbin',
  '/lib',
  '/lib64',
];

const CRITICAL_CONFIG_EXACT = [
  '/etc/shadow',
  '/etc/sudoers',
];

const HIGH_CONFIG_EXACT = [
  '/etc/passwd',
  '/etc/group',
  '/etc/hosts',
  '/etc/resolv.conf',
];

const MEDIUM_CONFIG_EXACT = [
  '/etc/crontab',
];

const CONFIG_PREFIXES = [
  '/etc',
  '/etc/ssh',
  '/etc/systemd',
];

const SECURITY_HOME_PATHS = [
  '~/.ssh',
  '~/.gnupg',
  '~/.aws',
  '~/.kube',
  '~/.npmrc',
  '~/.netrc',
];

const MUTATING_OPERATIONS = new Set<SystemPathOperation>(['write', 'delete', 'move', 'chmod', 'chown']);

export function classifySystemPathOperation(
  rawPath: string,
  operation: SystemPathOperation
): SystemPathClassification | null {
  const path = normalizeSystemPath(rawPath);
  if (!path) return null;

  if (path === '/') {
    return {
      path,
      operation,
      decision: operation === 'read' ? 'require_approval' : 'block',
      severity: operation === 'read' ? 'high' : 'critical',
      category: 'root',
      description: 'Root filesystem path',
    };
  }

  if (matchesAnyPrefix(path, BOOT_PREFIXES)) {
    if (operation === 'read') return null;
    return {
      path,
      operation,
      decision: 'block',
      severity: 'critical',
      category: 'system_boot',
      description: 'System boot or runtime directory',
    };
  }

  if (CRITICAL_CONFIG_EXACT.includes(path) || path.startsWith('/etc/ssh/ssh_host_')) {
    return {
      path,
      operation,
      decision: operation === 'read' ? 'require_approval' : 'block',
      severity: operation === 'read' ? 'high' : 'critical',
      category: 'system_config',
      description: 'Critical system credential or privilege file',
    };
  }

  if (HIGH_CONFIG_EXACT.includes(path)) {
    return {
      path,
      operation,
      decision: operation === 'read' ? 'require_approval' : 'block',
      severity: operation === 'read' ? 'high' : 'critical',
      category: 'system_config',
      description: 'System configuration file',
    };
  }

  if (MEDIUM_CONFIG_EXACT.includes(path)) {
    return {
      path,
      operation,
      decision: operation === 'read' ? 'require_approval' : 'require_approval',
      severity: 'high',
      category: 'system_config',
      description: 'Sensitive system configuration path',
    };
  }

  if (matchesAnyPrefix(path, CONFIG_PREFIXES)) {
    return {
      path,
      operation,
      decision: operation === 'read' ? 'require_approval' : 'block',
      severity: operation === 'read' ? 'high' : 'critical',
      category: 'system_config',
      description: 'Sensitive system configuration path',
    };
  }

  if (matchesKernelOrDevicePath(path)) {
    if (operation === 'read' && !path.startsWith('/proc/1')) return null;
    return {
      path,
      operation,
      decision: operation === 'read' ? 'require_approval' : 'block',
      severity: operation === 'read' ? 'high' : 'critical',
      category: 'kernel_device',
      description: 'Kernel, process, or device path',
    };
  }

  if (path === '/root' || path.startsWith('/root/')) {
    return {
      path,
      operation,
      decision: operation === 'read' ? 'require_approval' : 'require_approval',
      severity: 'high',
      category: 'security_credentials',
      description: 'Root user home directory',
    };
  }

  if (matchesSecurityHomePath(path)) {
    return {
      path,
      operation,
      decision: operation === 'read' || MUTATING_OPERATIONS.has(operation) ? 'require_approval' : 'require_approval',
      severity: 'high',
      category: 'security_credentials',
      description: 'User credential path',
    };
  }

  return null;
}

export function normalizeSystemPath(rawPath: string): string {
  let path = rawPath.trim();
  if (!path) return '';
  path = path.replace(/^['"]|['"]$/g, '');
  path = path.replace(/[),.;]+$/g, '');
  path = path.replace(/\\/g, '/');
  path = path.replace(/[?*[\]{}]+.*$/g, '');
  if (path.startsWith('~/')) {
    path = `${homedir().replace(/\\/g, '/')}/${path.slice(2)}`;
  }
  path = path.replace(/\/+/g, '/');
  if (path.length > 1) path = path.replace(/\/+$/g, '');
  return path;
}

function matchesAnyPrefix(path: string, prefixes: string[]): boolean {
  return prefixes.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
}

function matchesKernelOrDevicePath(path: string): boolean {
  return path === '/proc/1' ||
    path.startsWith('/proc/1/') ||
    path.startsWith('/sys/') ||
    /^\/dev\/(?:sd[a-z]\d*|vd[a-z]\d*|xvd[a-z]\d*|nvme\d+n\d+(?:p\d+)?|disk\/)/.test(path);
}

function matchesSecurityHomePath(path: string): boolean {
  const home = homedir().replace(/\\/g, '/');
  const expanded = SECURITY_HOME_PATHS.map((item) =>
    item.startsWith('~/') ? `${home}/${item.slice(2)}` : item
  );
  return expanded.some((item) => path === item || path.startsWith(`${item}/`));
}
