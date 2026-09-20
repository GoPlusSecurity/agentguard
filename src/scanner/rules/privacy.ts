import type { PiiCategory } from '../../runtime/types.js';
import type { RiskTag, ScanRule } from '../../types/scanner.js';

const NATIONAL_ID_PATTERN = /["']?(?:national[_-]?id|id[_-]?card|identity[_-]?(?:number|no)|身份证号?|social[_-]?security[_-]?(?:number|no)|ssn|passport[_-]?(?:number|no)?)["']?\s*[:=]\s*["']?([A-Z0-9-]{6,20})/i;
const BANK_ACCOUNT_PATTERN = /["']?(?:bank[_-]?account|account[_-]?(?:number|no)|card[_-]?(?:number|no)|credit[_-]?card|debit[_-]?card|iban|收款账号|银行卡号?)["']?\s*[:=]\s*["']?([A-Z]{2}\d{2}[A-Z0-9 ]{10,30}|\d[\d -]{10,28}\d)/i;
const BIOMETRIC_PATTERN = /["']?(?:face[_-]?(?:embedding|template)|fingerprint[_-]?(?:template|data)|voiceprint|voice[_-]?print|iris[_-]?(?:template|scan)|genetic[_-]?(?:sequence|data)|dna[_-]?(?:sequence|profile)|人脸特征|指纹模板|声纹|虹膜|基因数据)["']?\s*[:=]\s*["']?([^"'\n,}]{8,}|\[[^\]\n]{12,}\])/i;
const MINOR_PATTERN = /["']?(?:age|child[_-]?age|minor[_-]?age|年龄)["']?\s*[:=]\s*["']?(\d{1,3})\b/i;
const HEALTH_PATTERN = /["']?(?:medical[_-]?record|health[_-]?record|diagnosis|prescription|lab[_-]?(?:result|report)|病历|诊断|处方|检验结果)["']?\s*[:=]\s*["']?([^"'\n,}]{3,})/i;
const LOCATION_PATTERN = /["']?(?:location[_-]?(?:trace|history)|gps[_-]?(?:trace|history)|trajectory|precise[_-]?locations?|定位轨迹|行踪轨迹)["']?\s*[:=]/i;
const CONTACT_DUMP_PATTERN = /["']?(?:contacts?|contact[_-]?list|address[_-]?book|customer[_-]?list|通讯录|客户名单)["']?\s*[:=]/i;
const PHONE_PATTERN = /["']?(?:phone[_-]?(?:number|no)?|mobile[_-]?(?:number|no)?|telephone|手机号|联系电话)["']?\s*[:=]\s*["']?(\+?[1-9]\d{7,14})\b/i;
const EMAIL_PATTERN = /["']?(?:personal[_-]?email|email[_-]?(?:address|addr)?|e-mail|邮箱)["']?\s*[:=]\s*["']?([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})/i;
const DATASET_PATTERN = /["']?(?:users?|customers?|patients?|people|persons?|records?|dataset|用户数据|客户数据|患者数据)["']?\s*[:=]\s*[\[{]/i;

const EMAIL_CANDIDATE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const PHONE_CANDIDATE = /(?<!\d)(?:\+[1-9]\d{7,14}|1[3-9]\d{9})(?!\d)/g;
const KNOWN_TEST_CARD_NUMBERS = new Set([
  '4111111111111111',
  '4242424242424242',
  '4000000000000002',
  '5555555555554444',
  '378282246310005',
  '6011111111111117',
]);

export interface PiiCategoryDetection {
  category: PiiCategory;
  tag: RiskTag;
  count: number;
}

export const PRIVACY_RULES: ScanRule[] = [
  privacyRule('PII_NATIONAL_ID', 'Detects labeled national ID, passport, and SSN values', 'high', NATIONAL_ID_PATTERN,
    (_content, match) => isValidNationalIdentifier(match[1] ?? '')),
  privacyRule('PII_BANK_ACCOUNT', 'Detects labeled bank account, payment card, and IBAN values', 'high', BANK_ACCOUNT_PATTERN,
    (_content, match) => isValidBankIdentifier(match[1] ?? '', match[0])),
  privacyRule('PII_BIOMETRIC', 'Detects labeled biometric or genetic templates embedded in files', 'high', BIOMETRIC_PATTERN,
    (_content, match) => !isPlaceholderValue(match[1] ?? '')),
  privacyRule('PII_MINOR_DATA', 'Detects labeled data for children under 14 years old', 'high', MINOR_PATTERN,
    (_content, match) => Number(match[1]) >= 0 && Number(match[1]) < 14),
  privacyRule('PII_HEALTH_RECORD', 'Detects labeled medical, diagnosis, prescription, and laboratory data', 'high', HEALTH_PATTERN,
    (_content, match) => !isPlaceholderValue(match[1] ?? '')),
  privacyRule('PII_LOCATION_TRACE', 'Detects continuous precise location traces', 'high', LOCATION_PATTERN,
    (content) => countCoordinatePairs(content) >= 3),
  privacyRule('PII_CONTACT_DUMP', 'Detects contact or customer lists containing at least 20 phone numbers or email addresses', 'high', CONTACT_DUMP_PATTERN,
    (content) => countContactValues(content) >= 20),
  privacyRule('PII_PHONE_NUMBER', 'Detects labeled Chinese mobile and E.164 phone numbers', 'medium', PHONE_PATTERN,
    (_content, match) => isValidPhoneNumber(match[1] ?? '')),
  privacyRule('PII_EMAIL_ADDRESS', 'Detects labeled personal email addresses', 'medium', EMAIL_PATTERN,
    (_content, match) => isValidEmailAddress(match[1] ?? '')),
  privacyRule('PII_HARDCODED_DATASET', 'Detects inline structured datasets containing at least three PII categories', 'critical', DATASET_PATTERN,
    (content) => detectPiiCategories(content, false).length >= 3),
];

function privacyRule(
  id: RiskTag,
  description: string,
  severity: ScanRule['severity'],
  pattern: RegExp,
  validator: NonNullable<ScanRule['validator']>,
): ScanRule {
  return {
    id,
    description,
    severity,
    file_patterns: ['*'],
    patterns: [pattern],
    validator: (content, match, filePath, matchOffset) =>
      !hasSyntheticMarker(match[0]) && validator(content, match, filePath, matchOffset),
  };
}

export function isValidNationalIdentifier(rawValue: string): boolean {
  const value = rawValue.trim().toUpperCase();
  if (!value || hasSyntheticMarker(value)) return false;
  if (/^\d{17}[\dX]$/.test(value)) return isValidChineseNationalId(value);
  if (/^\d{3}-\d{2}-\d{4}$/.test(value)) return isValidSsn(value);
  return /^(?=.*\d)[A-Z][A-Z0-9]{5,8}$/.test(value) && !/^(?:TEST|FAKE|MOCK)/.test(value);
}

export function isValidBankIdentifier(rawValue: string, fieldContext = ''): boolean {
  const compact = rawValue.replace(/[\s-]/g, '').toUpperCase();
  if (!compact || hasSyntheticMarker(rawValue)) return false;
  if (/iban/i.test(fieldContext) || /^[A-Z]{2}\d{2}/.test(compact)) return isValidIban(compact);
  if (KNOWN_TEST_CARD_NUMBERS.has(compact)) return false;
  if (!/^\d{12,19}$/.test(compact) || /^(\d)\1+$/.test(compact)) return false;
  return passesLuhn(compact);
}

export function isValidPhoneNumber(rawValue: string): boolean {
  const value = rawValue.replace(/[\s()-]/g, '');
  if (!/^(?:\+[1-9]\d{7,14}|1[3-9]\d{9})$/.test(value)) return false;
  if (/55501\d{2}/.test(value) || /^(?:\+?\d{1,3})?(?:0{7,}|1{7,})$/.test(value)) return false;
  return true;
}

export function isValidEmailAddress(rawValue: string): boolean {
  const value = rawValue.trim().toLowerCase();
  const match = value.match(/^([^@]+)@([^@]+)$/);
  if (!match) return false;
  const [, local, domain] = match;
  if (/^(?:no-?reply|do-?not-?reply|faker?|mock|test)(?:[+._-]|$)/.test(local)) return false;
  if (/^(?:example\.(?:com|org|net)|localhost)$/.test(domain) || domain.endsWith('.test')) return false;
  return true;
}

/** Pure local category detector reused by runtime payload evaluation. */
export function detectPiiCategories(content: string, includeDataset = true): PiiCategoryDetection[] {
  const detections: PiiCategoryDetection[] = [];
  addDetection(detections, content, NATIONAL_ID_PATTERN, 'national_id', 'PII_NATIONAL_ID', (match) =>
    isValidNationalIdentifier(match[1] ?? ''));
  addDetection(detections, content, BANK_ACCOUNT_PATTERN, 'bank_account', 'PII_BANK_ACCOUNT', (match) =>
    isValidBankIdentifier(match[1] ?? '', match[0]));
  addDetection(detections, content, BIOMETRIC_PATTERN, 'biometric', 'PII_BIOMETRIC', (match) =>
    !isPlaceholderValue(match[1] ?? ''));
  addDetection(detections, content, MINOR_PATTERN, 'minor_data', 'PII_MINOR_DATA', (match) =>
    Number(match[1]) >= 0 && Number(match[1]) < 14);
  addDetection(detections, content, HEALTH_PATTERN, 'health_record', 'PII_HEALTH_RECORD', (match) =>
    !isPlaceholderValue(match[1] ?? ''));
  if (LOCATION_PATTERN.test(content) && countCoordinatePairs(content) >= 3) {
    detections.push({ category: 'location_trace', tag: 'PII_LOCATION_TRACE', count: countCoordinatePairs(content) });
  }
  const contactCount = countContactValues(content);
  if (CONTACT_DUMP_PATTERN.test(content) && contactCount >= 20) {
    detections.push({ category: 'contact_dump', tag: 'PII_CONTACT_DUMP', count: contactCount });
  }
  addDetection(detections, content, PHONE_PATTERN, 'phone_number', 'PII_PHONE_NUMBER', (match) =>
    isValidPhoneNumber(match[1] ?? ''));
  addDetection(detections, content, EMAIL_PATTERN, 'email_address', 'PII_EMAIL_ADDRESS', (match) =>
    isValidEmailAddress(match[1] ?? ''));
  if (includeDataset && DATASET_PATTERN.test(content) && detections.length >= 3) {
    detections.push({ category: 'hardcoded_dataset', tag: 'PII_HARDCODED_DATASET', count: 1 });
  }
  return detections;
}

/** Redact validated PII values for audit previews without returning raw evidence. */
export function redactPiiText(content: string): string {
  const original = content;
  let redacted = content;
  for (const rule of PRIVACY_RULES) {
    for (const pattern of rule.patterns) {
      const flags = pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`;
      const globalPattern = new RegExp(pattern.source, flags);
      redacted = redacted.replace(globalPattern, (...args: unknown[]) => {
        const full = String(args[0] ?? '');
        const offset = Number(args.at(-2) ?? 0);
        const captures = args.slice(1, -2).map((value) => value === undefined ? undefined : String(value));
        const match = [full, ...captures] as unknown as RegExpMatchArray;
        match.index = offset;
        match.input = redacted;
        if (rule.validator && !rule.validator(original, match, undefined, offset)) return full;
        return `[REDACTED:${rule.id}]`;
      });
    }
  }

  redacted = redacted.replace(EMAIL_CANDIDATE, (value) =>
    isValidEmailAddress(value) ? '[REDACTED:PII_EMAIL_ADDRESS]' : value);
  redacted = redacted.replace(PHONE_CANDIDATE, (value) =>
    isValidPhoneNumber(value) ? '[REDACTED:PII_PHONE_NUMBER]' : value);
  redacted = redacted.replace(/\b\d{17}[\dX]\b/gi, (value) =>
    isValidNationalIdentifier(value) ? '[REDACTED:PII_NATIONAL_ID]' : value);
  redacted = redacted.replace(/\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/gi, (value) =>
    isValidBankIdentifier(value, 'iban') ? '[REDACTED:PII_BANK_ACCOUNT]' : value);
  redacted = redacted.replace(/(?<!\d)\d{12,19}(?!\d)/g, (value) =>
    isValidBankIdentifier(value, 'card_number') ? '[REDACTED:PII_BANK_ACCOUNT]' : value);

  if (LOCATION_PATTERN.test(original) && countCoordinatePairs(original) >= 3) {
    redacted = redacted.replace(
      /(?:\[|\()\s*-?\d{1,3}(?:\.\d{4,})?\s*,\s*-?\d{1,3}(?:\.\d{4,})?\s*(?:\]|\))/g,
      '[REDACTED:PII_LOCATION_TRACE]',
    );
  }
  return redacted;
}

function addDetection(
  detections: PiiCategoryDetection[],
  content: string,
  pattern: RegExp,
  category: PiiCategory,
  tag: RiskTag,
  validate: (match: RegExpMatchArray) => boolean,
): void {
  const match = content.match(pattern);
  if (match && !hasSyntheticMarker(match[0]) && validate(match)) detections.push({ category, tag, count: 1 });
}

function isValidChineseNationalId(value: string): boolean {
  const birth = value.slice(6, 14);
  const year = Number(birth.slice(0, 4));
  const month = Number(birth.slice(4, 6));
  const day = Number(birth.slice(6, 8));
  const date = new Date(Date.UTC(year, month - 1, day));
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) return false;
  const weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
  const checks = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];
  const sum = value.slice(0, 17).split('').reduce((total, digit, index) => total + Number(digit) * weights[index], 0);
  return checks[sum % 11] === value[17];
}

function isValidSsn(value: string): boolean {
  const [area, group, serial] = value.split('-');
  return area !== '000' && area !== '666' && !area.startsWith('9') && group !== '00' && serial !== '0000';
}

function passesLuhn(value: string): boolean {
  let sum = 0;
  let double = false;
  for (let index = value.length - 1; index >= 0; index--) {
    let digit = Number(value[index]);
    if (double) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    double = !double;
  }
  return sum % 10 === 0;
}

function isValidIban(value: string): boolean {
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(value)) return false;
  const rearranged = `${value.slice(4)}${value.slice(0, 4)}`;
  let remainder = 0;
  for (const character of rearranged) {
    const digits = /[A-Z]/.test(character) ? String(character.charCodeAt(0) - 55) : character;
    for (const digit of digits) remainder = (remainder * 10 + Number(digit)) % 97;
  }
  return remainder === 1;
}

function countCoordinatePairs(content: string): number {
  const pairPattern = /(?:\[|\()\s*(-?\d{1,3}(?:\.\d{4,})?)\s*,\s*(-?\d{1,3}(?:\.\d{4,})?)\s*(?:\]|\))/g;
  let count = 0;
  for (const match of content.matchAll(pairPattern)) {
    const latitude = Number(match[1]);
    const longitude = Number(match[2]);
    if (Math.abs(latitude) <= 90 && Math.abs(longitude) <= 180) count++;
  }
  return count;
}

function countContactValues(content: string): number {
  const emails = [...content.matchAll(EMAIL_CANDIDATE)].map((match) => match[0]).filter(isValidEmailAddress);
  const phones = [...content.matchAll(PHONE_CANDIDATE)].map((match) => match[0]).filter(isValidPhoneNumber);
  return emails.length + phones.length;
}

function isPlaceholderValue(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return normalized.length < 8 || /^(?:none|null|unknown|n\/?a|healthy|normal|example|sample|test|fixture|mock|fake)(?:[-_\s]|$)/.test(normalized);
}

function hasSyntheticMarker(value: string): boolean {
  return /(?:^|[^a-z])(?:faker?|fixture|mock|sample|dummy)(?:[^a-z]|$)/i.test(value)
    || /(?:no-?reply|example\.(?:com|org|net)|\.test\b)/i.test(value);
}
