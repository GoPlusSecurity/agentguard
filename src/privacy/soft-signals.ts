/**
 * Cheap, local recall net for personal data that has no extractable span.
 *
 * This is the chunk-track counterpart of the loose candidate regexes: it decides
 * only whether a sentence is *worth judging*, never whether it contains personal
 * data. Precision comes from adjudication, so the list is deliberately broad.
 *
 * Its failure mode is bounded by design. A missing keyword does not produce a
 * false clean result on its own — it means one sentence was not sent for
 * judgment, and the count of skipped sentences is reported. Adding a term is
 * always safe; the only cost of a term that is too broad is tokens.
 *
 * Grouped by the sensitive-personal-information categories in PIPL Article 28
 * so the table can be reviewed against the standard rather than by intuition.
 */
export const SOFT_SIGNAL_GROUPS: Record<string, RegExp> = {
  health: /医生|医院|门诊|住院|病情|病历|症状|确诊|诊断|手术|化验|检查结果|复查|服药|吃药|处方|药物|怀孕|孕期|抑郁|焦虑|残疾|过敏|doctor|hospital|clinic|diagnos|symptom|surgery|prescri|medication|pregnan|disabilit|therapy|illness/i,
  finance: /月薪|年薪|工资|薪水|收入|房贷|车贷|贷款|欠款|存款|余额|还款|理财|保险|social security|salary|income|mortgage|loan|debt|savings|payroll/i,
  residence: /我住|家住|住在|老家|租住|小区|门牌|常住地址|收货地址|寄到|i live at|home address|my address/i,
  identity: /身份证|护照|户口|社保|驾照|证件号|实名|passport|driver'?s licen[cs]e|national id/i,
  minor: /孩子|女儿|儿子|小孩|未成年|幼儿园|小学|上学|班主任|年级|监护人|my (?:son|daughter|kid|child)|kindergarten|grade school/i,
  belief: /宗教|信仰|教徒|党派|政治面貌|religio|church|mosque|temple|political affiliation/i,
  relationship: /结婚|离异|离婚|配偶|伴侣|恋爱|性取向|married|divorc|spouse|partner|sexual orientation/i,
  whereabouts: /行程|航班|车次|打车|通勤|轨迹|定位|每天(?:早上|晚上)?(?:都)?去|flight|itinerary|commute|my route/i,
  biometric: /人脸|指纹|声纹|虹膜|基因|dna|fingerprint|face scan|voiceprint|biometric/i,
};

/** Density of code punctuation above which a chunk is treated as structured noise. */
const CODE_DENSITY_THRESHOLD = 0.06;
// ASCII quotes, colons and commas are included because they carry JSON and log
// lines. Chinese prose uses the full-width forms, and English prose rarely
// reaches this density, so both stay below the threshold.
const CODE_PUNCTUATION = /[{}[\]();=<>|\\"':,]/g;

/** True when the sentence carries a hint that it may concern a natural person. */
export function hasSoftSignal(text: string): boolean {
  for (const pattern of Object.values(SOFT_SIGNAL_GROUPS)) {
    if (pattern.test(text)) return true;
  }
  return false;
}

/** Which categories fired, for evidence and for tuning the table. */
export function softSignalGroups(text: string): string[] {
  return Object.entries(SOFT_SIGNAL_GROUPS)
    .filter(([, pattern]) => pattern.test(text))
    .map(([group]) => group);
}

/**
 * True for JSON, logs, minified payloads and source code.
 *
 * Structured text is already the deterministic rules' home ground, and it makes
 * up the overwhelming majority of an agent's on-disk footprint. Sending it for
 * semantic judgment buys nothing and dominates the token bill.
 */
export function isStructuredNoise(text: string): boolean {
  if (text.length < 8) return true;
  const punctuation = text.match(CODE_PUNCTUATION)?.length ?? 0;
  return punctuation / text.length > CODE_DENSITY_THRESHOLD;
}
