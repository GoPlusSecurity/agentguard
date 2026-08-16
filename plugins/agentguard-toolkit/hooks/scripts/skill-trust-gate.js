let fs;
let os;
let path;

function resolveRegistryPath() {
  if (process.env.OPENCLAW_STATE_DIR) {
    return path.join(process.env.OPENCLAW_STATE_DIR, "agentguard", "registry.json");
  }
  if (process.env.AGENTGUARD_HOME) {
    return path.join(process.env.AGENTGUARD_HOME, "registry.json");
  }
  return path.join(os.homedir(), ".agentguard", "registry.json");
}

function loadRegistry(registryPath) {
  try {
    const registry = JSON.parse(fs.readFileSync(registryPath, "utf8"));
    return registry && Array.isArray(registry.records)
      ? { status: "ok", registry }
      : { status: "invalid" };
  } catch (err) {
    return err && err.code === "ENOENT" ? { status: "missing" } : { status: "invalid" };
  }
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let input = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      input += chunk;
    });
    process.stdin.on("end", () => resolve(input));
    process.stdin.on("error", reject);
  });
}

// Match by declared name only: PreToolUse:Skill supplies no canonical
// source@version_ref#artifact_hash identity. This defence-in-depth gate is not
// a cryptographic control, so a renamed artifact will not match a revoked record.
function recordMatches(record, norm) {
  const skill = record && record.skill && typeof record.skill === "object" ? record.skill : {};
  const id = typeof skill.id === "string" ? skill.id.toLowerCase() : "";
  const sourcePart = typeof skill.source === "string" ? skill.source.split("/").pop() : "";
  const source = sourcePart ? sourcePart.replace(/\.git$/i, "").toLowerCase() : "";
  return id === norm || source === norm;
}

function isExpired(record) {
  if (typeof record.expires_at !== "string") return false;
  const expiresAt = Date.parse(record.expires_at);
  return Number.isFinite(expiresAt) && expiresAt < Date.now();
}

function newestActive(records) {
  const active = records.filter((record) => record.status === "active" && !isExpired(record));
  if (active.length === 0) return null;
  const dated = active
    .map((record) => ({ record, updatedAt: Date.parse(record.updated_at) }))
    .filter((item) => Number.isFinite(item.updatedAt));
  if (dated.length === 0) return active[active.length - 1];
  dated.sort((a, b) => a.updatedAt - b.updatedAt);
  return dated[dated.length - 1].record;
}

function emit(output) {
  process.stdout.write(`${JSON.stringify(output)}\n`);
}

function list(v) {
  return Array.isArray(v) && v.length ? v.join(", ") : "none";
}

async function main() {
  [fs, os, path] = await Promise.all([
    import("node:fs"),
    import("node:os"),
    import("node:path"),
  ]);

  let event;
  try {
    event = JSON.parse(await readStdin());
  } catch {
    return;
  }

  const raw = event && event.tool_input && event.tool_input.skill;
  if (event.tool_name !== "Skill" || typeof raw !== "string" || raw.trim() === "") return;

  const norm = raw.split(":").pop().split("/").pop().trim().toLowerCase();
  if (!norm) return;

  const registryPath = resolveRegistryPath();
  const registryResult = loadRegistry(registryPath);
  if (registryResult.status === "missing") return;
  if (registryResult.status === "invalid") {
    // Without parsed records we cannot identify revoked skills; denying every
    // skill would wedge the session, so stay open and report the failure loudly.
    emit({
      hookSpecificOutput: { hookEventName: "PreToolUse" },
      systemMessage: `AgentGuard: trust registry at ${registryPath} exists but could not be parsed (expected {"records":[...]}). The skill trust gate is inactive this session.`,
    });
    return;
  }

  const registry = registryResult.registry;
  if (registry.records.length === 0) return;

  const matches = registry.records.filter((record) => recordMatches(record, norm));
  if (matches.length === 0) return;

  const record = matches.find((match) => match.status === "revoked") || newestActive(matches);
  if (!record) return;

  if (record.status === "revoked") {
    emit({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: `AgentGuard trust registry: skill '${norm}' is REVOKED (record ${record.record_key}). Do not run it. Use the skill-trust skill (registry_lookup / registry_attest) to review or re-trust it.`,
      },
    });
    return;
  }

  if (record.trust_level === "untrusted") {
    emit({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "ask",
        permissionDecisionReason: `AgentGuard trust registry: skill '${norm}' is marked UNTRUSTED (record ${record.record_key}). Confirm before running it.`,
      },
    });
    return;
  }

  if (record.trust_level === "restricted") {
    const capabilities = record.capabilities && typeof record.capabilities === "object" ? record.capabilities : null;
    const exec = capabilities && (capabilities.exec === "allow" || capabilities.exec === "deny") ? capabilities.exec : "unspecified";
    const hasValidCapabilities = capabilities && (
      exec !== "unspecified"
      || Array.isArray(capabilities.network_allowlist)
      || Array.isArray(capabilities.filesystem_allowlist)
      || Array.isArray(capabilities.secrets_allowlist)
    );
    if (!hasValidCapabilities) {
      emit({
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          additionalContext: `AgentGuard: skill '${norm}' is trust-level RESTRICTED but its trust record is malformed (capabilities missing or invalid). Treat it as untrusted and proceed with caution.`,
        },
      });
      return;
    }
    const network = list(capabilities.network_allowlist);
    const filesystem = list(capabilities.filesystem_allowlist);
    const secrets = list(capabilities.secrets_allowlist);
    emit({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        additionalContext: `AgentGuard: skill '${norm}' is trust-level RESTRICTED. Granted capabilities — exec: ${exec}; network allowlist: ${network}; filesystem allowlist: ${filesystem}; secrets allowlist: ${secrets}. Stay within these bounds while this skill runs.`,
      },
    });
  }
}

main().catch(() => process.exit(0));
