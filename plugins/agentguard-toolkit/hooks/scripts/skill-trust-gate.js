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
    return registry && Array.isArray(registry.records) ? registry : null;
  } catch {
    return null;
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

function recordMatches(record, norm) {
  const skill = record && record.skill && typeof record.skill === "object" ? record.skill : {};
  const id = typeof skill.id === "string" ? skill.id.toLowerCase() : "";
  const sourcePart = typeof skill.source === "string" ? skill.source.split("/").pop() : "";
  const source = sourcePart ? sourcePart.replace(/\.git$/i, "").toLowerCase() : "";
  const key = typeof record.record_key === "string" ? record.record_key.split("@")[0].toLowerCase() : "";
  return id === norm || source === norm || key === norm;
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

  const registry = loadRegistry(resolveRegistryPath());
  if (!registry || registry.records.length === 0) return;

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
    const capabilities = record.capabilities;
    const network = capabilities.network_allowlist.length ? capabilities.network_allowlist.join(", ") : "none";
    const filesystem = capabilities.filesystem_allowlist.length ? capabilities.filesystem_allowlist.join(", ") : "none";
    const secrets = capabilities.secrets_allowlist.length ? capabilities.secrets_allowlist.join(", ") : "none";
    emit({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        additionalContext: `AgentGuard: skill '${norm}' is trust-level RESTRICTED. Granted capabilities — exec: ${capabilities.exec}; network allowlist: ${network}; filesystem allowlist: ${filesystem}; secrets allowlist: ${secrets}. Stay within these bounds while this skill runs.`,
      },
    });
  }
}

main().catch(() => process.exit(0));
