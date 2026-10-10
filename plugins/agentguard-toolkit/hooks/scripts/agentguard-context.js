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

async function main() {
  [fs, os, path] = await Promise.all([
    import("node:fs"),
    import("node:os"),
    import("node:path"),
  ]);

  await readStdin();
  const registryResult = loadRegistry(resolveRegistryPath());
  const sentences = [
    "GoPlus AgentGuard MCP tools are available (server 'agentguard'): skill_scanner_scan, registry_lookup, registry_attest, registry_revoke, registry_list, action_scanner_decide, action_scanner_simulate_web3.",
    "Before installing or first-running any third-party skill, scan it with skill_scanner_scan and check registry_lookup; before any Web3 signing or transaction, run action_scanner_simulate_web3; when unsure whether a risky command, network request, or secret access is safe, run action_scanner_decide.",
  ];
  const warning = registryResult.status === "invalid"
    ? " Warning: the local AgentGuard trust registry could not be parsed; the skill trust gate is inactive."
    : "";
  process.stdout.write(`${JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "SessionStart",
      additionalContext: `${sentences.join(" ")}${warning}`,
    },
  })}\n`);
}

main().catch(() => process.exit(0));
