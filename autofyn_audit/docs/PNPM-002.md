# allowBuilds Security Policy Does Not Block Bin Linking (PATH Hijacking)

**CVSS3.1:** 5.9 `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:N`
**CWE:** CWE-269: Improper Privilege Management
**Ecosystem:** npm
**Package Name:** pnpm
**Affected Versions:** <= 11.2.2
**Patched Versions:** None

> Discovered by [AutoFyn](https://github.com/SignalPilot-Labs/AutoFyn). Full audit (7 confirmed findings, 3 exploit chains): [audit_report.md](https://github.com/tempcollab/pnpm/blob/main/autofyn_audit/audit_report.md)

### Summary

pnpm's `allowBuilds` security policy blocks lifecycle scripts (postinstall, preinstall, install) for disallowed packages but does not block bin linking. A package blocked by `allowBuilds: {pkg: false}` can still place executables in `node_modules/.bin/` that shadow common command names (`node`, `npm`, `git`, `curl`). These shadowed binaries can execute if an allowed lifecycle script, project script, or user command invokes the shadowed name while pnpm has prepended `node_modules/.bin` to PATH. This is a coverage gap in the `allowBuilds` security boundary, not direct code execution by itself.

### Details

When `allowBuilds: {pkg: false}` is set in `pnpm-workspace.yaml`, the `buildModules` function in `building/during-install/src/index.ts` (lines 90-108) correctly sets `ignoreScripts = true` for the blocked package, preventing its lifecycle scripts from running. However, in the `buildDependency` function, `linkBinsOfDependencies()` at line 176 executes **unconditionally before** the `ignoreScripts` check that gates `runPostinstallHooks()` at line 187. Additionally, `linkAllBins()` at `installing/deps-installer/src/install/index.ts:1651` links bins for all new dependency paths with no `allowBuild` check at all.

```typescript
// building/during-install/src/index.ts
const allowed = allowBuild(node.name, node.version)
switch (allowed) {
  case false:
    ignoreScripts = true  // only blocks lifecycle scripts
    break
}

// buildDependency: line 176 runs BEFORE ignoreScripts is checked
await linkBinsOfDependencies(depNode, depGraph, opts)  // unconditional
// line 187: only this is gated
const hasSideEffects = !opts.ignoreScripts && await runPostinstallHooks(...)
```

The vendored `@pnpm/npm-lifecycle` module's `extendPath()` function prepends `node_modules/.bin` to PATH for lifecycle scripts, so a blocked package's shadowed `node` binary can execute when an allowed package's postinstall calls `node`.

### PoC

```bash
# Prerequisites: verdaccio test registry on localhost:4873 (see setup.sh)
bash autofyn_audit/exploits/vuln5_bin_shadow/exploit.sh
# Publishes evil-shadow@1.0.0 with bin: {"curl": "./evil.sh"} and a postinstall.
# Project blocks it via allowBuilds: {evil-shadow: false}.
# Result: PASS -- postinstall correctly blocked, but node_modules/.bin/curl
#         linked to evil.sh (policy bypass). Running the linked bin executes
#         the attacker's script.
```

### Impact

PATH hijacking from a package that the user explicitly blocked via `allowBuilds`. Users who rely on this pnpm v11 supply-chain security feature to contain suspicious packages have an incomplete picture: the blocked package's lifecycle scripts are blocked, but its declared executables may still be linked and may execute if another script invokes the shadowed command name.

### Preconditions

- The attacker must get a package with a malicious `bin` entry installed in the dependency graph.
- The package must be blocked via `allowBuilds`, creating the expectation that it cannot execute install-time code.
- A later lifecycle script, project script, or user command must invoke the shadowed command name.
