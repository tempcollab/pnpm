# Arbitrary File Write/Delete via Malicious Patch File (Path Traversal)

**CVSS3.1:** 7.3 `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:H`
**CWE:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
**Ecosystem:** npm
**Package Name:** pnpm
**Affected Versions:** <= 11.2.2
**Patched Versions:** None

> Discovered by [AutoFyn](https://github.com/SignalPilot-Labs/AutoFyn). Full audit (7 confirmed findings, 3 exploit chains): [audit_report.md](https://github.com/tempcollab/pnpm/blob/main/autofyn_audit/audit_report.md)

### Summary

pnpm's patch application pipeline (`@pnpm/patch-package`) performs no path validation on file paths extracted from `.patch` files. An attacker who contributes a malicious patch file via a pull request can write attacker-controlled content to or delete arbitrary files on the filesystem during `pnpm install`, as the user running the install. The `diff --git` header paths containing `../../` sequences traverse out of the package directory, and the traversal is difficult to catch in code review because patch file diff headers are opaque to most reviewers.

### Details

During `pnpm install`, when a `patchedDependencies` entry is present in `pnpm-workspace.yaml`, pnpm reads the referenced `.patch` file and applies it via the embedded `@pnpm/patch-package` library. The `applyPatchToDir` function at `patching/apply-patch/src/index.ts:12-13` calls `process.chdir(opts.patchedDir)`, setting the working directory to the installed package location deep inside `node_modules/.pnpm/`.

The patch parser at `@pnpm/patch-package/dist/patch/parse.js:88` extracts file paths from `diff --git a/(.*?) b/(.*?)` headers using a regex with no path sanitization. The `executeEffects` function in `apply.js` then operates on these unsanitized paths:

**File write** (`apply.js:35-49`):
```javascript
case 'file creation': {
  const eff = effect
  fs.ensureDirSync(dirname(eff.path))
  fs.writeFileSync(eff.path, fileContents, { mode: eff.mode })
  break
}
```

**File delete** (`apply.js:13-22`):
```javascript
case 'file deletion': {
  const eff = effect
  // TODO: integrity checks
  if (!opts.dryRun) {
    fs.unlinkSync(eff.path)
  }
  break
}
```

A path like `../../../../../../../../../../home/user/.ssh/authorized_keys` in the patch header traverses out of the package directory to an arbitrary location. Both write and delete can be combined in a single patch file (demonstrated in CHAIN-2: Patch File SSH Backdoor).

### PoC

```bash
# Write variant:
bash autofyn_audit/exploits/vuln6_patch_traversal_write/exploit.sh
# Result: PASS -- /tmp/vuln6_pwned created with attacker-controlled content

# Delete variant:
bash autofyn_audit/exploits/vuln7_patch_traversal_delete/exploit.sh
# Result: PASS -- /tmp/vuln7_target deleted by malicious patch

# Combined chain (delete + replace SSH authorized_keys):
bash autofyn_audit/exploits/chain2_patch_ssh_backdoor/exploit.sh
# Result: PASS -- authorized_keys replaced with attacker's public key
```

### Impact

Arbitrary file write and delete as the user running `pnpm install`, limited to paths writable by that user. An attacker who submits a PR adding a `.patch` file and `patchedDependencies` config can target SSH authorized_keys, shell configuration, CI/CD files, or other writable files. Patch files may receive less review scrutiny than `package.json` changes because the `../` traversal sequences are in `diff --git` headers that look like patch metadata. The `--frozen-lockfile` flag provides no protection since patch files and `pnpm-workspace.yaml` are separate from the lockfile. This finding is demonstrated in CHAIN-2 where a single patch file deletes and replaces `~/.ssh/authorized_keys` with an attacker's public key.

### Preconditions

- A malicious `.patch` file and matching `patchedDependencies` entry must be accepted into the project.
- The target path must be writable by the user running `pnpm install`.
- A project that accepts arbitrary package scripts from the same attacker may already be exposed to other install-time code execution paths; this report focuses on pnpm failing to contain patch file effects to the patched package directory.
