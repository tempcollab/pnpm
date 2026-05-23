# Git Fetch Argument Injection via Lockfile `resolution.commit`

**CVSS3.1:** 6.4 `CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:N`
**CWE:** CWE-88: Improper Neutralization of Argument Delimiters in a Command
**Ecosystem:** npm
**Package Name:** pnpm
**Affected Versions:** <= 11.2.2
**Patched Versions:** None

> Discovered by [AutoFyn](https://github.com/SignalPilot-Labs/AutoFyn). Full audit (7 confirmed findings, 3 exploit chains): [audit_report.md](https://github.com/tempcollab/pnpm/blob/main/autofyn_audit/audit_report.md)

### Summary

pnpm passes the lockfile-controlled git `resolution.commit` value to `git fetch` without a `--` separator or commit-format validation. For git dependencies fetched through the shallow-fetch path, a malicious lockfile can replace the expected 40-character commit hash with a Git option such as `--upload-pack=<command>`. Git interprets the value as an option rather than as a revision. For SSH and local transports, `--upload-pack` can execute the supplied command before the fetch fails.

This is a conditional argument-injection issue. HTTPS git transports ignore `--upload-pack`, so the practical attack surface is primarily SSH or local git dependencies whose host is in pnpm's `gitShallowHosts` list.

### Details

The vulnerable path is in `fetching/git-fetcher/src/index.ts`. When a git dependency host is configured for shallow fetching, pnpm initializes a temporary repository, adds the remote, and calls:

```typescript
await execGit(['fetch', '--depth', '1', 'origin', resolution.commit], { cwd: tempLocation })
```

Because `resolution.commit` is appended before a `--` separator, Git can parse a commit value beginning with `-` as an option. The same file later passes the value to `git checkout` without a separator:

```typescript
await execGit(['checkout', resolution.commit], { cwd: tempLocation })
```

`resolution.commit` comes from the lockfile and is typed as a plain `string`; pnpm does not validate it as a 40-character hexadecimal commit before passing it to Git.

### PoC

```bash
bash autofyn_audit/exploits/vuln11_git_upload_pack_rce/exploit.sh
# Creates a local bare git repo and triggers the shallow-fetch path with
# pnpm_config_git_shallow_hosts='["githost"]'.
# Replaces the lockfile commit hash with:
#   '--upload-pack=touch /tmp/vuln11_pwned'
# Result: PASS -- /tmp/vuln11_pwned created by injected touch command.
```

The PoC uses a local `file://githost/...` repository because the injection requires a local or SSH transport. In a real project, the analogous target would be an SSH git dependency whose host is in `gitShallowHosts`, such as a private `git+ssh://git@github.com/...` dependency.

### Impact

Code execution as the user running `pnpm install`, under specific transport conditions. The attacker must be able to modify `pnpm-lock.yaml`, and the affected dependency must use SSH or local git transport on a host that pnpm shallow-fetches. The command may execute even though the subsequent fetch fails.

### Preconditions

- The attacker must be able to modify `pnpm-lock.yaml`.
- The project must contain a git dependency that reaches pnpm's shallow-fetch path.
- The dependency must use SSH or local transport. HTTPS transport ignores `--upload-pack`, which substantially narrows the practical attack surface.
- The install must attempt to fetch the git dependency rather than reuse a previously populated store entry.

### Remediation

1. Add a `--` separator before lockfile-controlled git revision values:

   ```typescript
   await execGit(['fetch', '--depth', '1', 'origin', '--', resolution.commit], { cwd: tempLocation })
   await execGit(['checkout', '--', resolution.commit], { cwd: tempLocation })
   ```

2. Validate `resolution.commit` before passing it to Git. For pinned git lockfile entries, reject values that do not match `/^[0-9a-f]{40}$/i`.
3. Apply validation when reading lockfile git resolutions so malformed values fail before reaching the fetcher.
