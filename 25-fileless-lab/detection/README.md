# detection/ — blocks 21-24, verbatim from the document

| File | Block | Content |
|---|---|---|
| `audit-fileless.rules` | 21 | auditd syscall rules |
| `sigma_fileless_memfd_exec.yml` | 22 | Sigma — exec from a memfd |
| `sigma_deleted_binary_exec.yml` | 23 | Sigma — exec from a deleted binary |
| `sigma_payload_piped_to_interpreter.yml` | 24 | Sigma — staging (pattern 3) |

Byte-identical to the HTML; regenerate with `../extract-blocks.py`.

## These are excerpts, not deployable rules

All three Sigma files parse as valid YAML and their `condition` references resolve.
They omit `id`, `status`, `description`, `author`, `date` and `references` — mandatory
or recommended by the Sigma spec, so `sigma check` will reject them as-is. Add that
front matter before loading into a SIEM.

The Sigma **logic** was validated against measured `/proc/PID/exe` values
(`tests/sigma_check.sh`): rule 22 matches both memfd loaders, rule 23 matches all four
unlinked-inode patterns. See FINDINGS.md.

## Two issues in audit-fileless.rules

**`-F exe=` is rejected by the kernel** (FINDINGS.md #8). The last two rules fail with
`Field option not supported by kernel: exe` — a field-parse error, distinct from the
`Operation not permitted` the other five get for lacking privilege, so this is not a
container artifact. `exe=` needs audit userspace/kernel support that is absent here;
`-F path=` parses fine and is the portable spelling. Verify on your target kernel before
deploying, or the two interpreter rules load silently as nothing.

**The rules do not cover patterns 1a/1b** (FINDINGS.md #4). The `fileless_fdexec`
comment claims `execveat` catches memfd exec, but `memfd_exec`, `memfd_script` and
`interp_oneliner.sh` all issue plain `execve("/proc/self/fd/N")` — caught only by the
`memfd_create` rule, which an attacker inheriting a memfd never calls.

```sh
../run-tests.sh detection_lint.sh    # parse the YAML, syntax-check the audit rules
```
