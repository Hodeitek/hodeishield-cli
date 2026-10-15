# Security advisory template

Every security advisory for `hodeishield` is written from this template, as described in
[SECURITY.md](../SECURITY.md#how-advisories-are-published), so that every advisory has the same
fields in the same order. Copy everything below the line into a new GitHub security advisory for
this repository, fill in each field, and delete the parts in *italics*. Keep a heading and write
"None" rather than removing it, so readers and scripts find the same sections every time.

The first table maps to the fields of GitHub's advisory form; the rest is the advisory's
description.

---

| Advisory form field | Value |
|---|---|
| Title | *One line: the component, the flaw and its effect, e.g. "Sign-in token sent to a redirected host".* |
| Affected versions | *A range, e.g. `>= 0.2.0, < 0.3.2`.* |
| Patched versions | *e.g. `0.3.2`.* |
| Severity | *Critical, High, Medium or Low, from the CVSS v3.1 base score.* |
| CVSS v3.1 vector | *e.g. `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N`.* |
| Weakness | *CWE identifier, if one fits.* |
| Credits | *Reporter, as they asked to be credited, or "None" if they prefer not to be.* |

## Summary

*Two or three sentences: what is wrong, what an attacker can do, and what to do about it.*

## Affected versions

*Every release in the range, and every install channel that shipped them. Say if a channel was not
affected.*

## Fixed versions

*The first release with the fix, with a link to its release page.*

## Severity

*The rating and the CVSS v3.1 vector, with one sentence on why each metric that is not obvious was
chosen.*

## Impact

*What an attacker gains (for example a credential, the ability to hide terminal output, a tampered
download) and what they need first (network position, a crafted URL or identifier, local access,
the user running a particular command).*

## Who is affected

*The commands, flags, environment variables, configuration settings and platforms involved, e.g.
"anyone who signs in with `hodeishield login` on Windows", "scripts that set
`HODEISHIELD_API_KEY` together with a custom API URL". Say who is not affected.*

## Workarounds

*What to do until you can update, or "None: update". If a credential may have been exposed, say
which one and to revoke it in the app.*

## How to check whether you are affected

```sh
hodeishield --version
```

*Compare the version with the affected range above. Add any other check: a configuration value, a
file, an environment variable, a log line from `--verbose`. For the container image, check the tag
or digest your pipeline pins.*

## How to update

Verify every download as described in
[docs/verifying-releases.md](https://github.com/Hodeitek/hodeishield-cli/blob/main/docs/verifying-releases.md).
*Delete the channels that did not ship an affected version.*

- **Release archive (Linux, macOS, Windows):** download the archive for your platform from the
  release page of `<fixed version>`, verify it, and replace the `hodeishield` binary on your `PATH`.
- **Homebrew:** `brew update && brew upgrade hodeishield`
- **Scoop:** `scoop update` then `scoop update hodeishield`
- **Debian, Ubuntu (`.deb`) and Fedora, RHEL (`.rpm`):** download the `<fixed version>` package,
  verify it, and install it with the same `sudo apt install ./...` or `sudo dnf install ./...`
  command as the first time.
- **Windows installer (MSI):** install the `<fixed version>` MSI; it upgrades the installed version
  in place.
- **Install script (Linux and macOS):** download and verify the `install.sh` of `<fixed version>`,
  then run `sh install.sh --version <fixed version>`.
- **Container image:** pull `ghcr.io/hodeitek/hodeishield-cli:<fixed version>`, verify it with
  `cosign verify`, and pin the new digest in your pipeline.
- **From source:**
  `cargo install --locked --force --git https://github.com/Hodeitek/hodeishield-cli --tag v<fixed version> hodeishield-cli`

## Timeline

| Date (UTC) | Event |
|---|---|
| *YYYY-MM-DD* | Reported |
| *YYYY-MM-DD* | Fixed in `<fixed version>` |
| *YYYY-MM-DD* | Advisory published |

*Add other dates that matter, such as when exploitation was first seen or when the first notice was
published.*

## Credit

*Who reported it and how they asked to be named, or "Reported privately; the reporter asked not to
be named".*

## References

- *The release notes of `<fixed version>`.*
- *The pull request or commit with the fix, once public.*
- *The CVE identifier, if one was assigned.*
- *Anything else a reader needs: related advisories, upstream issues.*
