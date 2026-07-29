# If it already happened — do this, in this order

**You pasted something into Terminal, or a decoy fired, or something is just
wrong. Start here.**

Read this on your **phone**, not on the Mac you are worried about. The order is
the whole point: several of these steps are useless or actively wasted if you do
them in the wrong sequence. Do not skip ahead to "change my passwords" — that is
step 4, and doing it first is the single most common mistake.

Print this, or run `./panic.sh`, which prints it with no network and no browser.

> **The one-line version:** move crypto → get offline → **kill sessions before
> changing passwords** → revoke app access → change passwords → hunt for mail
> rules → rotate developer tokens → then decide about wiping.

---

## 0. Crypto first. It is the only loss you cannot undo.

Everything else in this document is recoverable. This is not.

If a seed phrase, keystore file, or wallet password was anywhere on that
machine — in Notes, a screenshot, a text file, a password manager, a browser
extension, a photo of a piece of paper:

- [ ] On a **different, clean device**, create a **brand new wallet**.
- [ ] Move the funds to it **now**. Before coffee, before reading the rest.
- [ ] Do **not** "change the password" on the old wallet. The seed *is* the
      wallet. Whoever has it owns the funds forever, password or not.
- [ ] Assume every wallet derived from that seed is compromised, including ones
      you have not used.

Stealers sell wallet material first because it clears fastest. Minutes matter
here in a way they do not anywhere else in this document.

---

## 1. Get the machine off the network. Do not reboot it yet.

- [ ] Turn off Wi-Fi. Unplug ethernet. Leave the machine **on**.
- [ ] Do all following steps from your **phone** or another computer.
- [ ] **Do not reboot, and do not "clean up" yet.** Rebooting destroys running
      process and network evidence that tells you what actually ran — which is
      what tells you how much of the rest of this list you truly need.
- [ ] If you want that evidence preserved, run `./preserve.sh` first. If you do
      not care, keep moving; the rest of this list matters more.

Do not power it off either. A powered-off machine is fine; you just lose more
information.

---

## 2. Kill every active session. **Before** you touch a single password.

This is the step people get wrong, and getting it wrong wastes the whole effort.

**A stolen session cookie logs in as you without the password and without your
2FA code.** Changing your password does not always invalidate sessions that are
already live. If you change the password first and *then* sign out everywhere,
fine — but if you change it and stop there, the attacker is still logged in,
with your new password now protecting nothing.

So: **sign out of all devices/sessions first, then change the password.**

- [ ] **Google:** myaccount.google.com → Security → Your devices → Manage all
      devices → sign out of everything you do not recognise.
- [ ] **Apple:** appleid.apple.com → Devices → remove anything unfamiliar.
- [ ] **Microsoft / Slack / Discord / X / Meta / GitHub:** each has a "sign out
      of all sessions" or "active sessions" control. Use it on every one.
- [ ] **Your password manager** — sign out all sessions, then change the master
      password from a clean device.
- [ ] **Your bank and anything holding money** — sign out all sessions, and call
      them if there is any sign of movement.

If a service offers only "log out everywhere" buried in settings, that is the
control you want.

---

## 3. Revoke third-party app access (OAuth). These survive every password change.

An app you authorised years ago still has a token. Your new password does
nothing to it. Neither does your 2FA.

- [ ] **Google:** myaccount.google.com → Data & privacy → Third-party apps with
      account access → remove anything you do not actively use.
- [ ] **GitHub:** Settings → Applications → Authorized OAuth Apps **and**
      Authorized GitHub Apps. Revoke aggressively; you can re-authorise later.
- [ ] **Microsoft, Slack, Discord, Notion, Figma, Dropbox:** same idea, same
      place — "connected apps" / "installed apps".

---

## 4. Now change passwords. Email account first.

Email first, always — it is the master key that resets everything else.

- [ ] Change your **primary email** password from a **clean device**.
- [ ] Then: password manager, bank, Apple ID, Google, GitHub, hosting, domain
      registrar, anything with a card on file.
- [ ] Every password saved in a **browser** should be treated as stolen. That is
      the first thing a stealer takes.
- [ ] Turn on 2FA where it is missing. Prefer an **app or hardware key** over
      SMS.
- [ ] Do not reuse anything. If you reused a password anywhere, change it
      everywhere it was reused.

---

## 5. Sweep your email for persistence. Do this even if nothing looks wrong.

This is how someone keeps access after you have changed everything. All of it is
invisible during normal use, and all of it survives a password reset.

- [ ] **Forwarding** — Settings → Forwarding. Remove any address you did not add.
- [ ] **Filters / rules** — look for rules matching `reset`, `verify`, `code`,
      `security`, `bank`, or anything that auto-deletes or auto-archives. A rule
      that silently trashes password-reset emails means they can reset your
      accounts and you will never see the mail.
- [ ] **Send mail as / aliases** — remove addresses you do not recognise.
- [ ] **Account delegation / granted access** — Gmail lets another account read
      and send as you. Check it.
- [ ] **App-specific passwords** — revoke all of them and regenerate only what
      you actually need. They bypass 2FA by design.
- [ ] **Recovery email and phone number** — confirm both are still yours. A
      changed recovery address is a permanent back door.

---

## 6. Rotate developer credentials, in blast-radius order.

If you write code, this section is the difference between *your* breach and
*your users'* breach.

- [ ] **npm / PyPI / RubyGems / crates.io publish tokens — first.** A stolen
      publish token turns a personal compromise into a **supply-chain
      compromise** that hits everyone who installs your package. Revoke, then
      re-issue. Check your packages' recent versions for anything you did not
      publish.
- [ ] **Cloud keys** (AWS / GCP / Azure). **Disable first, delete after.**
      Deleting immediately destroys the audit trail that shows what was done
      with them. Check billing for resources you did not create.
- [ ] **GitHub personal access tokens** — Settings → Developer settings → revoke
      all, re-issue narrowly.
- [ ] **SSH and GPG keys** — Settings → SSH and GPG keys. Remove anything
      unfamiliar. Generate a new key **with a passphrase** and delete the old.
- [ ] **Per-repo deploy keys and Actions secrets** — the most forgotten items on
      this list, because there is no "revoke all" button. You have to walk every
      repo. Do the ones that deploy to production first.
- [ ] **Hosting and services**: Vercel, Netlify, Railway, Fly, Convex, Supabase,
      Stripe (**check for new API keys and webhook endpoints**), Cloudflare,
      Twilio, SendGrid, OpenAI/Anthropic.
- [ ] **Your `.env` files** — every value in every one is burned. Rotate them,
      do not just move them.
- [ ] **Check `git log` on your main repos** for commits you did not make.

---

## 7. Apple ID

- [ ] appleid.apple.com → **Devices** — remove anything you do not recognise.
- [ ] Change the password. Regenerate **app-specific passwords**.
- [ ] Verify **trusted phone numbers** — an added number is a back door.
- [ ] Understand the blast radius: **if iCloud Keychain sync was on, one Apple ID
      compromise means every synced credential on every device you own.** Treat
      the whole keychain as exposed.

---

## 8. Decide about wiping. This is a bright line, not a feeling.

Ask one question: **did anything get root?**

Answer **yes** if any of these are true:

- You typed your Mac password into any prompt during or shortly after the
  incident — including one that looked like System Settings. (The fake password
  dialog is the standard second stage. It is convincing.)
- There is a new file in `/Library/LaunchDaemons`.
- There is a new file in `/Library/PrivilegedHelperTools`.
- A configuration profile appeared (System Settings → General → Device
  Management).
- A new system extension appeared (`systemextensionsctl list`).
- `sudo` behaves differently, or you find an entry in `/etc/sudoers.d/`.

**If yes to any → erase and reinstall from Recovery.**
Restore your **data only** — documents, photos, code. Never restore applications,
LaunchAgents, or system settings from a backup taken after the incident. Treat
every credential that was on the machine as burned, whether or not you found
evidence it was taken.

**If no to all, and the exposure was browser-scoped** (saved passwords, cookies,
extension data) → the steps above are a defensible cleanup without a wipe.

**Third option:** restore a Time Machine snapshot from **before** the incident.
Be careful with the date — a snapshot taken after infection restores the
infection.

If you cannot tell, wipe. The cost of an unnecessary reinstall is an afternoon.
The cost of skipping a necessary one is doing this whole list again in a month.

---

## 9. Afterwards

- [ ] Run `./exposurescan/exposurescan.py` to see what a stealer would have
      walked away with. Fix the P0s so the next one is smaller.
- [ ] Install **ShellGuard** so the next paste has to get past a typed
      confirmation.
- [ ] Make a **standard, non-admin account** for everyone who is not you
      (`./guestmode/setup-guestmode.sh`). The founding incident of this kit was
      someone else using an admin account to watch a movie.
- [ ] Plant **canaries** (`./canary/canary-gen.sh`) so next time you find out
      early instead of eventually.
- [ ] Freeze your credit if identity documents were on the machine.
      In Canada: Equifax and TransUnion. In the US: all three bureaus.
- [ ] Tell anyone whose data was on that machine. Clients, especially. It is a
      bad conversation and a much worse one later.

---

## What not to do

- **Do not** reuse the compromised machine for the cleanup. Every password you
  type on it goes to the same place the last ones did.
- **Do not** change passwords before killing sessions (step 2).
- **Do not** delete cloud keys before disabling them — you lose the audit trail.
- **Do not** restore applications or LaunchAgents from a post-incident backup.
- **Do not** assume "it only got my browser." Assume the worst until
  ExposureScan and the checks in step 8 tell you otherwise.
- **Do not** rush past step 0 because the rest of the list looks longer.

---

*Part of the [ClickFix Defense Kit](https://github.com/DareDev256/clickfix-defense-kit).
Written after a real breach. If you are reading this during one: work the list
in order, and it will be over sooner than it feels right now.*
