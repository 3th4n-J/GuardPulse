<div align="center">

<img src="src/assets/icon.png" width="128" alt="GuardPulse icon" />

# GuardPulse

**A completely free content blocker with accountability controls.**
Block sites and apps, filter adult content with Cloudflare Family DNS, and put someone you trust in charge of the off switch.

![Flet](https://img.shields.io/badge/Flet-1.0.5-22D3EE?style=for-the-badge&logo=flutter&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12-14B8A6?style=for-the-badge&logo=python&logoColor=white)
![Android](https://img.shields.io/badge/Android-only-34D399?style=for-the-badge&logo=android&logoColor=white)
![Price](https://img.shields.io/badge/Price-free%20forever-06122B?style=for-the-badge)
![Status](https://img.shields.io/badge/status-phase%205%20of%206-FBBF24?style=for-the-badge)

[Features](#-features) · [How it works](#-how-it-works) · [Roadmap](#-roadmap) · [Getting started](#-getting-started) · [Security model](#-security-model) · [FAQ](#-faq)

</div>

---

## ✨ Features

| | Feature | What it does |
|---|---|---|
| 🚫 | **Website blacklist** | Block any domain and all of its sub-domains. Paste a full link and GuardPulse works out the domain. |
| ✅ | **Website whitelist** | Always allow specific sites, even inside a blocked domain. The most specific rule wins. |
| 📱 | **App blocking** | Block whole apps, with one-tap presets for TikTok, Instagram, Snapchat, Reddit, X, Telegram and more. |
| 🎬 | **Short-video feeds** | Turn off YouTube Shorts, Instagram and Facebook Reels, and Snapchat Spotlight while keeping the rest of the app. |
| ⏰ | **Scheduled app lock** | Lock chosen apps during bedtime, study or work hours, including windows that run past midnight. |
| 🛡️ | **Cloudflare Family DNS** | Every app's DNS goes through `1.1.1.3` / `1.0.0.3`, which filter adult content and malware. |
| 🤝 | **Accountability partner** | Your partner's PIN is needed for anything that loosens protection. |
| 🔑 | **Remote unlock codes** | Away from your partner? They read you a one-time 6-digit code from their authenticator app. |
| 🚨 | **Partner alerts** | Unlocks, wrong PINs, whitelisting, deletions and any protection being switched off are pushed to your partner's phone through the free [ntfy](https://ntfy.sh) app, even when the change happens outside GuardPulse. |
| 🧷 | **Uninstall protection** | GuardPulse can't be removed without the partner PIN. |
| 🔏 | **Sealed rules** | The rule set is signed with HMAC-SHA256, so editing the database outside the app is detected and reported. |

## 🧭 How it works

### The one-way ratchet

Making protection **stricter is always free**. Making it **looser always needs your partner**.

| Free, any time | Needs the partner PIN or code |
|---|---|
| Block a site or app | Whitelist a site |
| Add a schedule | Delete any block, app or whitelist entry |
| Resume a paused schedule | Pause or delete a schedule |
| Turn a protection **on** | Turn a protection **off** |
| Shorten the unlock window | Lengthen the unlock window |
| | Change the partner, PIN, authenticator or partner-alert link |

An unlock lasts 1 to 30 minutes (5 by default) and is held in memory only, so restarting the app locks it again. Three wrong attempts trigger a back-off that starts at 30 seconds and doubles each time, up to an hour. The back-off survives restarts.

### Architecture

```mermaid
flowchart LR
    subgraph Python["Flet app (Python)"]
        UI["UI<br/>Home · Sites · Apps · Schedule · Settings"]
        Guard["Guard<br/>rule engine + ratchet"]
        DB[("SQLite<br/>HMAC-sealed")]
        UI --> Guard --> DB
        Guard -->|"policy.json + .sig"| Policy[/"Signed policy"/]
    end
    subgraph Kotlin["Flet extension (Kotlin)"]
        VPN["VpnService<br/>DNS filter"]
        A11y["AccessibilityService<br/>overlay + app lock"]
        Admin["Device Admin<br/>uninstall guard"]
    end
    Policy --> VPN & A11y & Admin
    VPN -->|"allowed lookups"| CF(["Cloudflare Family<br/>1.1.1.3 / 1.0.0.3"])
    A11y & Admin -->|"tamper events"| Guard
    Guard -->|"alerts"| NTFY(["ntfy.sh → partner's phone"])
```

Flet handles the UI, data and rules. Android only exposes VPN, Accessibility and Device Admin to native code, so the enforcement services live in a Kotlin extension that reads the signed `policy.json` the Python side writes after every change.

### The DNS filter (phase 2)

The VPN claims a single virtual DNS address (`10.111.222.2`), so **only DNS lookups** go through it. Browsing, streaming and downloads keep using the normal network, so there's no speed cost and no battery-hungry packet routing.

| Lookup | Answer |
|---|---|
| Matches your blacklist | `NXDOMAIN`: the site doesn't exist |
| Matches your whitelist | Forwarded to Cloudflare |
| Browser DoH endpoints (`dns.google`, `use-application-dns.net`, …) | `NXDOMAIN`, so browsers can't tunnel around the filter |
| Everything else | Forwarded to Cloudflare Family `1.1.1.3` / `1.0.0.3`, which filters adult content and malware |

### The security overlay (phase 3)

An Android Accessibility service watches which app is in front and covers it with a full-screen block screen when:

| Trigger | What happens |
|---|---|
| A blocked app opens, or an app inside an active schedule | "App is blocked" cover; **Close** returns to the home screen |
| **Any** browser shows a blacklisted site (every app that opens web links counts, not just a fixed list) | "Site blocked" cover, then the tab is sent to `about:blank` and you're taken to the home screen, so reopening the browser doesn't loop back to the site. Works in Chrome, Firefox, Samsung Internet, Edge, Brave, Opera, DuckDuckGo, Vivaldi and more |
| You open YouTube Shorts, Instagram or Facebook Reels, or Snapchat Spotlight | Bounces you back with a brief "Shorts are blocked" message; the rest of the app keeps working |

It only reads the foreground app's name, the browser's address bar and the labels of short-video screens. Nothing leaves the phone.

> **Sideloading on Android 13+:** Android hides accessibility for apps installed outside the Play Store until you allow it. Open **App info → ⋮ → Allow restricted settings**, then switch GuardPulse on under **Accessibility**. The app walks you through this.

For the strongest setup, turn on **Always-on VPN** for GuardPulse in Android's VPN settings, so the filter starts at boot and comes back if it stops. The app reminds you and opens the screen for you.

> ⚠️ **Leave "Block connections without VPN" OFF.** GuardPulse's tunnel only carries DNS lookups; the rest of your traffic uses the normal network. That lockdown switch blocks every connection that doesn't go *through* the VPN, so the whole phone goes offline. The app shows a red warning if it's on. If the VPN is ever revoked, GuardPulse shows a "Protection is OFF" notification and queues a tamper alert for your partner.

### Uninstall + settings protection (phase 4)

Turn on **Uninstall protection** (Device Admin) and Android blocks removing GuardPulse while it's active. On top of that, the overlay watches Android's own Settings and the package installer, and asks for the partner PIN before it lets anyone:

- uninstall GuardPulse, or clear its data / force stop it;
- deactivate its device-admin (the step Android needs before an uninstall);
- disable it on the Accessibility or VPN screens.

The PIN is checked **on the device, while the app is closed** — the native layer reads an HMAC-sealed PBKDF2 hash of the PIN, so a hand-edited file is rejected and the PIN is never stored in the clear. A correct PIN grants a short window to finish the change; a wrong one backs off the same way the in-app PIN does.

> **What can't be stopped on the phone.** Safe mode, a factory reset, or `adb` can remove any user-installed app, GuardPulse included. Nothing running on the phone can prevent that — the honest answer is that the defence against it is the partner knowing. Phase 5 adds a daily "this phone has gone quiet" alert so a wipe or a long offline stretch is noticed.

> Detection of Settings screens is text-based and varies by Android version and brand, so it errs toward asking for the PIN. If a screen slips through on your phone, tell me the device and Android version.

### Partner alerts (phase 5)

When your partner is set up, GuardPulse creates a private, unguessable alert channel on [ntfy.sh](https://ntfy.sh). Your partner installs the free **ntfy** app (Android/iOS), scans the QR code GuardPulse shows, and taps Subscribe. That's the whole setup: no account, no server, no password on your phone.

| Your partner hears about | Sent by |
|---|---|
| Unlocks with the PIN or authenticator code, repeated wrong PINs | the app |
| A site whitelisted, a block / app / schedule deleted, the PIN changed | the app |
| A protection switched off in Settings (Family DNS, overlay, feed blocking, …) | the app |
| The DNS filter switched off in Android, the overlay disabled in Accessibility, uninstall protection removed, wrong PINs at the Settings guard, the rules file tampered with | **the Android layer, the moment it happens**, even if GuardPulse is never opened again |

Alerts wait in a queue until ntfy accepts them, so being offline only delays them. **Settings → Partner alerts** has a *Send test alert* button and the partner's subscribe QR (which needs the partner PIN). If the link ever leaks, the partner can make a new one there.

## 🗺️ Roadmap

- [x] **Phase 1: Core app.** Flet 1.0.5 UI, SQLite with an HMAC seal, partner PIN (scrypt) and TOTP codes, the one-way ratchet, schedules, activity log, signed policy export
- [x] **Phase 2: DNS filter.** Kotlin `VpnService` that intercepts DNS only: blacklisted names get NXDOMAIN and everything else goes to Cloudflare Family. Also: reloads instantly when rules change, restarts after reboot, raises a tamper alert when the VPN is revoked, warns when Private DNS bypasses the filter, and blocks browsers' own encrypted-DNS (DoH) endpoints
- [x] **Phase 3: Security overlay.** `AccessibilityService` that covers blocked apps (always or on a schedule), blocked sites in any browser, and YouTube Shorts / Instagram Reels / Facebook Reels / Snapchat Spotlight. Also adds an installed-app picker and raises a tamper alert if the overlay is switched off outside the app
- [x] **Updates:** daily GitHub release check, signature-verified in-place install, safety copies and automatic data recovery
- [x] **Phase 4: Uninstall + settings protection.** Device Admin blocks uninstalling GuardPulse, and the overlay covers Android's Settings/installer screens that act on GuardPulse (uninstall, force stop, clear storage, deactivate device admin, disable) with a partner-PIN prompt. The native layer verifies the PIN offline (PBKDF2, from an HMAC-sealed file) so it works while the app is closed. Switching either off outside the app raises a tamper alert.
- [x] **Phase 5: Partner alerts.** Free push alerts to the partner's phone through [ntfy](https://ntfy.sh): no account, no server, no password stored on the phone. Tamper alerts are sent straight from the Android layer the moment they happen, and everything is queued and retried while offline. The site overlay also now works in **any** browser.
- [ ] **Later (optional): "phone went quiet" alert.** Nothing on the phone can report its own uninstall or factory reset. A free [Healthchecks.io](https://healthchecks.io) heartbeat could notice the silence and tell the partner.
- [ ] **Phase 6: Google sign-in + sync.** Sign in with Google to keep rules, partner/PIN and activity in sync across devices. Uses Firebase's free Spark plan, end-to-end encrypted with a key that never leaves your devices. New devices pair by QR code, and showing that code needs the partner PIN.

## 🚀 Getting started

**Requirements:** Python 3.12, [uv](https://docs.astral.sh/uv/). Android builds also need JDK 17 and the Android SDK, which `flet build` installs on first run.

```bash
uv venv .venv --python 3.12
```

```bash
uv pip install --python .venv/Scripts/python.exe "flet[all]==1.0.5" "segno==1.6.6" -e extensions/flet_guardpulse_native
```

**Run on desktop** (hot reload):

```bash
cd src && ../.venv/Scripts/flet run main.py
```

**Run the tests:**

```bash
.venv/Scripts/python.exe -m unittest discover -s tests -v
```

**Build a signed release APK** (PowerShell). The first time, create the GuardPulse release key; it's stored outside the repo in `%USERPROFILE%\Keystores\`:

```bash
.\build-release.ps1 -NewKey
```

Then, for every release:

```bash
.\build-release.ps1
```

The script prompts for the keystore password, increases the Android version code, writes `build\apk\GuardPulse-<version>.apk` and prints the signer, so you can confirm it isn't `CN=Android Debug`.

> **Back up the keystore and its password.** Every future update must be signed with the same key. Lose it and existing installs can never be updated. Never publish a debug-signed build: Android refuses to install it over a properly signed one.

**Publish it** as a GitHub release (the in-app updater picks it up):

```bash
.\create-release.ps1
```

The script refuses any APK that isn't signed with the GuardPulse release key, makes sure the code is committed, adds a `.sha256` checksum, then tags `v<version>` and creates the release.

### 🔄 Updates that never lose your data

GuardPulse checks GitHub for a new release once a day (or from **Settings → About → Check for updates**) and shows an *Update available* card. **Update now** then:

1. saves a private safety copy of all data (`<app data>/backups`, newest 3 kept);
2. downloads the APK and checks it has the **same package, a newer version and the same signing key** as the app you have installed. Android only updates in place, keeping every byte of app data, when all three match, so anything else is refused instead of nudging you to uninstall;
3. hands it to Android's installer, and you confirm.

On first start after an update, GuardPulse logs *App updated*. If a new build ever finds no database where it expects one (the storage move that cost Selah Notes its data), it moves the old copy across or restores the newest safety copy, and never overwrites existing data. Safety copies stay in private storage because they contain the partner PIN hash and authenticator key.

> **Even safer alternative:** [Obtainium](https://github.com/ImranR98/Obtainium) can track the GitHub releases and install updates with the same signature checks. The in-app updater does this for you, so it's optional.

### Project layout

```
src/
├── main.py                  # entry point
├── assets/icon.png          # launcher icon
└── guardpulse/
    ├── guard.py             # rule engine, ratchet, tamper seal, policy export
    ├── security.py          # scrypt PIN, RFC 6238 TOTP, HMAC seal
    ├── domains.py           # URL → domain normalising + matching
    ├── db.py                # SQLite schema + app-private storage
    ├── native.py            # bridge to the Kotlin services + tamper-event intake
    └── ui/                  # Flet screens, onboarding, theme
extensions/flet_guardpulse_native/
├── src/flet_guardpulse_native/   # GuardNative Flet service (Python)
└── src/flutter/flet_guardpulse_native/
    ├── lib/                      # Dart: forwards calls to the MethodChannel
    └── android/…/shield/         # Kotlin: VPN + accessibility services, overlay, detectors, policy,
                                   #   device-admin, offline PIN verify, settings-guard, self-updater
tests/test_guard.py               # engine + native-glue tests
```

## 🔐 Security model

| Concern | How GuardPulse handles it |
|---|---|
| **PIN storage** | Only a salted `scrypt` hash is stored (N=2¹⁴, r=8, p=1). The PIN itself is never written to disk. |
| **Brute force** | Three free attempts, then a back-off from 30 s up to 1 h. The counter is stored, so restarting the app doesn't reset it. |
| **Remote codes** | Standard RFC 6238 TOTP (6 digits, 30 s, ±1 step for clock drift). Each code works once. |
| **DB tampering** | Rules, apps, schedules, settings and partner credentials are sealed with HMAC-SHA256. A mismatch flags the app, queues an alert, and only the partner can clear the warning. |
| **Policy hand-off** | The `policy.json` file the native services read is signed with the same key. The Kotlin filter verifies the signature before using any rule, keeps the last good policy if the check fails, and reports the tampering. |
| **Data location** | App-private storage (`FLET_APP_STORAGE_DATA`), which other apps can't read without root. |

> **Why not an "encrypted SQLite"?** SQLCipher isn't available for Python on Android. The real risk is that someone *changes* the rules, not that they *read* them, so GuardPulse signs the data instead of encrypting it. Moving the signing key into the Android Keystore is planned.

## ❓ FAQ

<details>
<summary><b>Is it really free?</b></summary>

Yes. No subscriptions, no paywalled features, no ads, and no accounts.
</details>

<details>
<summary><b>What about iPhone?</b></summary>

iOS only allows this kind of blocking through Apple's Screen Time and Network Extension APIs, which need special entitlements and Swift code. GuardPulse is Android-only.
</details>

<details>
<summary><b>Can it be bypassed?</b></summary>

No app that runs on the phone is unbreakable. Safe mode, a factory reset or ADB can get around any user-level blocker. GuardPulse's job is to make bypassing slow and **visible**: switching any protection off or tampering with the rules alerts your partner.
</details>

<details>
<summary><b>Why isn't it on the Play Store?</b></summary>

Google closely restricts apps that combine Accessibility and VPN permissions. Releasing on GitHub keeps every feature available with no policy review.
</details>

---

<div align="center">
<sub>Built with <a href="https://flet.dev">Flet</a> · DNS filtering by <a href="https://one.one.one.one/family/">Cloudflare 1.1.1.1 for Families</a></sub>
</div>
