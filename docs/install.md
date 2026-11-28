# Install Anagram on your computer

This page is for a member: a person who uses Anagram with a node (a lab, or
Radiofuture). To run a node, read [deploy.md](deploy.md). To work on the
code, read [CONTRIBUTING.md](../CONTRIBUTING.md).

Status: the first release is for macOS. Windows and Linux builds come
later. There is no public download location yet: a build comes from your
organizer, or you make it yourself (at the end of this page).

## 1. Install

1. Open the download (`Anagram.dmg`) and drag **Anagram** into
   **Applications**.
2. Open **Anagram** from **Applications**. Nothing shows in the Dock: Anagram
   runs in the background and opens in your web browser.
3. macOS can ask if Anagram can use the keychain. Click **Always Allow**.
   Anagram keeps its master key there. It asks one time for each build.

At the first open, Anagram:

- starts when you log in (you can turn this off: **Account**, "This
  computer");
- becomes the program for `anagram://` links, so that an invite link in your
  browser opens it.

## 2. Join your node

1. Open the invite link that your organizer or your PI sent you. The page of
   the node has the button **Open Anagram**.
2. The browser asks if it can open Anagram. Allow it.
3. Anagram shows the name of the community and of the node. Type your name
   (an email address is optional) and click **Join**. The invite is the
   proof; you need no ORCID iD. You can link one later in Account.
4. Save your **recovery kit** (download or print), then confirm that you saved it.
   Keep the kit away from this computer. Anybody with the kit can restore
   your keys.

If the link does not open Anagram, open Anagram, choose **Use an invite
link**, and paste the link.

## 3. A new computer

Install and open Anagram on the new computer:

1. On the welcome screen, click **I have a recovery kit**.
2. Choose your recovery kit file (or paste the text of the kit) and click
   **Restore my keys**. Anagram unlocks the encrypted backup on your community
   node and restores your keys and findings.

If you prefer the command line, the CLI fallback is also available:

```sh
/Applications/Anagram.app/Contents/MacOS/Anagram recover --help
```

You can also name **recovery guardians** (for example, 2 of 3 colleagues) in
**Account** so you can still recover if you lose both your computer and your
recovery kit. Your node keeps an encrypted copy of your findings, so a new
computer gets them back.

## 4. What Anagram keeps on this computer

The data folder is `~/.anagram` (or the folder in `ANAGRAM_HOME`). The data
in it is encrypted with keys that are sealed by a master key in the macOS
keychain. Read "What leaves this computer" in the app (**Account**) for each
flow of data. In short:

- A person who copies your disk, or who takes your computer while it is off,
  cannot read your Anagram data without the password of your computer
  account.
- A person or a program that controls your computer while you are signed in
  can read your Anagram data.
- Your own files in the folders that you connect are not encrypted by
  Anagram. Turn on FileVault: it protects them and the memory that macOS
  writes to the disk.

If **Account** shows "The keys are in files on this computer", the keychain
was not available when the data folder was made, and the first point above
does not apply.

## 5. Updates

A release build can check one time each day if a new version exists. The
check reads one signed file from the release server: the server sees your IP
address and the time, nothing else. A file with a wrong signature is ignored.
Anagram never installs a program by itself: **Account** shows the download
link. Install the new version as in section 1. The next time that you open
Anagram, the old background app stops and the new one starts.

A build with no release server (all builds for now) makes no
update check and no request.

## 6. Remove Anagram

```sh
/Applications/Anagram.app/Contents/MacOS/Anagram app uninstall
```

This stops the background app, removes the start at login, and removes the
`anagram://` link handler. Then move **Anagram** to the Bin. Your data folder
stays; delete `~/.anagram` to remove your data from this computer. The
master key stays in the keychain as the item `org.radiofuture.anagram`;
delete it in Keychain Access.

## 7. Make a build yourself (macOS)

You need `uv` and the source of this repository.

From the root of this repository:

```sh
packaging/macos/build.sh            # dist/Anagram.app, then the self test
```

The build is not signed. macOS Gatekeeper stops an unsigned app: open
**System Settings**, **Privacy & Security**, and click **Open Anyway**. The
keychain asks again after each new unsigned build. A signed build needs an
Apple Developer ID.

## 8. For developers and headless computers

On macOS and Linux, you can run the local web app directly from source with
[uv](https://docs.astral.sh/uv/) (0.7.20 or later; it installs Python 3.13):

```sh
uv sync
uv run anagram
```

This starts the local web UI on `127.0.0.1` and opens your browser with a
one-time link. Your data stays in `~/.anagram` (use `--home DIR` for another
folder).

Optional extras:

- `uv sync --extra node` — required to run a community node or enclave process
  (not needed for the local app alone).
- `uv sync --extra anthropic` — required to use Anthropic as a model provider.

Other CLI entry points also work as `uv run anagram ...`: `anagram ui` (a local
UI in this terminal), `anagram app run` (the app with no login service), and the
CLI commands (see [priority-proofs.md](priority-proofs.md)). A new home uses the
keychain of the operating system, as the app does. Where there is no keychain,
the keys are hex files. To use hex key files on purpose, add `--plain-key-files`
(for example `anagram --plain-key-files ui`), or set `ANAGRAM_KEYSTORE=file`
(tests and headless hosts do this). The `node` and `demo` commands keep `file`
as the default. See [spec/identity.md](../spec/identity.md) section 16.

## 9. Models, AI assistants (MCP), and cost

- **Supported models:** For reading and summarizing your work, Anagram supports
  a local model through [Ollama](https://ollama.com) (the default if Ollama is
  running on your computer), any OpenAI-compatible endpoint (including OpenAI
  and OpenRouter), or Anthropic (requires `uv sync --extra anthropic`). You
  choose the provider in the app.
- **Your own AI assistant (MCP):** Claude Desktop or any other MCP client can
  connect locally through `anagram mcp` on your computer. It supports read tools
  plus draft proposals (such as matching statements) that wait for your explicit
  approval in the app. You approve each assistant and what it can access.
- **Cost:** Anagram is free and open source. Running a local model costs
  nothing. With a cloud model, you bring your own API key and pay the provider
  directly; Anagram refuses any paid call unless you set a budget or spend
  limit. Running a community node requires one small server and a domain name.
- **ORCID iD:** Not required. Your invite is the proof of membership; you can
  link an ORCID iD later in **Account** if you want.
