# OAuth for an app on the person's computer

A design pattern of Anagram (`anagram.local.sources.oauth`,
`anagram.local.sources.credentials`). Use it when an app on the person's
computer reads a cloud service of that person (Google Drive, Gmail, Notion).

## Problem

The app must get a token with the consent of the person, keep it, and use it
for a long time. The app cannot keep a client secret: anyone can read the
binary. Another local app or a web page can try to take the authorization
code or send a forged callback. A token in a config file, a log line or a
backup is a token that leaks.

## Contract

1. **PKCE with a one-use loopback receiver** (RFC 8252, RFC 7636). The
   redirect goes to `http://127.0.0.1:<port>/oauth/callback`. The receiver
   is a separate listener, not a route of the local UI. It binds to
   127.0.0.1 only, accepts one `GET` with the expected `state` (32 random
   bytes, a constant-time compare), and stops after that request or after
   300 seconds. A provider with no PKCE (Notion) gets fixed registered
   ports, tried in order.
2. **The client secret of an installed app is not a secret.** The design
   does not depend on it. A real secret is never in the repository.
3. **Client order: group, build, user.** A client that the lab set in its
   signed settings record, then a client in the release build, then a
   client in a developer file in the app home. A refresh or a revoke uses
   the client of the grant.
4. **The token is in the OS keychain only.** The local database holds the
   account label, the scopes and the status, never a token. A token is
   never in a config, a log line, an event, an error text, a backup or the
   recovery kit.
5. **A host allow-list for token use.** The credential store gives a token
   only for a URL on the API hosts of the provider, over HTTPS. The HTTP
   layer follows no redirect to another host, port or scheme.
6. **Read-only scopes, the narrowest that do the work.**
7. **One account for each provider, client and person.**
8. **Revoke on remove.** When the last source of an account goes, the app
   revokes the grant and deletes the keychain entry.
9. **Expiry is a state, not an error loop.** A refresh that gives
   `invalid_grant` marks the account `expired`; its sources wait with one
   action: sign in again.

## Limits

The provider sees the client, the account, the IP address and each API
request. A person who controls the running computer can use the token.
