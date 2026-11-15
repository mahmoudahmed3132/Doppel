# Remote access decoy (SSH, Telnet, FTP)

Read `common-decoy.md` first.

## Listeners

| Protocol | Default port |
|---|---|
| SSH 2.0 | 22 |
| Telnet | 23 |
| FTP | 21 |

## SSH (RFC 4251–4254)

- Use `golang.org/x/crypto/ssh` (BSD-3-Clause, already in the dependency
  graph) for the server transport; record it in `THIRD_PARTY.md`.
- Host key: Ed25519, derived deterministically from the node capture key and
  a fixed label (so it is stable across restarts on one node and differs
  between nodes), never written to disk. A configurable server version
  string with a plausible OpenSSH default.
- Offer `password`, `keyboard-interactive` and `publickey`. Every attempt
  fails. Report `ssh_login` per attempt (subject to the limiter) with user,
  method, client version, and: the password per the capture policy;
  for public keys, the key type and SHA-256 fingerprint (never accept).
- Cap authentication attempts per connection (for example 6) and close.

## Telnet (RFC 854, RFC 1572 for NEW-ENVIRON user)

- Negotiate minimally (refuse options, or accept ECHO/SGA to look like a
  login), show a configurable banner and `login:` / `Password:` prompts,
  read line-by-line with a maximum line length, answer `Login incorrect`,
  allow a small number of attempts, then close.
- Report `telnet_login` with user and password evidence. Strip IAC sequences
  and control bytes before reporting.

## FTP (RFC 959)

- Send a `220` banner (configurable). Accept `USER` / `PASS` and answer
  `530 Login incorrect.`; `AUTH TLS` gets `534` (or real TLS, as a setting);
  `QUIT` gets `221`; anything else before login gets `530 Please login with
  USER and PASS.`.
- Commands are lines up to 512 bytes; longer lines close the connection.
- Report `ftp_login` per USER/PASS pair (anonymous logins included, with
  `anonymous: true`).

## Out of scope

Shells, file transfer, port forwarding, any data channel.
