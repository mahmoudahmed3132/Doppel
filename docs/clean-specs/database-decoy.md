# Database decoy (MySQL, PostgreSQL, Microsoft SQL Server)

Read `common-decoy.md` first.

## Purpose

Impersonate database servers far enough to capture login attempts (user,
database, client software, password evidence) and refuse them exactly as the
real server would.

## Listeners

| Protocol | Default port |
|---|---|
| MySQL / MariaDB client protocol | 3306 |
| PostgreSQL frontend/backend protocol v3 | 5432 |
| TDS (SQL Server) 7.x | 1433 |

## MySQL (MySQL client/server protocol documentation)

- Send the initial handshake (protocol 10) with a configurable server version
  string, a random 20-byte scramble and `mysql_native_password` as the
  default plugin.
- Parse the handshake response (including the SSL request: answer by closing,
  or support TLS if implemented, as a setting): user, database, client
  attributes (`_client_name`, `_client_version`, `program_name`, capped).
  The auth response is a scramble, not a password; report it as evidence per
  the capture policy only if useful (an HMAC of the scramble response is
  acceptable), plus `password_supplied`.
- Answer `ERR` 1045 (`Access denied for user '<user>'@'<client address>'
  (using password: YES|NO)`), SQLSTATE 28000.

## PostgreSQL (PostgreSQL protocol documentation, chapter "Frontend/Backend Protocol")

- Handle `SSLRequest` (answer `N`) and `GSSENCRequest` (answer `N`), then the
  StartupMessage: user, database, application name.
- Request cleartext password authentication (AuthenticationCleartextPassword)
  so the password can be evidenced per the capture policy, read the
  PasswordMessage, and answer an ErrorResponse with severity FATAL,
  SQLSTATE 28P01 and the message `password authentication failed for user
  "<user>"`.
- `CancelRequest` closes silently.

## SQL Server (MS-TDS)

- Answer PRELOGIN with a version and `ENCRYPT_NOT_SUP` (or support the TLS
  handshake inside TDS, as a setting).
- Parse LOGIN7: host name, user name, application name, server name,
  library name, database. The password is obfuscated by MS-TDS (nibble swap
  and XOR 0xA5): de-obfuscate it, then apply the capture policy.
- Answer an ERROR token 18456, state 1, class 14 (`Login failed for user
  '<user>'.`) followed by DONE, then close.

## Triggers

`mysql_login`, `postgres_login`, `mssql_login`; `<protocol>_connection` for
sessions that end before authentication.

## Out of scope

Executing any query, TLS client certificates, replication protocols.
