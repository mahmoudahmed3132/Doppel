# Identity decoy (LDAP, LDAPS, RDP)

Read `common-decoy.md` first.

## Purpose

Impersonate a Windows domain controller's directory and remote-desktop
surface, so that credential guessing, directory enumeration and pass-the-hash
attempts against "the DC" become events with the attempted identity.

## Listeners

| Protocol | Default port | Transport |
|---|---|---|
| LDAP | 389 | TCP |
| LDAPS | 636 | TLS over TCP, self-signed certificate for the persona host name, generated at start, never written to disk |
| RDP | 3389 | TCP (X.224, then TLS for NLA) |

## LDAP and LDAPS (RFC 4511, BER per X.690)

- Parse LDAPMessage envelopes with a strict BER reader: definite lengths only,
  a maximum message size (for example 64 KiB) and a maximum nesting depth.
- **BindRequest, simple:** report `ldap_login` (or `ldaps_login`) with the
  bind DN as `bind_dn`, the user name derived from it as `username`, and the
  password per the capture policy. Answer `invalidCredentials` (49) with a
  diagnostic message in the style of Active Directory (`80090308: LdapErr:
  DSID-…, data 52e`).
- **Anonymous bind** (empty DN and password): answer success, and report
  nothing until the client searches.
- **BindRequest, SASL GSS-SPNEGO / NTLM and the Sicily NTLM bind**
  (Microsoft's LDAP NTLM extension): run the NTLM challenge-response
  (MS-NLMP): answer the NEGOTIATE with a CHALLENGE (random server challenge,
  target information naming the persona domain and host), parse the
  AUTHENTICATE message, and report user, domain, workstation and the
  NetNTLMv2 response per the capture policy (HMAC by default). Then answer
  `invalidCredentials`.
- **SearchRequest:** answer the RootDSE (base search on the empty DN) with
  plausible attributes for the persona (naming contexts, supported LDAP
  versions and controls, `dnsHostName`, domain functionality levels). Any
  other search answers success with no entries. Report `ldap_query` with the
  base DN, scope and a capped rendering of the filter.
- **UnbindRequest** closes; unknown operations get `unwillingToPerform` or
  are ignored, per RFC 4511.

## RDP (MS-RDPBCGR, MS-CSSP, MS-NLMP)

- Answer the X.224 Connection Request with a Connection Confirm that selects
  TLS + CredSSP (Network Level Authentication), as a modern server does.
  Report the cookie user name (`mstshash=`) as `username` when present.
- Upgrade to TLS, then run CredSSP: carry the NTLM exchange in TSRequest
  messages (ASN.1 DER), parse the AUTHENTICATE message and report user,
  domain, workstation and the NetNTLMv2 response per the capture policy as
  `rdp_login`. Then fail the exchange the way a server does on a wrong
  password and close.
- A client that refuses NLA gets a failure; report `rdp_connection`.

## Persona settings

Domain (NetBIOS and DNS), host name and operating-system build shown in NTLM
target information, LDAP RootDSE and the TLS certificate. Defaults must be
plausible and must never name Doppel.

## Out of scope

Kerberos, LDAP writes, StartTLS (answer `unavailable`), RDP sessions beyond
authentication, relaying of any credential.
