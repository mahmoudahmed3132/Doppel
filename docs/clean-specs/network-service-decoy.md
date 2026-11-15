# Network service decoy (SNMP, DNS)

Read `common-decoy.md` first. Both protocols are UDP: there is no
connection, so the limiter is per source address, and the decoy must never
become a reflector or amplifier.

## SNMP (RFC 3416 PDUs; RFC 1157 v1, RFC 1901 v2c, RFC 3414 USM for v3)

- Listen on UDP 161. Parse messages with a strict BER reader (maximum
  message size, for example 1472 bytes; maximum nesting depth).
- v1 / v2c: if the community string equals a configured "valid" community
  (a setting, empty by default), answer GetRequest / GetNextRequest for the
  system group (sysDescr, sysObjectID, sysUpTime, sysContact, sysName,
  sysLocation) from persona settings; answer nothing else. For any other
  community, stay silent, as a real agent does. Report `snmp_query` with
  version, PDU type, the requested OIDs (capped list) and the community per
  the capture policy (HMAC by default: community strings are credentials).
  A SetRequest is reported at high severity and never applied.
- v3: report the user name from the USM security parameters and the
  security level; answer a Report PDU for unknown engine ID discovery only
  (usmStatsUnknownEngineIDs), which is how a real agent replies, then stay
  silent.
- Rate-limit replies per source (for example 10/s) and never send a reply
  larger than the request plus a small fixed margin.

## DNS, log-only (RFC 1035)

- Listen on UDP 53 (and optionally TCP 53). Parse the header and the first
  question (bounded name length and label count).
- Never resolve, recurse or forward. Answer REFUSED with the question copied
  and no other records, so the reply is the same size as the query. AXFR /
  IXFR over TCP gets REFUSED and is reported at high severity.
- Report `dns_query` with query name, type and class (subject to the
  limiter).

## Triggers

`snmp_query`, `dns_query`. Both are already in Doppel's ATT&CK table.
