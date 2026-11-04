# v10 sealed test: how to read it (written after the single run; nothing was changed)

- The pre-stated rule is met: v10 session FA is lower than v9 on S1 (ClarkNet .0049 -> .0046) and S2 (USask .0069 -> .0068).
- The gain is very small, and it does NOT test the main v10 change. ClarkNet, USask and NASA are Common Log Format
  logs with no user agent field (share of rows with a user agent: 0.0 in both S1 and S2; checked on the converted
  files after the run). On these logs v10 falls back to one visitor = one IP, exactly like v9. The small gain comes
  from the new detector and the no-size rule. This was a weakness in choosing S1/S2 and is reported as one.
- secrepo (S5) has user agents (99.9%) and gives the same session FA for v9 and v10 (.1011); its "normal" rows include
  real scanners the payload rules did not label, so this number is an upper bound, not a clean FA.
- The large session-FA gains (reverse-proxy sites .75-.87 -> .26-.39, ModSec-WP .578 -> .005) were measured on dev
  logs that were also used to find the problem (results/final_v10/dev). They are optimistic and not sealed evidence.
- S6 (lab) was dropped (Amendment 2); lab and AIT numbers are dev checks only (Amendment 3).
- v10 stays frozen at tag v10.0-final-test. A clean test of the visitor split needs new, hashed logs WITH user agents
  behind a proxy or NAT (future work).
