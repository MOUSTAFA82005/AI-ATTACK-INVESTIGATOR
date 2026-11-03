# run7: test rules, written before the test exists (fixed 3 Nov 2026, at tag v8.0-final-test)

These rules are fixed before run7 is generated. Nothing in them may change after anyone has looked at run7 data or results. If a rule turns out wrong, the change and the reason go in the report next to the result. The result is never re-run.

## 1. What is frozen before run7

- **Code:** a git tag `v8.0-final-test` on the commit that holds:
  - every model file the pipeline uses;
  - every training script;
  - this file.
- **Models:** the SHA-256 of every file in `models/` is written into `results/final_v8/models.sha256` at the tag.
- **After the tag:** no change to code, features, thresholds or models until the final results are written.

## 2. What run7 contains

| Part | Content | Why |
|---|---|---|
| Lab sites already used | The 7 lab sites (Juice Shop, DVWA, bWAPP, Mutillidae, DVNA, VAmPI, DVGA), a generator seed never used before. | Same sites, new traffic. |
| One unseen site | One application never in any training or dev data. Proposed: OWASP WebGoat; Elsharawy picks, and the name is written here before generation. Its generator spec (pages, forms, accounts) is written only from the app's own pages. No model is run on it before the final run. | Generalization to a new site. |
| Sealed tools | gobuster, wfuzz, medusa, dalfox and feroxbuster, at their default settings, against every site. None of them has ever been run in this project. | Generalization to new attack tools. |
| Real traffic | zanbil lines 9,000,000 to 9,200,000 (never read). Five days of the real secrepo.com access log, downloaded by Safi on 2 Nov and hashed unopened: `/mnt/project-files/sealed/secrepo_run7/hashes_reported.txt`. Three other secrepo days and NASA Jul 1995 are dev data. | False alarms and hand-labelled precision on real traffic, including real scanners. |
| Demo backup | bak62 stays sealed for the demo and is not part of run7. | |

- **Before the final run:** every run7 file is hashed (SHA-256) as soon as it is written. The hashes are committed before anyone runs a model on the files.
- **Labels:** the generator writes them. The tool runs are labelled by IP: the tool's IP is the attack, everything else is normal.

## 3. What is reported (all of it, whatever it shows)

The baseline is rules + rule sessions. Every table has the ML pipeline and this baseline side by side.

1. **Lab sites, seen and unseen:** per site, recall on attacks, false alarms on normal users, false alarms inside attacker sessions, attack-type accuracy and stage accuracy.
2. **Sealed tools:** per tool and site, the share of the tool's requests caught, normal users flagged next to it, and the defence action given to the tool's session.
3. **Real logs:** the share of requests flagged.
4. **Hand-labelled precision:** a random sample of up to 200 flagged requests per real log, judged attack / not attack / unclear. The criteria in section 4 are fixed now. A second person labels 50 of them to check agreement. Precision is reported with a 95% interval.
5. **Next step:** top-1 and top-3, shown next to the ceiling of 0.38 that the generator's random choice allows.

## 4. Hand-labelling criteria (fixed now)

- **Attack:** the request carries attack syntax aimed at the server (SQL, script, traversal, command, template, injected markup). Or it probes for files or admin pages that no page of the site links to, in a pattern a scanner uses. Or it is one of many failed logins in a row.
- **Not attack:** an ordinary page, asset, search or form use, even if odd (typos, long values, non-Latin text, unusual characters in a product name).
- **Unclear:** cannot be decided from the log line. Counted apart from the other two, never as attack.
- **Who labels:** the labeller sees the request and its session only, not the model's verdict or score.

## 5. What counts as a result

No pass/fail threshold is tuned to the data. The report states:

- whether the ML pipeline beats the rules baseline on each part;
- every part where it does not, with the number.

A loss on a part is reported as a loss; it is not fixed and re-run.

## Amendment 1 (3 Nov 2026, before any run7 file exists)

Safi generates run7, not Elsharawy. The models were trained before this, at tag `v8.0-final-test`, and they stay frozen.

What keeps the test independent:

- The generator seed was never used before.
- The tools were never run in this project.
- Every file is hashed as soon as it is written.
- The hashes are committed before any model reads the files.
- No file is opened except to count its lines.

The unseen site keeps its rule: it is named here before its generator spec is written, and no model is run on it before the final run.

## Amendment 2 (3 Nov 2026, sealed tool runs, before any model reads them)

Written after the tool runs and before any model has read their files. Only the tools' own messages were read, never the logs.

- **dalfox, second pass:** the first pass on DVWA, bWAPP and DVNA used the wrong cookie flag (`--cookie`) and sent no requests. Those three runs were redone with `--cookies`, and their files were replaced.
- **medusa** runs on bWAPP and Mutillidae only:
  - Juice Shop, VAmPI and DVGA log in with JSON, and medusa's web-form module sends form fields only.
  - DVWA and DVNA answer every login with a 302 redirect, right or wrong password. The web-form module cannot read that answer and stops after one try. The two 2-line files from that try were removed. No traffic was made by hand to stand in for them.
- **gobuster on Juice Shop** stopped by itself after 2 requests, because Juice Shop answers every path with 200 (catch-all). The file is kept as it is, with default settings.
- **Hashes:**
  - First pass: `run7_tools_hashes_first.txt`.
  - Final set: `run7_tools_hashes.txt`, 30 files.
  - Run notes: `run7_tools_runs.txt`.

## Amendment 3 (3 Nov 2026, before any WebGoat spec or traffic exists)

- **Unseen site:** OWASP WebGoat, a Java/Spring app with form login and lesson pages. Safi chose it.
- **Why it is a fair test:** none of the 7 training sites uses this stack.
- **How its generator spec is written:** only from WebGoat's own pages and forms, with no model run on it.
- **When models first see it:** in the single final run7 evaluation. WebGoat traffic is generated with seed 7007 and tag run7, and hashed as soon as it is written, like the other run7 files.
