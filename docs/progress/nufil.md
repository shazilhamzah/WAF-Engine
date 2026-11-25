# Progress — Nufil (member B: security engine / evaluation fixtures)

Owns `src/engine/**`, `src/rules/**`, benign fixtures in `fixtures/`, `test/unit/engine/**`,
`docs/rule-dsl.md`, `docs/engine.md`, `docs/fixtures.md`.

## Log

| Date | Entry |
|---|---|
| 2026-10-19 | Read Proposal 44, `docs/00-project-plan.md`, `docs/01-requirements.md` and the integration contract `docs/02-architecture.md` (§1.2 pipeline, §3 engine interface, §3.4 exceptions, §3.5 locations, §3.6 Decision, §3.7 DSL) |
| 2026-11-25 | Closed two T5 misses with Claude's help (automated session, same disclosure as below): 942100 now accepts hex literals (T5-16 `OR 0x31=0x31`) and 942110 a quote break-out with a `\|\|` concatenation comparison (T5-17). Patterns only gained alternatives; expected verdicts unchanged; T3/benign corpus still fully allowed; new `tautology-variants.test.js`. T5-13/14/15/18 stay documented as out of scope (`limitations-and-ethics.md` §3, `engine.md` §4.1); the Oct-19 evaluation snapshot was not regenerated. |

## Handover reconciliation and completion - 2026-10-20

This update records integration continuation of Nufil's engine workstream (B), which was produced
with Claude's help; it does not imply a human team member independently authored the automated
work. The first Claude attempt at this workstream stopped without implementation. A second attempt
delivered `src/engine/`, 41 rules, benign fixtures, engine tests,
`rule-dsl.md`, `engine.md` and `fixtures.md`, then hit the Claude session limit. The traversal score
fix (930105=5) and parser variant-test fix were already present at handover and pass current tests.

The missing follow-up is now complete: T1=28 (10 SQLi/10 XSS/8 traversal), T2=20, T5=18 and adverse
corpus=80, generated deterministically by `scripts/build-attack-fixtures.js`. There are 51 additional
fixture regression tests. T1/T2 all block; T3 and the benign corpus remain allowed. Six T5 misses
retain expected block and limitation explanations; four are also corpus false negatives. Controlled
corpus recall is 95%, with zero benign false positives. Full evidence: `../evaluation/results.md`.

No signature rule was weakened or adverse expected verdict relabelled to pass. Cross-field/base64
cases depend on application interpretation and are not confirmed exploits of the bundled shop.
Remaining detection boundaries are accepted limitations in `../limitations-and-ethics.md`.
