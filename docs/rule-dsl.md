# WAF Studio Rule DSL

Owner: Nufil (member B). Implements **FR-2**: rules are written in this documented language, invalid
rules are rejected with line/column errors, unsafe regular expressions are refused, and every rule
carries a version (the `version` of its stored record, see `rule_versions` in the data model).

Code: `src/engine/dsl.js` (lexer, parser, validator, compiler), `src/engine/regexguard.js` (ReDoS
guard), `src/engine/evaluate.js` (runtime semantics). Default rules: `src/rules/default.rules`.

## 1. A rule at a glance

```
rule 942100 "SQLi boolean tautology" {
  when args matches /\b(or|and)\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i
  severity critical
  score 5
  category sqli
  tags sqli, owasp-a03
  description "Tautology used to bypass WHERE clauses"
}
```

Read it as: *when any argument value, in any normalized form, matches this pattern, add 5 points to
the request's score under category `sqli` and explain why.*

## 2. Grammar (EBNF)

```ebnf
file        = { comment | rule } ;
rule        = "rule" rule-id string "{" { clause } "}" ;
rule-id     = integer ;                              (* 1000 … 999999 *)
clause      = "when" expr
            | "severity" ( "low" | "medium" | "high" | "critical" )
            | "score" integer                        (* 0 … 100 *)
            | "category" word                        (* [a-z][a-z0-9_-]{0,31} *)
            | "tags" tag { "," tag }                 (* ≤ 16 tags *)
            | "description" string ;                 (* ≤ 500 chars *)

expr        = and-expr { "or" and-expr } ;
and-expr    = not-expr { "and" not-expr } ;
not-expr    = "not" not-expr | "(" expr ")" | condition ;
condition   = target { "," target } operator ;
target      = "path" | "path_raw" | "query" | "args" | "arg_names" | "body"
            | "headers" | "header" ":" header-name | "cookies" | "method"
            | "user_agent" | "content_type" | "body_size" ;
operator    = "matches" regex
            | ( "contains" | "startswith" | "endswith" ) string
            | "equals" ( string | integer )
            | "in" "[" literal { "," literal } "]"   (* ≤ 200 items, all of one type *)
            | ( "gt" | "lt" | "ge" | "le" ) integer ;

regex       = "/" pattern "/" [ flags ] ;            (* flags ⊆ i m s u, no repeats *)
string      = '"' { char | "\\" ( '"' | "\\" | "n" | "t" | "r" ) } '"' ;   (* single line, ≤ 1000 chars *)
integer     = [ "-" ] digit { digit } ;
word, tag, header-name = letter-or-_ { letter | digit | "_" | "-" } ;
comment     = "#" { any char except newline } ;
```

* Required clauses: `when`, `severity`, `score`, `category`. `tags` and `description` are optional
  (every default rule has both). Clause order is free; each clause may appear once.
* `and` binds tighter than `or`; use parentheses for clarity. Maximum nesting depth 32, maximum 64
  conditions per rule.
* One rule per stored record (`validateRuleSource`); a `.rules` file may hold many
  (`parseRuleFile`). In a file, each rule starts on a line beginning with `rule`; only comments and
  blank lines may appear between rules. Maximum source length: 10 000 characters per rule,
  1 MiB per file.

## 3. Targets

Each target is a list of *fields*. Every field has a **location** (contract §3.5) that appears in the
evidence, and a list of normalization **variants** (raw value first, then decoded forms — see
`docs/engine.md` §3).

| Target | Fields (location) | Notes |
|---|---|---|
| `path` | the URL path (`path`) | variants include URL-decoded and canonicalized (`/a/../b` → `/b`) forms |
| `path_raw` | the URL path exactly as received (`path`) | no decoding; use for encoding-specific signatures |
| `query` | each query parameter value (`query.<name>`) | |
| `args` | query values + body field values (`query.<name>`, `body.<name>`) | if the body has no fields (text, binary, invalid JSON) the raw body (`body`) is used instead |
| `arg_names` | query and body parameter names (`query_names`, `body_names`) | JSON keys are dotted (`user.address.city`) |
| `body` | the inspected part of the raw body (`body`) | |
| `headers` | every header value except `Cookie` (`header.<name>`) | |
| `header:<name>` | one header (`header.<name>`) | name is case-insensitive; a missing header has no values |
| `cookies` | each cookie value (`cookie.<name>`) | |
| `method` | the HTTP method (`method`) | context only (see §6) |
| `user_agent` | `header.user-agent` | |
| `content_type` | `header.content-type` | |
| `body_size` | total body size in bytes (`body`) | numeric target |

A condition may list several targets: `when args, cookies, user_agent matches /…/` is true when any
of them matches.

## 4. Operators

| Operator | Operand | True when (for some field, some variant) |
|---|---|---|
| `matches` | `/regex/flags` | the regex finds a match (flags `i m s u`; `g`/`y` are refused) |
| `contains` | string | the value contains the string (case-insensitive) |
| `equals` | string | the whole value equals the string (case-insensitive) |
| `equals` | integer | `body_size` equals the number |
| `startswith` / `endswith` | string | prefix / suffix (case-insensitive) |
| `in` | list | the value equals one of the list items (case-insensitive) / `body_size` is one of the numbers |
| `gt` `lt` `ge` `le` | integer | `body_size` compared with the number; for text targets the **length of the raw value** is compared (e.g. `args gt 4096` = an over-long argument) |
| `not` | expression | the expression is false |

Type rules: `body_size` only accepts `equals`/`in` with numbers and the four comparisons; text
targets reject numeric `equals`/`in` (write `"5"` to compare text).

## 5. Semantics

* **Any value, any variant.** A condition holds if *any* field of the target, in *any* normalization
  variant, satisfies the operator. Variants are tried in order (raw first), so the evidence reports
  the **fewest** decoding steps needed (`decodedVia`).
* **A rule counts once per request** no matter how many fields match; the match lists every
  matching location in `locations` and reports the first as `location`.
* **`and` short-circuits; `or` evaluates both sides** so all matching locations are known (this
  matters for exceptions: a rule is suppressed only if every location it matched is covered).
* **`not X`** is true when `X` is false. It produces context-only evidence at the target's location
  (e.g. `header.user-agent` for `not header:user-agent matches /\S/`).
* Comparisons on `method` and `body_size` and `not` evidence are *context*; exceptions are scoped
  by the value locations of a match.

## 6. Validation errors

All errors have the shape `{ line, col, message }` (1-based; `compileRules`/`parseRuleFile` add
`ruleId`). Syntax errors stop parsing at the first problem; semantic errors are collected so several
can be shown at once. Examples:

| Class | Example input | Message |
|---|---|---|
| Unknown keyword | `severty low` | `Unknown keyword 'severty' — did you mean 'severity'? (expected one of: when, severity, …)` |
| Unknown target | `when argz contains "a"` | `Unknown target 'argz' — did you mean 'args'? (targets: …)` |
| Unknown operator | `when args matchez /a/` | `Unknown operator 'matchez' — did you mean 'matches'? (operators: …)` |
| Missing field | no `score` clause | `Missing required 'score' clause in rule 5000` (at the closing `}`) |
| Duplicate clause | two `severity` lines | `Duplicate 'severity' clause (first given at line 3)` |
| Severity enum | `severity huge` | `Unknown severity 'huge' — did you mean 'high'? (allowed: low, medium, high, critical)` |
| Score range | `score 500` | `Score must be an integer between 0 and 100 (got 500)` |
| Id range | `rule 12 …` | `Rule id must be an integer between 1000 and 999999 (got 12)` |
| Category / tag syntax | `category SQLi` | `Category must be lower-case letters, digits, _ or - (max 32 characters)` |
| Type mismatch | `body_size matches /1/` | `Operator 'matches' cannot be used with the numeric target body_size …` |
| Regex compile error | `matches /(a/` | `Invalid regular expression: /(a/: Unterminated group` |
| Regex flags | `matches /a/g` | `Regex flag 'g' is not allowed (allowed flags: i, m, s, u)` |
| Unsafe regex | `matches /(a+)+/` | `Unsafe regular expression: nested quantifiers such as (a+)+ are not allowed …` |
| Lexical | `"abc` / `/abc` / `;` | `Unterminated string …` / `Unterminated regular expression …` / `Unexpected character ';'` |
| Structure | missing `}` | `Missing '}' to close rule 5000 (opened at line 1, column 15)` |
| Several rules in one record | | `Unexpected 'rule' after the end of the rule (one rule per record; …)` |
| Duplicate id | same id twice in `compileRules` / a file | `Duplicate rule id 942100` |
| Id mismatch | record id ≠ source id | `Rule id 5000 in the source does not match the record id 7777` |

## 7. ReDoS policy

Rule regexes run on attacker-controlled input of up to 64 KiB, so a pattern with catastrophic
backtracking would let one request freeze the proxy. Every `matches` pattern is compiled **and**
statically analysed (`src/engine/regexguard.js`). A pattern is refused when it has:

| # | Construct | Example refused | Safe rewrite |
|---|---|---|---|
| R1 | length > 500 characters | — | split into several rules |
| R2 | nested quantifiers: a repeated group that contains a repeated element | `(a+)+`, `(\w+\s?)*`, `(a+){2,9}` | `(?:\w{1,40}\s?){1,20}` (bounded inside **and** outside) or `[\w\s]{1,200}` |
| R3 | overlapping alternatives inside a repeated group (same first atom, empty or `.` alternative) | `(a|a)*`, `(ab|ac)+`, `(a|)*` | `a(?:b|c)` |
| R4 | backreference inside a repetition, or repeated | `(a)\1+`, `((a)\2)*` | avoid backreferences |
| R5 | adjacent unbounded quantifiers over overlapping characters | `.*.*`, `\w+\w*`, `.*\s*` | one quantifier, or bounded ones |

The guard is conservative: some safe patterns are refused, and the message says why. Recommended
style (used by every default rule): prefer **bounded** repetition (`\s{0,10}`, `[^>]{0,200}`) to `*`
and `+`, anchor patterns on a distinctive literal (`<`, `union`, `../`), and keep alternatives
distinct. The default rule set's unit test feeds 64 KiB adversarial bodies (`<<<<…`, `''''…`,
`{{{{…`, `../../…`) to all rules and asserts each request finishes quickly.

## 8. Writing and testing a rule

1. **Decide the indicator and its strength.** Default thresholds are flag = 3, block = 5. Use
   `score 5` only for indicators that are almost never benign; 3–4 for suspicious signals that
   should block only together with another one; 1–2 for context.
2. **Pick the narrowest target.** `args` covers query and body values; add `cookies`, `user_agent`
   or `header:referer` only when the attack really travels there.
3. **Write a bounded regex** and remember that the value is matched in every normalized form —
   you do not need to handle `%27`, `&#39;`, fullwidth characters or `/**/` comments yourself.
4. **Validate** in the console (Rules → Validate, `POST /api/rules/validate`) or in Node:

   ```js
   const engine = require('./src/engine');
   engine.validateRuleSource(source);          // { ok, rule, errors: [{ line, col, message }] }
   ```

5. **Try it on samples** (console Analyze, or):

   ```js
   const { rules } = engine.compileRules([{ id: 5000, source, enabled: true, version: 1 }]);
   const d = engine.inspect({ method: 'GET', url: '/search?q=test', headers: {} }, { rules });
   d.matches; d.explanation;
   ```

6. **Check false positives** against `fixtures/t3-benign.json` and `fixtures/corpus-benign.json`
   (`node --test "test/unit/engine/*.test.js"` runs them with the default set).
7. **Prefer exceptions to disabling.** If a rule misfires on one legitimate field, request a scoped
   exception (rule id + path prefix + location + method) instead of weakening the rule for everyone.

## 9. Examples

```
# A parameter that should only ever be numeric
rule 100100 "Non-numeric product id" {
  when query matches /[^0-9]/ and arg_names equals "id"
  severity low
  score 2
  category protocol
  description "The id parameter of /products is numeric"
}

# Over-long cookie value
rule 100110 "Oversized cookie" {
  when cookies gt 2048
  severity low
  score 2
  category protocol
}

# Admin path from a scripted client
rule 100120 "Scripted access to admin area" {
  when path startswith "/admin" and user_agent matches /^(?:curl|python-requests)/i
  severity medium
  score 3
  category scanner
  tags recon
}

# Large JSON upload
rule 100130 "Large JSON body" {
  when content_type contains "json" and body_size gt 500000
  severity low
  score 1
  category protocol
}
```

(Note on the first example: conditions are evaluated independently, so `query matches …` looks at
every query value, not only `id`. Field-scoped conditions are a possible future extension.)
