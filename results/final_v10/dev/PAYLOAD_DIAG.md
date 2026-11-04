# v10 dev: payload detector on ModSec-WP (v9 model, aggregates only)

| rows | n | flag@0.5 | flag@0.7 | flag@0.8 | share with any signal | median proba |
|---|---|---|---|---|---|---|
| normal login POSTs | 81 | 0.988 | 0.988 | 0.988 | 1.0 | 0.939 |
| normal, other | 12516 | 0.185 | 0.14 | 0.138 | 0.403 | 0.026 |
| bruteforce login POSTs | 488 | 1.0 | 1.0 | 1.0 | 1.0 | 0.985 |
| rce | 11740 | 0.915 | 0.887 | 0.874 | 0.967 | 1.0 |
| sqli | 69631 | 0.989 | 0.984 | 0.983 | 0.992 | 1.0 |
| xss | 8625 | 0.969 | 0.951 | 0.95 | 0.98 | 1.0 |
| fileinclusion | 6290 | 0.969 | 0.952 | 0.938 | 0.99 | 0.975 |

| rows | top signals (share of rows) |
|---|---|
| normal login POSTs | p_probe_path 1.00, v_kw_total 1.00, v_kw_ssrf 0.99 |
| normal, other | v_kw_total 0.39, p_probe_path 0.28, v_ctx_brace 0.12, v_kw_ssrf 0.11, v_sql_comment 0.01, v_crlf 0.01, v_kw_xss 0.00, v_ctx_quote 0.00 |
| bruteforce login POSTs | p_probe_path 1.00, v_kw_ssrf 1.00, v_kw_total 1.00 |
| rce | v_ctx_tag 0.67, v_crlf 0.62, v_kw_total 0.36, p_probe_path 0.35, v_kw_cmd 0.16, v_ctx_call 0.12, v_ctx_quote 0.11, v_ctx_shell 0.08 |
| sqli | v_kw_total 0.96, v_kw_sql 0.94, v_ctx_call 0.88, v_ctx_quote 0.83, v_tautology 0.72, v_sql_comment 0.22, v_ctx_shell 0.12, v_kw_cmd 0.11 |
| xss | v_kw_total 0.95, v_kw_xss 0.95, v_ctx_tag 0.93, v_ctx_call 0.88, v_ctx_quote 0.62, v_ctx_attr_break 0.40, v_chr_backslash 0.10, v_ctx_shell 0.06 |
| fileinclusion | v_kw_total 0.99, p_probe_path 0.91, v_kw_trav 0.86, double_encoded 0.06, v_kw_cmd 0.05, v_kw_ssrf 0.05, v_chr_backslash 0.05, v_kw_ssti 0.03 |

## RCE: signals in missed vs caught rows
| signal | missed rce | caught rce |
|---|---|---|
| v_kw_total | 0.705 | 0.319 |
| p_probe_path | 0.702 | 0.303 |
| v_kw_cmd | 0.289 | 0.144 |
| v_ctx_call | 0.047 | 0.128 |
| v_ctx_shell | 0.035 | 0.088 |
| v_ctx_tag | 0.0 | 0.752 |
| v_ctx_quote | 0.0 | 0.125 |
| v_crlf | 0.0 | 0.697 |

## v8 vs v9 on the same rows (row order differs: skipped)
