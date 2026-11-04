# v10 dev: why the session layer flags normal traffic (v9 models, aggregates only)

## Summary
| group | requests | normal | session FA | payload FA | normal sessions | flagged normal sessions | median requests per flagged session |
|---|---|---|---|---|---|---|---|
| indonesia 3 (1635 IPs) | 21926 | 21920 | 0.188 | 0.0048 | 7554 | 75 | 55.0 |
| indonesia 5 (6 IPs) | 50000 | 50000 | 0.262 | 0.0004 | 194 | 10 | 939.0 |
| indonesia 13 (3 IPs) | 50000 | 49997 | 0.39 | 0.0 | 337 | 18 | 8.5 |
| indonesia 17 (864 IPs) | 105925 | 105785 | 0.376 | 0.003 | 3638 | 109 | 125.0 |
| indonesia 20 (3 IPs) | 50000 | 49905 | 0.392 | 0.0007 | 745 | 28 | 52.5 |
| modsecwp | 108883 | 12597 | 0.005 | 0.0098 | 40 | 3 | 16.0 |
| zanbil 10.0M | 100000 | 100000 | 0.0 | 0.0001 | 3411 | 1 | 12.0 |

## Behaviour of flagged normal requests (share)
| group | scan | bruteforce | enumeration |
|---|---|---|---|
| indonesia 3 (1635 IPs) | 1.0 | 0.0 | 0.0 |
| indonesia 5 (6 IPs) | 0.15 | 0.85 | 0.0 |
| indonesia 13 (3 IPs) | 0.147 | 0.853 | 0.0 |
| indonesia 17 (864 IPs) | 0.74 | 0.26 | 0.0 |
| indonesia 20 (3 IPs) | 0.327 | 0.673 | 0.0 |
| modsecwp | 0.118 | 0.882 | 0.0 |
| zanbil 10.0M | 0.0 | 0.0 | 1.0 |

## Shared addresses (one IP, many user agents)
| group | top IP share | top IP distinct UAs | IPs with >=20 UAs | share of requests from IPs with >=20 UAs | session FA on those IPs | session FA on other IPs |
|---|---|---|---|---|---|---|
| indonesia 3 (1635 IPs) | 0.183 | 1 | 13 | 0.043 | 0.0 | 0.196 |
| indonesia 5 (6 IPs) | 0.94 | 97 | 1 | 0.94 | 0.279 | 0.0 |
| indonesia 13 (3 IPs) | 0.958 | 195 | 1 | 0.958 | 0.407 | 0.0 |
| indonesia 17 (864 IPs) | 0.111 | 1 | 7 | 0.02 | 0.167 | 0.38 |
| indonesia 20 (3 IPs) | 0.95 | 360 | 1 | 0.95 | 0.412 | 0.0 |
| modsecwp | 0.781 | 12 | 0 | 0.0 |  | 0.005 |
| zanbil 10.0M | 0.046 | 1 | 0 | 0.0 |  | 0.0 |

## Context features: flagged normal vs unflagged normal (median)
| feature | indonesia 13 (3 IPs) | indonesia 17 (864 IPs) | indonesia 20 (3 IPs) | indonesia 3 (1635 IPs) | indonesia 5 (6 IPs) | modsecwp | zanbil 10.0M |
|---|---|---|---|---|---|---|---|
| answer_pages_log | 0.0 | 0.946 | 0.0 | 0.655 | 0.0 | 0.0 | 0.017 |
| attempts_this_form | 14579.0 | 0.0 | 12637.0 | 0.0 | 2680.0 | 44.0 | 0.0 |
| form_same_answer | 11794.0 | 0.0 | 12635.0 | 0.0 | 2680.0 | 44.0 | 0.0 |
| form_values | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.693 | 0.0 |
| ids_this_resource | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 20.0 |
| ids_vs_typical | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1.658 |
| page_popularity | 0.67 | 0.218 | 0.0 | 0.226 | 0.429 | 0.547 | 0.27 |
| password_field | 1.0 | 0.0 | 1.0 | 0.0 | 1.0 | 1.0 | 0.0 |
| payload_score | 1.0 | 0.0 | 1.0 | 0.0 | 1.0 | 0.0 | 0.0 |
| s_max_ids | 20.0 | 2.0 | 20.0 | 0.0 | 0.0 | 0.0 | 20.0 |
| s_mean_popularity | 0.649 | 0.428 | 0.032 | 0.251 | 0.429 | 0.418 | 0.27 |
| s_pages | 5.529 | 5.541 | 6.201 | 4.025 | 0.693 | 1.386 | 0.693 |
| s_requests | 9.973 | 7.566 | 9.582 | 4.025 | 7.894 | 5.342 | 3.367 |
| s_top_answer_share | 0.566 | 0.995 | 0.417 | 1.0 | 1.0 | 0.333 | 1.0 |
| s_unpopular_share | 0.023 | 0.0 | 0.935 | 0.0 | 0.0 | 0.0 | 0.0 |
| same_page_in_session | 20504.0 | 1.0 | 12637.0 | 1.0 | 2680.0 | 44.0 | 1.0 |
| values_vs_typical | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

| feature | indonesia 13 (3 IPs) | indonesia 17 (864 IPs) | indonesia 20 (3 IPs) | indonesia 3 (1635 IPs) | indonesia 5 (6 IPs) | modsecwp | zanbil 10.0M |
|---|---|---|---|---|---|---|---|
| answer_pages_log | 0.002 | 0.0 | 0.0 | 0.655 | 0.0 | 0.002 | 0.004 |
| attempts_this_form | 0.0 | 0.0 | 0.0 | 0.0 | 23164.0 | 0.0 | 0.0 |
| form_same_answer | 0.0 | 0.0 | 0.0 | 0.0 | 23035.0 | 0.0 | 0.0 |
| form_values | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| ids_this_resource | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| ids_vs_typical | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| page_popularity | 0.642 | 0.566 | 0.0 | 0.91 | 0.429 | 0.373 | 0.826 |
| password_field | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 | 0.0 | 0.0 |
| payload_score | 1.0 | 0.0 | 0.0 | 0.0 | 1.0 | 0.0 | 0.0 |
| s_max_ids | 1.0 | 1.0 | 2.0 | 0.0 | 1.0 | 1.0 | 1.0 |
| s_mean_popularity | 0.272 | 0.567 | 0.216 | 0.91 | 0.429 | 0.378 | 0.769 |
| s_pages | 1.609 | 1.386 | 3.584 | 1.099 | 3.466 | 4.663 | 3.296 |
| s_requests | 9.783 | 7.284 | 7.633 | 1.946 | 10.056 | 7.03 | 4.691 |
| s_top_answer_share | 0.25 | 0.75 | 0.385 | 1.0 | 0.097 | 0.333 | 0.14 |
| s_unpopular_share | 0.333 | 0.0 | 0.503 | 0.0 | 0.0 | 0.009 | 0.002 |
| same_page_in_session | 5911.0 | 674.0 | 443.0 | 3.0 | 23166.0 | 515.0 | 1.0 |
| values_vs_typical | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |