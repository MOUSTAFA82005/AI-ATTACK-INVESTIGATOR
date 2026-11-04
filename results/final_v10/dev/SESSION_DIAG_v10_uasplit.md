# v10 dev: why the session layer flags normal traffic (v9 models, aggregates only)

## Summary
| group | requests | normal | session FA | payload FA | normal sessions | flagged normal sessions | median requests per flagged session |
|---|---|---|---|---|---|---|---|
| indonesia 3 (1635 IPs) | 21926 | 21920 | 0.188 | 0.0048 | 7631 | 75 | 55.0 |
| indonesia 5 (6 IPs) | 50000 | 50000 | 0.262 | 0.0004 | 238 | 10 | 935.0 |
| indonesia 13 (3 IPs) | 50000 | 49997 | 0.319 | 0.0 | 470 | 9 | 378.0 |
| indonesia 17 (864 IPs) | 105925 | 105785 | 0.441 | 0.003 | 4041 | 108 | 125.0 |
| indonesia 20 (3 IPs) | 50000 | 49905 | 0.369 | 0.0007 | 975 | 28 | 67.0 |
| modsecwp | 108883 | 12597 | 0.005 | 0.0098 | 40 | 2 | 30.0 |
| zanbil 10.0M | 100000 | 100000 | 0.0 | 0.0001 | 3418 | 1 | 12.0 |

## Behaviour of flagged normal requests (share)
| group | scan | bruteforce | enumeration |
|---|---|---|---|
| indonesia 3 (1635 IPs) | 1.0 | 0.0 | 0.0 |
| indonesia 5 (6 IPs) | 0.149 | 0.851 | 0.0 |
| indonesia 13 (3 IPs) | 0.174 | 0.826 | 0.0 |
| indonesia 17 (864 IPs) | 0.778 | 0.221 | 0.0 |
| indonesia 20 (3 IPs) | 0.38 | 0.62 | 0.0 |
| modsecwp | 0.0 | 1.0 | 0.0 |
| zanbil 10.0M | 0.0 | 0.0 | 1.0 |

## Shared addresses (one IP, many user agents)
| group | top IP share | top IP distinct UAs | IPs with >=20 UAs | share of requests from IPs with >=20 UAs | session FA on those IPs | session FA on other IPs |
|---|---|---|---|---|---|---|
| indonesia 3 (1635 IPs) | 0.183 | 1 | 13 | 0.043 | 0.0 | 0.196 |
| indonesia 5 (6 IPs) | 0.94 | 97 | 1 | 0.94 | 0.279 | 0.0 |
| indonesia 13 (3 IPs) | 0.958 | 195 | 1 | 0.958 | 0.333 | 0.0 |
| indonesia 17 (864 IPs) | 0.111 | 1 | 7 | 0.02 | 0.167 | 0.447 |
| indonesia 20 (3 IPs) | 0.95 | 360 | 1 | 0.95 | 0.389 | 0.0 |
| modsecwp | 0.781 | 12 | 0 | 0.0 |  | 0.005 |
| zanbil 10.0M | 0.046 | 1 | 0 | 0.0 |  | 0.0 |

## Context features: flagged normal vs unflagged normal (median)
| feature | indonesia 13 (3 IPs) | indonesia 17 (864 IPs) | indonesia 20 (3 IPs) | indonesia 3 (1635 IPs) | indonesia 5 (6 IPs) | modsecwp | zanbil 10.0M |
|---|---|---|---|---|---|---|---|
| answer_pages_log | 0.0 | 0.946 | 0.0 | 0.655 | 0.0 | 0.0 | 0.017 |
| attempts_this_form | 5849.0 | 0.0 | 10941.0 | 0.0 | 2680.0 | 44.0 | 0.0 |
| form_same_answer | 5849.0 | 0.0 | 10927.0 | 0.0 | 2680.0 | 44.0 | 0.0 |
| form_values | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.693 | 0.0 |
| ids_this_resource | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 20.0 |
| ids_vs_typical | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1.658 |
| page_popularity | 0.755 | 0.264 | 0.118 | 0.224 | 0.522 | 0.659 | 0.27 |
| password_field | 1.0 | 0.0 | 1.0 | 0.0 | 1.0 | 1.0 | 0.0 |
| payload_score | 1.0 | 0.0 | 1.0 | 0.0 | 1.0 | 0.0 | 0.0 |
| s_max_ids | 5.0 | 2.0 | 0.0 | 0.0 | 0.0 | 0.0 | 20.0 |
| s_mean_popularity | 0.706 | 0.494 | 0.118 | 0.249 | 0.522 | 0.463 | 0.27 |
| s_pages | 5.011 | 6.201 | 0.693 | 4.025 | 0.693 | 1.386 | 0.693 |
| s_requests | 8.742 | 7.566 | 9.3 | 4.025 | 7.894 | 5.342 | 3.367 |
| s_top_answer_share | 0.842 | 0.937 | 1.0 | 1.0 | 1.0 | 0.333 | 1.0 |
| s_unpopular_share | 0.065 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| same_page_in_session | 5849.0 | 1.0 | 10941.0 | 1.0 | 2680.0 | 44.0 | 1.0 |
| values_vs_typical | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

| feature | indonesia 13 (3 IPs) | indonesia 17 (864 IPs) | indonesia 20 (3 IPs) | indonesia 3 (1635 IPs) | indonesia 5 (6 IPs) | modsecwp | zanbil 10.0M |
|---|---|---|---|---|---|---|---|
| answer_pages_log | 0.002 | 0.0 | 0.0 | 0.655 | 0.0 | 0.002 | 0.004 |
| attempts_this_form | 0.0 | 0.0 | 0.0 | 0.0 | 22783.0 | 0.0 | 0.0 |
| form_same_answer | 0.0 | 0.0 | 0.0 | 0.0 | 22654.0 | 0.0 | 0.0 |
| form_values | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| ids_this_resource | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| ids_vs_typical | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| page_popularity | 0.637 | 0.529 | 0.118 | 0.904 | 0.522 | 0.416 | 0.826 |
| password_field | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 | 0.0 | 0.0 |
| payload_score | 1.0 | 1.0 | 0.0 | 0.0 | 1.0 | 0.0 | 0.0 |
| s_max_ids | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 |
| s_mean_popularity | 0.295 | 0.53 | 0.235 | 0.904 | 0.522 | 0.422 | 0.769 |
| s_pages | 1.386 | 1.386 | 2.303 | 1.099 | 1.609 | 4.663 | 3.296 |
| s_requests | 9.783 | 7.189 | 7.63 | 1.946 | 10.034 | 7.03 | 4.691 |
| s_top_answer_share | 0.333 | 0.4 | 0.444 | 1.0 | 0.25 | 0.333 | 0.139 |
| s_unpopular_share | 0.333 | 0.0 | 0.0 | 0.0 | 0.0 | 0.007 | 0.002 |
| same_page_in_session | 5911.0 | 905.0 | 575.0 | 3.0 | 22783.0 | 515.0 | 1.0 |
| values_vs_typical | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |