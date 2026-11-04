# v10 dev: why the session layer flags normal traffic (v9 models, aggregates only)

## Summary
| group | requests | normal | session FA | payload FA | normal sessions | flagged normal sessions | median requests per flagged session |
|---|---|---|---|---|---|---|---|
| indonesia 3 (1635 IPs) | 21926 | 21920 | 0.212 | 0.0057 | 6470 | 93 | 50.0 |
| indonesia 5 (6 IPs) | 50000 | 50000 | 0.867 | 0.0004 | 4 | 2 | 21685.5 |
| indonesia 13 (3 IPs) | 50000 | 49997 | 0.75 | 0.0 | 4 | 1 | 37478.0 |
| indonesia 17 (864 IPs) | 105925 | 105785 | 0.366 | 0.0029 | 2355 | 145 | 42.0 |
| indonesia 20 (3 IPs) | 50000 | 49905 | 0.846 | 0.0007 | 4 | 2 | 21114.0 |
| modsecwp | 108883 | 12597 | 0.578 | 0.1276 | 32 | 14 | 413.0 |
| zanbil 10.0M | 100000 | 100000 | 0.0 | 0.0001 | 3243 | 1 | 12.0 |

## Behaviour of flagged normal requests (share)
| group | scan | bruteforce | enumeration |
|---|---|---|---|
| indonesia 3 (1635 IPs) | 1.0 | 0.0 | 0.0 |
| indonesia 5 (6 IPs) | 0.178 | 0.822 | 0.0 |
| indonesia 13 (3 IPs) | 0.586 | 0.414 | 0.0 |
| indonesia 17 (864 IPs) | 0.78 | 0.219 | 0.0 |
| indonesia 20 (3 IPs) | 0.423 | 0.577 | 0.0 |
| modsecwp | 0.989 | 0.011 | 0.0 |
| zanbil 10.0M | 0.0 | 0.0 | 1.0 |

## Shared addresses (one IP, many user agents)
| group | top IP share | top IP distinct UAs | IPs with >=20 UAs | share of requests from IPs with >=20 UAs | session FA on those IPs | session FA on other IPs |
|---|---|---|---|---|---|---|
| indonesia 3 (1635 IPs) | 0.183 | 1 | 13 | 0.043 | 0.559 | 0.197 |
| indonesia 5 (6 IPs) | 0.94 | 97 | 1 | 0.94 | 0.923 | 0.0 |
| indonesia 13 (3 IPs) | 0.958 | 195 | 1 | 0.958 | 0.783 | 0.0 |
| indonesia 17 (864 IPs) | 0.111 | 1 | 7 | 0.02 | 0.586 | 0.362 |
| indonesia 20 (3 IPs) | 0.95 | 360 | 1 | 0.95 | 0.891 | 0.0 |
| modsecwp | 0.781 | 12 | 0 | 0.0 |  | 0.578 |
| zanbil 10.0M | 0.046 | 1 | 0 | 0.0 |  | 0.0 |

## Context features: flagged normal vs unflagged normal (median)
| feature | indonesia 13 (3 IPs) | indonesia 17 (864 IPs) | indonesia 20 (3 IPs) | indonesia 3 (1635 IPs) | indonesia 5 (6 IPs) | modsecwp | zanbil 10.0M |
|---|---|---|---|---|---|---|---|
| answer_pages_log | 0.001 | 0.946 | 0.0 | 0.655 | 0.0 | 0.702 | 0.017 |
| attempts_this_form | 0.0 | 0.0 | 23664.0 | 0.0 | 35642.0 | 0.0 | 0.0 |
| form_same_answer | 0.0 | 0.0 | 23647.0 | 0.0 | 35381.0 | 0.0 | 0.0 |
| form_values | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1.099 | 0.0 |
| ids_this_resource | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 20.0 |
| ids_vs_typical | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1.658 |
| page_popularity | 0.0 | 0.205 | 0.0 | 0.187 | 0.0 | 0.356 | 0.272 |
| password_field | 0.0 | 0.0 | 1.0 | 0.0 | 1.0 | 0.0 | 0.0 |
| payload_score | 1.0 | 0.0 | 1.0 | 0.0 | 1.0 | 0.0 | 0.0 |
| s_max_ids | 20.0 | 2.0 | 24.0 | 0.0 | 5.0 | 1.0 | 20.0 |
| s_mean_popularity | 0.022 | 0.443 | 0.053 | 0.187 | 0.052 | 0.343 | 0.272 |
| s_pages | 7.12 | 6.284 | 8.868 | 4.043 | 6.907 | 5.063 | 0.693 |
| s_requests | 10.727 | 7.566 | 10.67 | 4.06 | 10.629 | 6.941 | 3.367 |
| s_top_answer_share | 0.697 | 0.992 | 0.572 | 0.989 | 0.799 | 0.976 | 1.0 |
| s_unpopular_share | 0.978 | 0.0 | 0.947 | 0.0 | 0.948 | 0.169 | 0.0 |
| same_page_in_session | 27383.0 | 1.0 | 23664.0 | 1.0 | 35663.0 | 103.0 | 1.0 |
| values_vs_typical | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

| feature | indonesia 13 (3 IPs) | indonesia 17 (864 IPs) | indonesia 20 (3 IPs) | indonesia 3 (1635 IPs) | indonesia 5 (6 IPs) | modsecwp | zanbil 10.0M |
|---|---|---|---|---|---|---|---|
| answer_pages_log | 0.002 | 0.0 | 0.003 | 0.655 | 0.003 | 0.702 | 0.004 |
| attempts_this_form | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| form_same_answer | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| form_values | 0.693 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| ids_this_resource | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| ids_vs_typical | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| page_popularity | 0.0 | 0.606 | 0.0 | 0.954 | 1.0 | 0.356 | 0.831 |
| password_field | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| payload_score | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| s_max_ids | 20.0 | 1.0 | 9.0 | 0.0 | 5.0 | 0.0 | 1.0 |
| s_mean_popularity | 0.022 | 0.606 | 0.073 | 0.954 | 0.052 | 0.355 | 0.769 |
| s_pages | 7.12 | 1.386 | 7.608 | 1.099 | 6.907 | 1.099 | 3.401 |
| s_requests | 10.727 | 7.284 | 8.401 | 2.708 | 10.629 | 7.041 | 4.727 |
| s_top_answer_share | 0.697 | 0.333 | 0.572 | 1.0 | 0.799 | 1.0 | 0.136 |
| s_unpopular_share | 0.978 | 0.0 | 0.927 | 0.0 | 0.948 | 0.004 | 0.005 |
| same_page_in_session | 1659.0 | 806.0 | 87.0 | 5.0 | 2152.0 | 1138.0 | 1.0 |
| values_vs_typical | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |