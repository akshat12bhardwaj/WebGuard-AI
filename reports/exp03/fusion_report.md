Rates = share of hosts. Legitimate groups: lower is better. OpenPhish: higher is better (detection).
TI not checked (offline), so every final result here has low confidence.

| group                    |    n |   raw @alert |   raw @high |   final caution+ (current guard) |   final high_risk (current guard) |   final caution+ (cap below alert) |   final high_risk (cap below alert) |
|:-------------------------|-----:|-------------:|------------:|---------------------------------:|----------------------------------:|-----------------------------------:|------------------------------------:|
| tranco_apex              | 3000 |       0.1817 |      0.0437 |                           0.183  |                            0.046  |                             0.183  |                              0.046  |
| tranco_subdomain         | 3000 |       0.9347 |      0.8613 |                           0.9346 |                            0.0513 |                             0.0513 |                              0.0513 |
| openphish                |  221 |       0.8688 |      0.8507 |                           0.8733 |                            0.0633 |                             0.095  |                              0.0633 |
| new_legit_subdomain_test | 8127 |       0.9029 |      0.7962 |                           0.9031 |                            0.0041 |                             0.0041 |                              0.0041 |