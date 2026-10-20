| model             | eval                          |   pr_auc |   roc_auc |   precision |   recall |    fpr |
|:------------------|:------------------------------|---------:|----------:|------------:|---------:|-------:|
| B_baseline        | phiusiil_test                 |   0.7469 |    0.7983 |      0.7181 |   0.5874 | 0.1042 |
| B_baseline        | kaggle_test                   |   0.3113 |    0.5474 |      0.3168 |   0.3275 | 0.2793 |
| B_baseline        | external_all                  |   0.2063 |    0.7969 |      0.0526 |   0.8869 | 0.588  |
| B_baseline        | openphish_vs_tranco_apex      |   0.8326 |    0.9191 |      0.2222 |   0.8869 | 0.2287 |
| B_baseline        | openphish_vs_tranco_subdomain |   0.2097 |    0.6747 |      0.0645 |   0.8869 | 0.9473 |
| C_phiusiil+kaggle | phiusiil_test                 |   0.723  |    0.7806 |      0.7075 |   0.5586 | 0.1044 |
| C_phiusiil+kaggle | kaggle_test                   |   0.4077 |    0.6213 |      0.3912 |   0.3166 | 0.1948 |
| C_phiusiil+kaggle | external_all                  |   0.1795 |    0.7888 |      0.0528 |   0.8597 | 0.5685 |
| C_phiusiil+kaggle | openphish_vs_tranco_apex      |   0.6583 |    0.9029 |      0.2189 |   0.8597 | 0.226  |
| C_phiusiil+kaggle | openphish_vs_tranco_subdomain |   0.1918 |    0.6747 |      0.065  |   0.8597 | 0.911  |
| D_kaggle_only     | phiusiil_test                 |   0.4807 |    0.6053 |      0.5355 |   0.2571 | 0.1008 |
| D_kaggle_only     | kaggle_test                   |   0.4967 |    0.6823 |      0.608  |   0.2078 | 0.053  |
| D_kaggle_only     | external_all                  |   0.0903 |    0.6665 |      0.0829 |   0.543  | 0.2212 |
| D_kaggle_only     | openphish_vs_tranco_apex      |   0.2283 |    0.6834 |      0.1843 |   0.543  | 0.177  |
| D_kaggle_only     | openphish_vs_tranco_subdomain |   0.133  |    0.6496 |      0.131  |   0.543  | 0.2653 |