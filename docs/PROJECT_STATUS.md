# Project status — 2026-11-11

The implemented application combines the original hostname XGBoost model, URL rules, DOM rules and threat intelligence in a local FastAPI backend and Chrome MV3 extension. Manual inspection supplies bounded structural evidence; automatic checks remain URL-only. The monochrome popup and responsive report explain warnings and incomplete coverage. DOM ML is retired.

Publication includes the unchanged production model, current source, tests, consolidated guides and real Chrome screenshots. Raw datasets, research outputs, recovery archives, profiles and credentials remain local. See [model provenance](../models/README.md), [architecture](ARCHITECTURE.md), [testing](TESTING.md) and [screenshot provenance](assets/README.md).

## Limits

- Hostname dataset/subdomain bias and limited real-world calibration remain. Hybrid scores are provisional policy scores.
- Live provider smoke tests are opt-in; mocked regression success does not establish live provider availability.
- Native Windows toast appearance and actual permission accept/decline dialogs still require manual verification.
- The existing Starlette/httpx deprecation warning remains.
- Historical Phase 6 reproduction requires the separately retained original source and licensed local inputs. Current source intentionally fails the original frozen-source guard; no recorded hashes were changed.

See [publication verification](PUBLICATION.md) for the current test run and release scope.
