# BIM9_Connect license activation service

This repository activates BIM9_Connect license keys. It is public on purpose:

- **`licenses.json`** lists which key is bound to which computer and since when. It contains **hashes only** (no keys, no Machine IDs, no customer data) and is **signed** by the service key, so nobody else can change it in a way the add-in would accept.
- **Issues titled `BIM9 …`** are activation requests opened automatically by the add-in. Their content is **encrypted** for the service only. Please do not edit, comment on or close them.
- **`.github/workflows/activate.yml`** processes the requests (GitHub Actions) and updates `licenses.json`.

The service key lives only in the repository secret `LICENSE_SERVICE_KEY`.
