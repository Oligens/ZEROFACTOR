# Synthetic controlled-module fixtures

These JSON files are examples for the offline evaluators only. They contain no real target data and are not requests to any system.

Copy `scripts/controlled-scope.example.json` to a private local file, replace the authorization ID and owner, and set `authorized` to `true` only when you possess written authorization for the named assessment. The example hostname is reserved for documentation and is never contacted by these five evaluators.

Run, for example:

```bash
python3 scripts/controlled_modules.py --module AUTH --scope scripts/controlled-scope.json --fixture fixtures/controlled/auth.json --output reports/auth.json
python3 scripts/controlled_modules.py --module INPUT --scope scripts/controlled-scope.json --fixture fixtures/controlled/input.json --output reports/input.json
python3 scripts/controlled_modules.py --module FILE --scope scripts/controlled-scope.json --fixture fixtures/controlled/file.json --output reports/file.json
python3 scripts/controlled_modules.py --module RATE --scope scripts/controlled-scope.json --fixture fixtures/controlled/rate.json --output reports/rate.json
python3 scripts/controlled_modules.py --module RECOVERY --scope scripts/controlled-scope.json --fixture fixtures/controlled/recovery.json --output reports/recovery.json
```

The RATE example is expected to return `inconclusive`: two unthrottled observations do not prove that a rate limiter is absent.
