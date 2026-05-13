# Canonical-JSON Cross-Check

The signing input for heartbeats must produce **byte-identical** output in:

- Python `_canonical_json()` in `fula-ota/docker/fxsupport/linux/readiness-check.py`
- TypeScript `canonicalJSON()` in `libp2p-relay/cloudflare/src/verify.ts`

If they disagree, the Worker rejects every heartbeat, KV stays empty, and `/find-box` always falls through to tier 2 — silently. Verify before deploy.

## Fixture

A representative box heartbeat payload (omitting the signature itself):

```json
{
  "peerId": "12D3KooWE6gC66XWxKacdna5LX4ymwnCCMpaddBFkB8At3WedRaZ",
  "timestamp": "2026-05-13T05:30:00.000Z",
  "data": {
    "type": "box",
    "reservedOn": ["relay.dev.fx.land"],
    "libp2pAddrs": [
      "/dns/relay.dev.fx.land/tcp/4001/p2p/12D3KooWDRrBaAfPwsGJivBoUw5fE7ZpDiyfUjqgiURq2DEcL835/p2p-circuit/p2p/12D3KooWE6gC66XWxKacdna5LX4ymwnCCMpaddBFkB8At3WedRaZ"
    ]
  }
}
```

## Expected canonical output (single line, no whitespace)

```
{"data":{"libp2pAddrs":["/dns/relay.dev.fx.land/tcp/4001/p2p/12D3KooWDRrBaAfPwsGJivBoUw5fE7ZpDiyfUjqgiURq2DEcL835/p2p-circuit/p2p/12D3KooWE6gC66XWxKacdna5LX4ymwnCCMpaddBFkB8At3WedRaZ"],"reservedOn":["relay.dev.fx.land"],"type":"box"},"peerId":"12D3KooWE6gC66XWxKacdna5LX4ymwnCCMpaddBFkB8At3WedRaZ","timestamp":"2026-05-13T05:30:00.000Z"}
```

## Run Python side

Save as `check_python.py`:

```python
import json, sys

def _canonical_json(value):
    if value is None or isinstance(value, (str, bool, int, float)):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + _canonical_json(v)
            for k, v in sorted(value.items())
        ) + "}"
    raise TypeError(type(value).__name__)

sample = {
    "peerId": "12D3KooWE6gC66XWxKacdna5LX4ymwnCCMpaddBFkB8At3WedRaZ",
    "timestamp": "2026-05-13T05:30:00.000Z",
    "data": {
        "type": "box",
        "reservedOn": ["relay.dev.fx.land"],
        "libp2pAddrs": [
            "/dns/relay.dev.fx.land/tcp/4001/p2p/12D3KooWDRrBaAfPwsGJivBoUw5fE7ZpDiyfUjqgiURq2DEcL835/p2p-circuit/p2p/12D3KooWE6gC66XWxKacdna5LX4ymwnCCMpaddBFkB8At3WedRaZ"
        ],
    },
}
out = _canonical_json(sample)
sys.stdout.write(out)
sys.stdout.write("\n")
sys.stderr.write(f"# byte length: {len(out.encode('utf-8'))}\n")
```

Run: `python3 check_python.py`

## Run TypeScript side

Save as `check_ts.mjs` (Node 20+ supports ES modules with mjs):

```javascript
function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJSON(value[k])).join(',') + '}';
}

const sample = {
  peerId: "12D3KooWE6gC66XWxKacdna5LX4ymwnCCMpaddBFkB8At3WedRaZ",
  timestamp: "2026-05-13T05:30:00.000Z",
  data: {
    type: "box",
    reservedOn: ["relay.dev.fx.land"],
    libp2pAddrs: [
      "/dns/relay.dev.fx.land/tcp/4001/p2p/12D3KooWDRrBaAfPwsGJivBoUw5fE7ZpDiyfUjqgiURq2DEcL835/p2p-circuit/p2p/12D3KooWE6gC66XWxKacdna5LX4ymwnCCMpaddBFkB8At3WedRaZ",
    ],
  },
};
const out = canonicalJSON(sample);
process.stdout.write(out);
process.stdout.write('\n');
process.stderr.write(`# byte length: ${Buffer.byteLength(out, 'utf-8')}\n`);
```

Run: `node check_ts.mjs`

## Compare

```bash
diff <(python3 check_python.py) <(node check_ts.mjs)
```

No output = byte-identical. If `diff` prints anything, fix before deploy.

## Edge cases that historically break canonical-JSON serializers

If you want extra confidence, run each of these through both sides and compare:

| Case | Sample |
|---|---|
| empty array | `{"x": []}` |
| nested empty object | `{"x": {}}` |
| escape characters | `{"x": "quote\"here"}` |
| non-ASCII (won't appear in our payloads but tests `ensure_ascii=False`) | `{"x": "café"}` |
| true/false/null | `{"a": true, "b": false, "c": null}` |
| integer | `{"x": 42}` |
| key with backslash | `{"a\\b": "v"}` |

All should produce byte-identical output between Python and TypeScript.
