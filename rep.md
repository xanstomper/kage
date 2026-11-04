# KAGE Mirror Report — ci

_every confirmed attack, mirrored as a detection rule_

## Detection rules
### KAGE-001 — sensitive path fetch [T1552] (TELEMETRY-LIVE)
- attack ref: /backup.zip
- log source: web access log
- match: GET on sensitive path + 200

```yaml
{
  "title": "Sensitive-path GET (backup/env/git)",
  "logsource": {
    "service": "web"
  },
  "detection": {
    "uri_re": "(backup|dump|\\.env|\\.git/config)",
    "status": 200
  }
}
```

## Telemetry sources
- web access log → /var/log/w
