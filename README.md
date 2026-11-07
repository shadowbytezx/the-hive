# TheHive Case Management Lab — SOC Investigation Workflow

A follow-up SOC project: standing up a case management platform and running two confirmed DVWA incidents through the full analyst workflow — alert → case → evidence → investigation → MITRE mapping → resolution — rather than stopping at "the alert fired" as in the earlier detection-focused projects (see [../README.md](../README.md) and [../dvwa-attack-lab/README.md](../dvwa-attack-lab/README.md)).

## Objectives

- Deploy TheHive 5 (case management / SOAR platform) via Docker Compose
- Take two already-confirmed Splunk alerts (SQL injection, credential brute force) and run them through a real investigative lifecycle instead of just reading the alert
- Document evidence as structured Observables, not just prose
- Track investigation steps as Tasks with timestamps and activity logs
- Formally map each incident to MITRE ATT&CK inside the case record
- Close both cases with a documented resolution and summary

## Lab Environment

| Component | Details |
|---|---|
| Platform | TheHive 5 (`strangebee/thehive:5`) |
| Backend | Cassandra 4.1 (metadata), Elasticsearch 7.17.9 (search index) |
| Storage | Local filesystem (see MinIO note below) |
| Host | New dedicated Ubuntu 22.04 VM, hostname `thehive` |
| Web UI | `http://127.0.0.1:9080` (VirtualBox port forward → guest `9080`) |
| Source data | Splunk `access_combined` events from the DVWA attack lab |

## 1. Deployment

```yaml
services:
  cassandra:
    image: cassandra:4.1
    mem_limit: 1000m
    environment:
      - MAX_HEAP_SIZE=512M
      - HEAP_NEWSIZE=128M
    ports: ["9042:9042"]

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.9
    mem_limit: 700m
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms512m -Xmx512m
    ports: ["9200:9200"]

  thehive:
    image: strangebee/thehive:5
    mem_limit: 1000m
    depends_on: [cassandra, elasticsearch]
    command:
      - --cql-hostnames
      - cassandra
      - --index-backend
      - elasticsearch
      - --es-hostnames
      - elasticsearch
      - --no-config-cortex
    ports: ["9080:9000"]
```

```bash
docker compose up -d
```

**Issues encountered along the way:**

- **`quay.io/minio/minio` returned `401 UNAUTHORIZED` on pull**, and the Docker Hub fallback (`minio/minio`) returned `pull access denied, repository does not exist`. Investigation confirmed this wasn't a config mistake: MinIO deleted its community-edition images from Docker Hub in September 2026 and locked quay.io's copy behind authentication shortly after, a permanent upstream breaking change affecting every MinIO-based Compose template written before that date, not just this one. Rather than chase an unofficial replacement image with unknown permission quirks (several third-party forks run as a non-root UID requiring a manual `chown` on the data volume), the stack was reconfigured to use **TheHive's local filesystem storage provider** instead of S3, removing the MinIO service entirely. This is a fully supported configuration for a single-node deployment and sidesteps the dependency altogether.
- **Port conflict on `9000`.** Both TheHive's default web port and MinIO's API port map to `9000`, surfaced before MinIO was removed. Resolved by mapping TheHive's container port `9000` to host port `9080` instead.
- **`ERR_CONNECTION_RESET`** reaching the web UI from the host browser, same root cause as every other VM in this lab series: no VirtualBox port-forwarding rule existed yet for the new VM. Fixed with a host `127.0.0.1:9080` → guest `9080` TCP rule.
- **Default admin credentials** (`admin@thehive.local` / `secret`) worked for first login; changed immediately via the profile menu.

## 2. Case #1 — DVWA SQL Injection

Created manually from the `SQL Injection Attempt - DVWA` Splunk alert (see DVWA attack lab for the underlying payload, regex detection, and raw log evidence).

| Field | Value |
|---|---|
| Severity | High |
| Status | Resolved — **True Positive** |
| Source IP | `10[.]0[.]2[.]2` |

**Observables (2):**
- `ip` — `10.0.2.2`, tagged `attacker`
- `other` — `1%27+OR+%271%27%3D%271` (payload, kept in its original URL-encoded form as logged — see the DVWA lab's note on why Splunk never decodes this field)

**Tasks (4/4 completed):**
1. Confirm SQLi payload in raw access logs
2. Determine if the query actually returned data — noted that DVWA's "Low" security setting performs no input sanitization, so the UNION SELECT would have succeeded against the `users` table
3. Check if this IP touched any other endpoints — cross-referenced against Case #2, confirming the same operator also ran the brute-force test in the same session window
4. Recommend remediation — parameterized queries, WAF rule blocking UNION/SELECT patterns in URL parameters

**TTP:** `T1190` — Exploit Public-Facing Application (tactic: Initial Access)

**Resolution summary:** Confirmed SQL injection vulnerability via UNION-based payload against DVWA's `/vulnerabilities/sqli` endpoint. Attack chain validated end-to-end: traffic generated → logged in Splunk → scheduled alert fired → investigated and documented in TheHive. Impact: none — intentionally vulnerable lab application, isolated environment, no production systems or real data affected.

## 3. Case #2 — DVWA Credential Brute Force

Created from the `Web Login Brute Force - DVWA` Splunk alert.

| Field | Value |
|---|---|
| Severity | High |
| Status | Resolved — **True Positive** |
| Source IP | `172[.]17[.]0[.]1` |

**Observables (2):**
- `ip` — `172.17.0.1`, tagged `attacker`
- `other` — `password` (the successful credential), tagged `successful-credential`

**Tasks (4/4 completed):**
1. Confirm brute-force pattern in access logs
2. Verify successful login occurred — confirmed via the password-attempt response
3. Check source IP for other malicious activity — cross-referenced against Case #1
4. Recommend remediation — rate limiting, account lockout, CAPTCHA

**TTP:** `T1110.001` — Password Guessing (tactic: Credential Access)

**Resolution summary:** Confirmed credential brute-force against DVWA's `/vulnerabilities/brute/` endpoint — 7 failed attempts followed by a successful login on the 8th. GET-based authentication exposed every attempted password, including the valid one, in cleartext in the access log. Impact: none — controlled lab test, no real accounts affected.

## 4. A Note on the Two Different "Attacker" IPs

Case #1 shows `10.0.2.2`; Case #2 shows `172.17.0.1`. Both represent the same operator, not two separate actors — the difference is purely which network path the traffic took:

| IP | What it actually is |
|---|---|
| `10.0.2.2` | VirtualBox's NAT gateway address — traffic from the host's own browser, through the VM's NAT adapter, to the DVWA container |
| `172.17.0.1` | Docker's internal bridge gateway — traffic sent directly from a shell session on the VM itself to the DVWA container |

This is a useful, realistic reminder for IOC attribution: a logged source IP reflects the last hop in whatever network path the request took, not necessarily anything about who or where the real originator is. A production SOC would need the same caution before treating an internal gateway or proxy address as if it were an external attacker's real IP.

## 5. MITRE ATT&CK Mapping

| Case | Technique | Tactic |
|---|---|---|
| SQL Injection | T1190 — Exploit Public-Facing Application | Initial Access |
| Credential Brute Force | T1110.001 — Password Guessing | Credential Access |

## Lessons Learned

- A broken upstream dependency (MinIO's Docker Hub removal) is sometimes better solved by removing the dependency than by chasing a replacement — TheHive's local storage provider was a simpler, equally valid fix for a single-node lab than hunting down an unofficial MinIO image with unknown permission behavior.
- Case management turns a one-line alert into an auditable record: the same SQL injection alert that was a single row in Splunk became a case with timestamped tasks, tagged evidence, and a formal technique classification — the artifact a real incident report or compliance audit would actually need.
- Observables should preserve data in the form it was actually logged (URL-encoded payload, not manually decoded) — consistent with the same lesson learned the hard way while writing the underlying Splunk detection regex.
- Tracking two related cases side by side surfaced a genuine finding (two different gateway IPs for the same operator) that wouldn't have been as visible working from raw Splunk search results alone — case-level organization makes cross-incident patterns easier to spot.

## Tools

Docker, Docker Compose, TheHive 5, Cassandra, Elasticsearch, Splunk Enterprise (upstream alert source)

