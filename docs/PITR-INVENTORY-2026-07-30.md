# PITR resource inventory — Noa Trust, read-only

| Field | Value |
|---|---|
| **Status** | **READ-ONLY INVENTORY. NOTHING DELETED, NOTHING MODIFIED.** Awaiting explicit owner authorization before any deletion. |
| **Date** | 2026-07-30 |
| **Authority** | Owner instruction 2026-07-30 item 14. Kept deliberately separate from the architecture work. |
| **Method** | Railway GraphQL API, read queries only. The CLI listed projects; the API supplied ids, sizes, states and exposure. |
| **Project** | `Noa Trust` — `27e7d56b-8ae0-4616-b625-a92471a132b6` |
| **Environment** | `production` — `10885b47-18ce-4062-ae8d-e368f2333c36` |
| **Totals** | 13 services · 11 volume instances · **12,421.9 MB used** · every volume provisioned at **50,000 MB** |

---

## 1. Exposure — checked per service, not assumed

Every service in the environment was queried individually for a public TCP proxy:

```
PUBLIC   Postgres  ->  hayabusa.proxy.rlwy.net:11674
private  noa-prod-pitr-verify-20260724
private  noa-prod-pitr-posta-20260724-1758
private  noa-prod-pitr-posta-20260724-1806
private  noa-pitr-cipher-source-staging-20260723
private  noa-pitr-cipher-source-v3-staging-20260723
private  noa-pitr-v4-positive
private  noa-pitr-v4-wrong-key
private  Postgres-PITR-Verify-Staging-20260723-162719Z
private  Postgres-TBYn
private  noa-scheduler · noa-scheduler-staging · noa-site
```

**No PITR service is reachable from the internet.** The only public endpoint is the main `Postgres`,
which matches the known `DATABASE_PUBLIC_URL` migration path. **The restored production copies are
internal-network only** — a cost and hygiene issue, not a live data-exposure one.

---

## 2. The inventory

`svc` = service id · `vol` = volume id · `used`/`prov` in MB · all volumes `state=READY`, mount
`/var/lib/postgresql/data`.

### 2.1 Not PITR — do not touch

| Service | svc | vol | used | Notes |
|---|---|---|---|---|
| `Postgres` | `04f7ca9d-074b-4196-a915-6e6e8509a15a` | `1e109080-9903-41e6-a403-7ec417e0ce4c` | 1342.2 **and** 1291.6 | ⚠ **Live production database. PUBLIC endpoint.** See the anomaly note below. |
| `noa-scheduler`, `noa-scheduler-staging`, `noa-site` | — | none | — | No volumes. Live services. |

> **Anomaly, reported rather than smoothed over.** `Postgres` returns **two volume instances sharing
> one `svc` id and one `vol` id** with different sizes (1342.2 MB, 1291.6 MB). That is one volume with
> an instance per environment (production and staging), not two volumes. **I did not confirm which
> instance belongs to which environment** — the query returned no environment field on the instance.
> `[UNVERIFIED: per-environment attribution of the two Postgres volume instances — the volumeInstance
> node exposes no environmentId in the schema shape used.]` It does not affect any PITR decision.

### 2.2 PITR — production-data restores

| Service | svc | vol | used | Restore status | Value |
|---|---|---|---|---|---|
| `noa-prod-pitr-posta-20260724-1806` | `f0e17208-bce4-4afb-b681-c884e3540f86` | `f5c3949e-cfe0-41db-8a79-56b2d6f6daf0` | **1089.4** | ✅ **SUCCEEDED** | **Highest evidence value.** The only successful production restore. It is the proof the drill passed. |
| `noa-prod-pitr-verify-20260724` | `7351e2e2-6c21-4ff9-b9d8-803bf93045a0` | `a54b4aad-9efb-4083-86d8-989ccdda9b29` | 1055.3 | ✅ restored | Production verify run. Second-highest evidence value. |
| `noa-prod-pitr-posta-20260724-1758` | `e1028f49-eb6d-4b87-8090-c8a08fcd3feb` | `01737adf-4822-4240-a8e1-ff0ec296ddfe` | **7.9** | ❌ **CRASHED — restore never ran** | Low. Superseded 7 minutes later by `-1806`. **This is the service in the owner's screenshot.** |

### 2.3 PITR — staging / method development

| Service | svc | vol | used | Notes |
|---|---|---|---|---|
| `noa-pitr-cipher-source-staging-20260723` | `e12c0e02-c8ef-4cbd-8a2e-f5a3ad760c60` | `86a2b883-7444-4b2b-bc5b-a854e522940f` | **2799.3** | Largest consumer. Superseded by the `v3` run 29 min later. |
| `noa-pitr-cipher-source-v3-staging-20260723` | `7423b608-f530-4353-b3e2-6cfb2f940d61` | `08ae5087-f9de-4f93-a119-113a8bcd0d8d` | 1303.4 | Supersedes the row above. |
| `noa-pitr-v4-positive` | `d4238829-91e2-4645-aa23-07a758d9d2ac` | `c1156063-3efc-49a9-b03d-23156b146e2d` | 1074.8 | v4 **positive control** — restore succeeded as intended. |
| `noa-pitr-v4-wrong-key` | `866d0115-3413-493d-ba7b-ba87049b48c7` | `d5208209-d9cb-4504-abbc-71cbd309927e` | **7.9** | v4 **negative control** — wrong key ⇒ **nothing restored, as designed.** |
| `Postgres-PITR-Verify-Staging-20260723-162719Z` | `cf1bd230-d6e0-4fa0-b8f8-84742d626c71` | `a6817e75-a5f8-4ed7-a9b3-2858fb800355` | 1130.4 | Earliest verify run. |
| `Postgres-TBYn` | `dcb1c52a-49fc-470e-966e-6e49e8371267` | `8b9280aa-e202-48c8-af90-76bb5ab7974f` | 1319.7 | ⚠ **Auto-generated name — purpose not established.** `[UNVERIFIED: whether this is a PITR artefact or an unrelated instance; the name carries no intent and I did not inspect its contents.]` |

### 2.4 The `7.9 MB` signature — why it is the most useful number here

`noa-prod-pitr-posta-20260724-1758` and `noa-pitr-v4-wrong-key` both hold
**7.888895999999999 MB — byte-identical.** A real restore of this database is ~1,050–1,090 MB.

That figure is "Postgres initialised, nothing restored". It appears once as a **failure** (the crashed
service) and once as an **intended negative control** (wrong key). The identical value is the evidence
that the wrong-key test failed *closed* — it produced **nothing**, rather than quietly restoring
something wrong. A wrong-key run holding ~1 GB would have been the dangerous outcome.

---

## 3. Dependency relationships

- **No PITR service is referenced by** `noa-scheduler`, `noa-scheduler-staging` or `noa-site`
  `[UNVERIFIED: established from absent public endpoints and the absence of any PITR hostname in the
  service list; I did not read service environment variables, which would require credential access
  outside the authorized read-only boundary.]`
- Each PITR service owns exactly one volume; no volume is shared between PITR services.
- `-1758` → `-1806` is a **retry pair**: the second supersedes the first.
- `cipher-source-staging` → `cipher-source-v3-staging` is a **revision pair**: v3 supersedes.

---

## 4. Proposed disposition — for owner authorization, NOT executed

| Tier | Services | Rationale |
|---|---|---|
| **KEEP** | `Postgres`, `noa-scheduler`, `noa-scheduler-staging`, `noa-site` | Live production. |
| **KEEP (evidence)** | `noa-prod-pitr-posta-20260724-1806`, `noa-prod-pitr-verify-20260724` | The successful production restores. **These are the proof the disaster-recovery drill passed.** Deleting them destroys the evidence and leaves only a claim. ~2,145 MB. |
| **KEEP (control pair)** | `noa-pitr-v4-positive`, `noa-pitr-v4-wrong-key` | A positive/negative control **pair**. The negative control is only meaningful *beside* its positive. Together ~1,083 MB — the wrong-key volume costs 7.9 MB. Cheap to keep, and it is the only artefact demonstrating the method fails closed. |
| **CANDIDATE FOR DELETION** | `noa-prod-pitr-posta-20260724-1758` | Crashed, 7.9 MB, superseded 7 min later. ⚠ **But see the caveat below.** |
| **CANDIDATE FOR DELETION** | `noa-pitr-cipher-source-staging-20260723` | Superseded by v3. **2,799.3 MB — the single largest reclaim available.** |
| **CANDIDATE FOR DELETION** | `Postgres-PITR-Verify-Staging-20260723-162719Z` | Earliest staging verify, superseded by later runs. ~1,130 MB. |
| **DECIDE FIRST** | `Postgres-TBYn`, `noa-pitr-cipher-source-v3-staging-20260723` | `TBYn`'s purpose is unestablished; v3 is the surviving staging revision and may still be wanted. ~2,623 MB. |

**Maximum safe reclaim if the three deletion candidates are approved: ~3,937 MB** of 12,422 MB.

### Caveat on the crashed service, and it argues against deleting it

`-1758` is the cheapest thing on this list (7.9 MB) and it is **the only record that the first restore
attempt failed.** Deleting it leaves a history in which the drill succeeded on the first try. For 7.9
MB, the honest audit trail is worth more than the space. **My recommendation is to keep it** and
reclaim from `cipher-source-staging` (2,799 MB) instead, which is 354× larger and genuinely superseded.

---

## 5. Rollback and recovery consequence — read this before authorizing anything

**Deleting a Railway volume is irreversible. There is no undo, and the data is not recoverable from
Railway.**

| If deleted | Consequence |
|---|---|
| An **evidence** restore | The DR drill becomes an unverifiable claim. Re-establishing it means re-running a production PITR restore — hours, and it touches production backups. |
| A **control pair** member | The negative control loses its meaning; "fails closed" becomes an assertion. |
| The **crashed** service | The failed-first-attempt record is gone; the history reads cleaner than it was. |
| `Postgres-TBYn` | **Unknown** — purpose not established. Deleting an unidentified volume is the one action on this page I would refuse to take without identifying it first. |

**Recovery path if a deletion is later regretted:** re-run the PITR restore from the source backup, if
the backup retention window still covers the target timestamp. `[UNVERIFIED: the current backup
retention window — not queried, as it was outside the read-only scope exercised here.]` **That
uncertainty alone is a reason to identify the retention window before deleting any restored copy.**

---

## 6. Authorization required

Nothing on this page has been executed. To proceed, the owner must name **which service ids** may be
deleted. I will confirm each id back before acting, and I will not delete `Postgres-TBYn` until its
purpose is established.
