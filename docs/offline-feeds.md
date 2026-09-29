# Vulnerability feeds without internet access

**Audience:** operators running NetSecOps in an air-gapped or restricted-egress site.

NetSecOps can tell you that a Cisco ASA on your estate is running 9.16.1 and that
CVE-2024-20353 affects 9.16.1. It knows the first from your own devices. It only knows
the second if somebody gives it a vulnerability feed.

Constraint C-7 says the product must work with no route to the internet, so importing
those feeds by hand is a first-class path rather than a fallback (FR-VUL-08). The online
sync is a convenience that produces the same bytes and runs the same ingest code — an
imported bundle is not a lesser thing.

---

## What the vulnerability engine cannot do without a feed

Worth being blunt, because the failure is silent. A device with no matching advisory and
a device that was never compared against anything both render as a device with no
vulnerabilities. Until a feed is loaded, every device looks clean.

| Feed | What it gives you | Without it |
|---|---|---|
| **KEV** (CISA) | Which CVEs are being exploited *right now* | Nothing is flagged as actively exploited, so everything competes on CVSS alone |
| **NVD** | CVE records, CVSS, affected version ranges | No CVE matching at all — this is the one that makes the page non-empty |
| **EPSS** (FIRST) | Probability each CVE is exploited in the next 30 days | No way to rank the long tail of medium-severity findings |
| **End-of-life** | Release-cycle and support dates per product | No warning that a platform has stopped receiving fixes |
| **Vendor CSAF** | The vendor's own advisory, with their affected-version statement | You rely on NVD's version data, which is coarser for network kit |

KEV and NVD first. The other three sharpen the answer; those two are what produce one.

---

## 1. Download, on a machine that has internet

```bash
# CISA KEV
curl -fsSLO https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

# FIRST EPSS — gzipped CSV, imported as published; no need to unpack it
curl -fsSLO https://epss.cyentia.com/epss_scores-current.csv.gz

# NVD, one year per file, plus the digest NVD publishes for each
for year in 2024 2025 2026; do
  curl -fsSLO "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$year.json.gz"
  curl -fsSLO "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$year.meta"
done

# End-of-life, one file per product you actually run
curl -fsSL https://endoflife.date/api/cisco-asa.json -o eol-cisco-asa.json
```

Use the yearly bulk files rather than the NVD API. The API returns 2,000 records a page
and rate-limits hard without a key, so a first load through it is hours of paging that
can fail halfway and leave you unsure what you have.

Vendor CSAF advisories are downloaded individually from the vendor's security site —
Cisco, Palo Alto, Fortinet and Juniper all publish them, and for your platforms they are
more precise about affected versions than NVD is.

Then record what you are carrying:

```bash
sha256sum *.json *.json.gz *.csv.gz > BUNDLE.sha256
```

**Take the digests over a separate path from the files.** Print them, or send the text
file by email, or read them over the phone. A digest that travels on the same USB stick
as the bundle proves only that the stick is internally consistent — which is exactly
what a stick that was tampered with in transit also is.

For NVD you do not have to trust your own copy at all: each `.meta` file carries the
`sha256:` NVD itself published for that year's data, fetched over TLS from a different
request than the bundle. That is the digest to carry in and check against.

---

## 2. Verify, on the NetSecOps host

```bash
sha256sum -c BUNDLE.sha256
```

This is not ceremony. A feed bundle is a list of statements about which of your devices
are exploitable, and it has passed through at least one machine outside your security
boundary to get here. A bundle that lost a thousand records in transit produces a
shorter list and no error. Pass the digest to the importer as well, at step 4 — it
refuses before writing anything, so a bad bundle imports nothing rather than most of
itself.

---

## 3. Put the files where the container can read them

The API container runs with a read-only root filesystem and no capabilities (SEC-10), so
`docker cp` into it fails and its `/tmp` is a 64 MB tmpfs. There is a directory mounted
for exactly this:

```bash
cp known_exploited_vulnerabilities.json /path/to/netsecops/deploy/bundles/kev.json
```

`deploy/bundles/` is bind-mounted read-only at `/bundles`. Set `FEED_BUNDLES_DIR` in
`.env` to point the mount at whatever directory your media-transfer process already
writes to, so nobody has to copy the file twice.

Running NetSecOps outside Docker: any path the service account can read will do.

---

## 4. Import

```bash
docker compose -f deploy/docker-compose.yml exec api \
  netsecops-cli import-feed /bundles/kev.json --feed kev --sha256 <digest>
```

```
Imported kev.json as kev
  KEV entries            1327
  KEV cleared            8801
  feed version           2026.09.29
```

The format is detected from the content, not the filename, and reported back — a
renamed file still imports as what it is, and `kind` coming back as something you did
not expect is the signal that the wrong file was copied. "KEV cleared" is the number of
CVEs the import set to *not* exploited, which is what turns the flag from a badge into
a filter.

One bundle per invocation, so the first load is usually a short script:

```bash
docker compose -f deploy/docker-compose.yml exec api sh -c '
  for f in /bundles/*.json; do
    netsecops-cli import-feed "$f" --feed "$(basename "${f%.json}")"
  done'
```

**Import NVD one year at a time.** A single year of the 2.0 feed is about 24 MB
compressed and 286 MB as JSON, and the importer holds the parsed document in memory
while it works. Three years is a sensible starting window for network kit; a
sixty-device estate does not need CVEs from 2002.

**End-of-life bundles need to be told whose they are.** An endoflife.date export is a
list of release cycles with nothing in it naming the vendor, and filing Cisco's dates
under Fortinet would mark a supported estate as dead:

```bash
netsecops-cli import-feed /bundles/eol-cisco-asa.json \
  --feed eol --vendor cisco --product asa
```

The console can do all of this too, under **Vulnerabilities → Feed status → Import
bundle**, for operators who have a browser session on the box and the `vuln:write`
permission.

---

## 5. Confirm it landed

**Vulnerabilities → Feed status** lists the last ten imports, successful or not, with
their record counts, how many records were rejected, and the feed's own version stamp
beside the time the import ran. Failures are listed alongside successes on purpose:
"when did this last work?" is the question asked the morning somebody notices the page
looks thin, and a table holding only successes cannot answer it (FR-VUL-07).

A status of `partial` means some records could not be read and `records_rejected` says
how many. Nine thousand of ten thousand imported is nine thousand answers and a thousand
blind spots, not a success.

Then check a device you already know something about. If its vulnerability list is still
empty after a KEV and NVD import, the usual cause is that NetSecOps does not know the
device's software version — the match needs one, and it will decline to guess rather
than report every advisory ever published for the platform. For an estate onboarded
before version capture existed, `netsecops-cli backfill-device-facts` reads the
versions out of configurations already collected; it reports what it would change and
does nothing until you add `--apply`.

---

## 6. Stop it reaching out at all

```
NETSECOPS_FEEDS_OFFLINE_MODE=true
```

With this set, a sync request is refused with a stated reason instead of timing out
against a blocked egress rule — which matters because a timeout looks like a NetSecOps
fault and an outbound connection attempt from a segmented management network is an
incident. Imports are unaffected.

---

## Cadence

| Feed | Refresh | Why that often |
|---|---|---|
| KEV | Weekly, and after any CISA alert | Additions are the ones already being exploited |
| EPSS | Weekly | Scores are recomputed daily but move slowly |
| NVD | Monthly, or after a vendor advisory that matters to you | Volume is high, relevance to network kit is not |
| End-of-life | Quarterly | Dates change rarely, and always with notice |
| Vendor CSAF | On advisory | These are the accurate ones for your platforms |

A feed that is three months old is not neutral: it reports the estate as clean of
everything published since. That is why the feed status table shows the bundle's own
date in a column of its own, next to the time it was imported — an import that ran an
hour ago against a year-old catalogue is fresh and stale at once, and the import time
alone reports only the reassuring half.
