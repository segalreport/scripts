#!/usr/bin/env python3
"""
flock_flag.py
=============
Scans Flock Safety audit log CSVs for immigration-related and potentially
concerning searches. Writes all flagged rows to a single output CSV,
preserving every original column verbatim and prepending two new columns:
  Source_File   — filename the row came from
  Flag_Category — pipe-separated list of matched category labels

Usage
-----
    python flock_flag.py                        # scan . and completed/
    python flock_flag.py --input dir1 dir2      # scan specific directories
    python flock_flag.py --output results.csv   # custom output filename
    python flock_flag.py --all-rows             # include unflagged rows too

Expected input format
---------------------
Flock Safety 13-column audit CSV export. Column headers must include 'Reason'
(case-insensitive). The 'Time Frame' field spans multiple lines inside quotes;
Python's csv.reader handles this correctly — do not pre-process with grep/awk.

Files without a 'Reason' header column are silently skipped.

Category logic
--------------
IMMIGRATION: Mutually exclusive — first matching pattern wins. This prevents
double-counting when a reason matches multiple immigration patterns.

IFFY: Allows multiple matches — a single row can be flagged under several
categories simultaneously (e.g., a protest search that also contains PII).

Notes on specific patterns
--------------------------
- \\bice\\b catches standalone "ice"/"ICE" as the reason. In Flock data this
  almost always means the federal agency, but review matches if your data
  includes other uses (icy roads, ice pack, etc.).

- The custody pattern uses negative lookaheads to exclude legitimate phrases
  like "took custody of suspect" or "custody of prisoner."

- Immigration - Structured Dropdown must appear BEFORE Immigration - General
  in the category list. Flock's 2026 dropdown generates reasons like
  "Immigration (civil/administrative)" which contain "immigra" and would
  mislabel as General if the order were reversed.
"""

import argparse
import csv
import os
import re
import sys
from collections import Counter

# =============================================================================
# IMMIGRATION CATEGORIES
# Mutually exclusive — first match wins. More specific patterns first.
# =============================================================================
IMMIGRATION_CATEGORIES = [
    # Specific ICE phrases before bare \bice\b so "ice detainer" gets the
    # more descriptive label rather than the generic ICE one.
    (
        "Immigration - ICE Hold / Detainer",
        re.compile(
            r"ice\s*(hold|detainer|warrant|pick.?up|pickup|administrative)",
            re.IGNORECASE,
        ),
    ),
    (
        "Immigration - ICE",
        re.compile(r"\bice\b", re.IGNORECASE),
    ),
    (
        "Immigration - HSI",
        re.compile(
            r"\bhsi\b|homeland\s*security\s*investigations?",
            re.IGNORECASE,
        ),
    ),
    (
        "Immigration - ERO",
        re.compile(
            r"\bero\b|enforcement\s*(and|&|of)\s*removal",
            re.IGNORECASE,
        ),
    ),
    (
        "Immigration - CBP / Border Patrol / USBP",
        re.compile(
            r"\bcbp\b|\busbp\b|border\s*patrol|"
            r"customs\s*[&]+\s*border|customs\s*and\s*border|"
            r"u\.?s\.?\s*border\s*patrol",
            re.IGNORECASE,
        ),
    ),
    (
        "Immigration - Deportation / Removal",
        re.compile(
            r"deportat|removal\s*order|order\s*of\s*removal",
            re.IGNORECASE,
        ),
    ),
    (
        "Immigration - DHS",
        re.compile(
            r"\bdhs\b|dept\.?\s*of\s*homeland\s*security|"
            r"department\s*of\s*homeland",
            re.IGNORECASE,
        ),
    ),
    (
        "Immigration - USCIS",
        re.compile(r"\buscis\b", re.IGNORECASE),
    ),
    # MUST precede Immigration - General.
    # Flock's 2026 dropdown produces "Immigration (civil/administrative)" which
    # contains "immigra" — if General ran first it would grab these entries.
    (
        "Immigration - Structured Dropdown",
        re.compile(r"immigration\s*\(", re.IGNORECASE),
    ),
    (
        "Immigration - General",
        re.compile(r"immigra", re.IGNORECASE),
    ),
]

# =============================================================================
# IFFY CATEGORIES
# Multiple matches allowed per row — all labels joined with " | ".
# =============================================================================
IFFY_CATEGORIES = [

    # -------------------------------------------------------------------------
    # PROTEST / POLITICAL SURVEILLANCE
    # -------------------------------------------------------------------------
    (
        "Protest / Political Surveillance",
        re.compile(
            r"\bprotest\b|demonstrat(ion|or|ing|s)?\b|\bDxE\b|"
            r"political\s*sign|political\s*shoot|"
            r"animal\s*rights?\s*activ|activist\s*vehicle|"
            r"\brall(y|ies|ying)\b|\bpicket\b|sit.?in\b",
            re.IGNORECASE,
        ),
    ),
    (
        "Civil Unrest / Riot Response",
        re.compile(
            r"\briot\b|\bunrest\b|civil\s*disturbance|"
            r"looting|mob\s*(action|violence)",
            re.IGNORECASE,
        ),
    ),

    # -------------------------------------------------------------------------
    # POLITICAL / EXTREMIST GROUP TRACKING
    # -------------------------------------------------------------------------
    (
        "Political / Extremist Group Tracking",
        re.compile(
            r"proud\s*boys?|oath\s*keeper|three\s*percent(er)?|3%er|"
            r"boogaloo|antifa\b|sovereign\s*citizen|"
            r"white\s*nationalist|neo.?nazi|\bkkk\b|"
            r"militia\s*(group|member)|extremist\s*(group|activ|suspect)",
            re.IGNORECASE,
        ),
    ),

    # -------------------------------------------------------------------------
    # RACIAL / ETHNIC TARGETING
    # -------------------------------------------------------------------------
    (
        "Racial/Ethnic - Officer Noted No PC or Not Wanted",
        re.compile(
            r"\bnot\s*pc\b|not\s*wanted.*suspect|"
            r"\bno\s*pc\b|no\s*probable\s*cause",
            re.IGNORECASE,
        ),
    ),
    # Ethnicity used as the primary search descriptor rather than a
    # named suspect or specific crime. Expand this list for your data.
    (
        "Racial/Ethnic - Ethnicity as Primary Descriptor",
        re.compile(
            # Romanian-linked patterns
            r"romanian\s*(crew|gang|group|suspect|burglar|crime|ring|skimmer|violin|jewelry|church|solicit)|"
            r"virginia\s*romanians|"
            # Asian-linked patterns
            r"asian\s*(burg|burglary|gang|crew|home|fraud|gambling|mart|pac|scam|crime)|"
            r"locating\s*chinese|chinese\s*(gang|crew|suspect|national)|"
            # Other nationality/ethnicity-as-descriptor patterns
            r"haitian\s*(gang|crew|suspect)|"
            r"jamaican\s*(gang|posse|suspect|crew)|"
            r"cuban\s*(gang|crew|suspect)|"
            r"armenian\s*(gang|crew|mob|suspect)|"
            r"korean\s*(gang|crew|suspect)|"
            r"vietnamese\s*(gang|crew|suspect)|"
            r"somali\s*(gang|crew|suspect|youth|national)|"
            r"hispanic\s*(gang|crew|burglary|crime\s*ring)|"
            r"latin[oax]\s*(gang|cartel|crew)|"
            r"african\s*(national|gang|crew)|"
            # Generic: race word + crime group type as primary descriptor
            r"(black|white|asian|hispanic|latino|african)\s*(gang|crew|crime\s*ring)",
            re.IGNORECASE,
        ),
    ),
    # Race/gender shorthand codes entered in reason field:
    # B/M = Black Male, W/F = White Female, H/M = Hispanic Male, etc.
    (
        "Sensitive PII - Race/Gender Codes in Reason",
        re.compile(
            r"\b[BWHAOINU]/[MF]\b",
            re.IGNORECASE,
        ),
    ),

    # -------------------------------------------------------------------------
    # CIVIL / NON-CRIMINAL USE
    # -------------------------------------------------------------------------
    (
        "Civil Use - Child / Family Custody",
        re.compile(
            # Negative lookaheads exclude legitimate law enforcement phrases
            r"custody(?!\s+of\s+(fugitive|suspect|prisoner|escapee|offender|subject))"
            r"(?!\s+escape)(?!\s+in\s+custody)|"
            r"parental\s*custody|custody\s*(dispute|paper|order|case|battle|issue)|"
            r"child\s*custody|visitation\s*(dispute|order|issue)|"
            r"parental\s*(abduction|kidnapping)",
            re.IGNORECASE,
        ),
    ),
    (
        "Civil Use - Restraining Order / Civil Matter",
        re.compile(
            r"restraining\s*order|\bTPO\b|\bDVPO\b|\bOFP\b|\bHRO\b|\bNCPO\b|"
            r"\bcivil\s*matter\b|\bcivil\s*case\b|"
            r"order\s*of\s*protection(?!\s*(violation|arrest|warrant|viol))",
            re.IGNORECASE,
        ),
    ),

    # -------------------------------------------------------------------------
    # REPRODUCTIVE HEALTHCARE SURVEILLANCE
    # -------------------------------------------------------------------------
    # In May 2025 a Texas sheriff's office searched ~83,000 Flock cameras
    # nationwide for a woman who self-managed an abortion - the logged reason
    # was "had an abortion, search for female" (reported by 404 Media; the
    # search reached cameras in Illinois and Washington). Post-Dobbs,
    # interstate ALPR searches tied to reproductive healthcare are a
    # documented abuse vector. Zero hits here is the good outcome — check
    # every time. Some matches may be legitimate (e.g. a crime at a clinic);
    # review before citing.
    (
        "Reproductive Healthcare - Abortion-Related Search",
        re.compile(
            r"\babortions?\b|planned\s*parenthood|"
            r"reproductive\s*(health|clinic|care|rights)|"
            r"\bmiscarriage\b|\bmifepristone\b|\bmisoprostol\b|"
            r"abortion\s*(clinic|pill|provider)|fetal\s*remains",
            re.IGNORECASE,
        ),
    ),

    # -------------------------------------------------------------------------
    # RELIGIOUS / PRESS / GENDER-IDENTITY TARGETING, PRIVATE BAIL RECOVERY
    # -------------------------------------------------------------------------
    # These four were validated against a 1.8M-row Minnesota dataset. Three had
    # zero hits - which is the point: zero is the good outcome, check every
    # time. The religion pattern deliberately EXCLUDES the bare words "church"
    # and "temple": in test data every church hit was the church as a
    # burglary/theft VICTIM (plus an officer surnamed Church), and "temple"
    # collides with place names like Temple, TX. If your data may phrase
    # faith-surveillance via "church", review those rows manually.
    (
        "Religious Targeting - Faith-Based Search Descriptor",
        re.compile(
            r"\bmosque\b|\bmuslim\b|\bislamic\b|\bsynagogue\b|\bjewish\b|"
            r"\bsikh\b|\bhindu\b|\bimam\b|\brabbi\b|"
            r"(jewish|buddhist|hindu|sikh)\s*temple",
            re.IGNORECASE,
        ),
    ),
    # Bare "press" is excluded — "press charges" is everywhere in police logs.
    (
        "Press Freedom - Journalist / Media Targeting",
        re.compile(
            r"\bjournalist\b|\breporter\b|news\s*media|\bnewsroom\b|"
            r"press\s*(pass|credential|conference)|media\s*(crew|vehicle)",
            re.IGNORECASE,
        ),
    ),
    # Same interstate abuse vector as the abortion case: several states
    # criminalize gender-affirming care for minors; refuge-state camera
    # networks are searchable by agencies from those states. Bare "trans",
    # "drag", and "pride" are excluded ("transport", "transient",
    # "drag racing", etc.).
    (
        "Gender Identity - Trans / LGBTQ+ / Gender-Affirming Care",
        re.compile(
            r"\btransgender\b|\btrans\s*(woman|man|male|female|kid|child|youth|person|people)\b|"
            r"gender[- ]affirming|gender\s*(clinic|transition)|"
            r"\blgbtq?\b|drag\s*(show|queen)|pride\s*(parade|event|fest)",
            re.IGNORECASE,
        ),
    ),
    # Bounty hunters and bail bondsmen are private commercial actors, not law
    # enforcement. NOTE: "bail jumping" is itself a crime and is deliberately
    # NOT matched — police searching for a bail jumper with a warrant is
    # legitimate.
    (
        "Private Use - Bail Bond / Bounty Recovery",
        re.compile(
            r"\bbounty\b|bail\s*bond(sman)?|bail\s*recovery|"
            r"fugitive\s*recovery\s*agent",
            re.IGNORECASE,
        ),
    ),

    # -------------------------------------------------------------------------
    # PERSONAL USE
    # -------------------------------------------------------------------------
    (
        "Personal Use of System",
        re.compile(
            r"\bmy\s*(vehicle|car|truck|plate|suv|van)\b|"
            r"test\s*my\s*(car|vehicle|plate|truck)|"
            r"personal\s*vehicle.*train|train.*personal\s*vehicle|"
            r"\bmy\s*own\s*(car|vehicle)|officer.{0,15}personal",
            re.IGNORECASE,
        ),
    ),

    # -------------------------------------------------------------------------
    # NO-PURPOSE / OPEN-ENDED SEARCHES
    # -------------------------------------------------------------------------
    (
        "No-Purpose / Open-Ended Search",
        re.compile(
            r"daytime\s*search\s*for\s*best\s*result",
            re.IGNORECASE,
        ),
    ),

    # -------------------------------------------------------------------------
    # MISSION CREEP — NON-CRIMINAL MUNICIPAL USE
    # -------------------------------------------------------------------------
    (
        "Mission Creep - Non-Criminal Use",
        re.compile(
            r"city\s*planning|traffic\s*analysis|urban\s*planning|"
            r"traffic\s*study|pedestrian\s*(count|study|analysis)|"
            r"parking\s*study|event\s*planning(?!\s*(vehicle|suspect))",
            re.IGNORECASE,
        ),
    ),

    # -------------------------------------------------------------------------
    # SENSITIVE PII IN REASON FIELD
    # -------------------------------------------------------------------------
    (
        "Sensitive PII - DOB in Reason",
        re.compile(
            r"\bdob\b|\bdate\s*of\s*birth\b",
            re.IGNORECASE,
        ),
    ),
    (
        "Sensitive PII - ID / License Number in Reason",
        re.compile(
            r"\bssn\b|\bsocial\s*security\b|"
            r"\bdl\s*[#:]?\s*\d{5,}|"
            r"driver.{0,10}license.{0,15}\d{5,}",
            re.IGNORECASE,
        ),
    ),
    # "rape suspect" / CSAM entries in audit logs mean sensitive case details
    # are stored in a commercial vendor's database. "Sex offender" is excluded —
    # it's extremely common in legitimate warrant/compliance searches.
    (
        "Sensitive Case - Rape / Child Exploitation in Reason",
        re.compile(
            r"rape\s*suspect|sexual\s*assault\s*suspect|"
            r"\bcsam\b|child\s*porn(ograph)?|child\s*exploit",
            re.IGNORECASE,
        ),
    ),

    # -------------------------------------------------------------------------
    # CI / UNDERCOVER OPERATIONS
    # -------------------------------------------------------------------------
    (
        "CI / Controlled Buy Operation",
        re.compile(
            r"buy.?walk|controlled\s*buy|drug\s*buy\b|"
            r"meth.*controlled\s*buy|controlled\s*buy.*meth|"
            r"\bci\s*(vehicle|op|run|plate)\b|"
            r"confidential\s*informant.*vehicle|"
            r"undercover\s*(buy|vehicle|op)",
            re.IGNORECASE,
        ),
    ),

    # -------------------------------------------------------------------------
    # HIGHWAY INTERDICTION / TRAVEL PROFILING
    # -------------------------------------------------------------------------
    (
        "Highway Interdiction / Travel Profiling",
        re.compile(
            r"travel\s*pattern|interdiction\s*check|"
            r"suspicious\s*traveler|highway\s*interdiction|"
            r"drug\s*interdiction(?!\s*(unit|task\s*force))",
            re.IGNORECASE,
        ),
    ),

    # -------------------------------------------------------------------------
    # JUVENILE SUPPRESSION
    # -------------------------------------------------------------------------
    (
        "Juvenile Suppression Detail",
        re.compile(r"juvenile\s*suppression", re.IGNORECASE),
    ),
]


# =============================================================================
# CORE LOGIC
# =============================================================================

def find_csv_files(directories, exclude_names=None):
    """
    Yield .csv file paths from all given directories, sorted by name.
    Skips files whose basenames are in exclude_names (e.g. the output file).
    Deduplicates by basename so the same filename in multiple directories
    is only processed once (first directory wins).
    """
    exclude_names = set(exclude_names or [])
    seen_basenames = set()
    for d in directories:
        if not os.path.isdir(d):
            continue
        for fname in sorted(os.listdir(d)):
            if not fname.lower().endswith(".csv"):
                continue
            if fname in exclude_names:
                continue
            if fname in seen_basenames:
                continue
            seen_basenames.add(fname)
            yield os.path.join(d, fname)


def col_index(headers, name):
    """Return index of first header matching name (case-insensitive), or None."""
    name_lower = name.lower()
    for i, h in enumerate(headers):
        if h.strip().lower() == name_lower:
            return i
    return None


def categorize(reason, moderation=None):
    """
    Return list of category labels for a reason string.

    Immigration categories are mutually exclusive (first match wins).
    Iffy categories allow multiple matches.
    A non-empty Moderation field always adds 'Vendor Moderation Note'.
    """
    cats = []

    for label, pattern in IMMIGRATION_CATEGORIES:
        if pattern.search(reason):
            cats.append(label)
            break

    for label, pattern in IFFY_CATEGORIES:
        if pattern.search(reason):
            cats.append(label)

    if moderation and moderation.strip():
        cats.append("Vendor Moderation Note")

    return cats


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Flag immigration-related and concerning searches in "
            "Flock Safety audit log CSVs."
        )
    )
    parser.add_argument(
        "--input",
        nargs="+",
        default=[".", "completed"],
        metavar="DIR",
        help="Directories to scan (default: . and completed/)",
    )
    parser.add_argument(
        "--output",
        default="FLAGGED_SEARCHES.csv",
        help="Output filename (default: FLAGGED_SEARCHES.csv)",
    )
    parser.add_argument(
        "--all-rows",
        action="store_true",
        help="Write all rows, not just flagged ones (Flag_Category blank if no match)",
    )
    args = parser.parse_args()

    input_dirs = [d for d in args.input if os.path.isdir(d)]
    if not input_dirs:
        print(f"ERROR: No valid input directories: {args.input}", file=sys.stderr)
        sys.exit(1)

    output_basename = os.path.basename(args.output)
    csv_files = list(find_csv_files(input_dirs, exclude_names=[output_basename, "FLAGGED_SEARCHES.csv"]))
    if not csv_files:
        print(f"No CSV files found in: {input_dirs}", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {len(csv_files)} file(s) ...")

    output_rows = []
    output_headers = None
    category_counts = Counter()
    files_ok = 0
    files_skipped = 0

    for filepath in csv_files:
        fname = os.path.basename(filepath)
        try:
            with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
                reader = csv.reader(f)
                raw_headers = next(reader, None)
                if raw_headers is None:
                    files_skipped += 1
                    continue

                headers = [h.strip() for h in raw_headers]
                reason_col = col_index(headers, "reason")
                mod_col = col_index(headers, "moderation")

                if reason_col is None:
                    print(f"  SKIP (no Reason column): {fname}")
                    files_skipped += 1
                    continue

                if output_headers is None:
                    output_headers = ["Source_File", "Flag_Category"] + headers

                files_ok += 1
                flagged_in_file = 0

                for row in reader:
                    if len(row) <= reason_col:
                        continue
                    reason = row[reason_col].strip()
                    if not reason or reason == "***":
                        continue

                    moderation = (
                        row[mod_col].strip()
                        if mod_col is not None and len(row) > mod_col
                        else None
                    )

                    cats = categorize(reason, moderation)

                    if cats or args.all_rows:
                        padded = list(row) + [""] * max(0, len(headers) - len(row))
                        out = {
                            "Source_File": fname,
                            "Flag_Category": " | ".join(cats),
                        }
                        for i, h in enumerate(headers):
                            out[h] = padded[i]
                        output_rows.append(out)
                        for cat in cats:
                            category_counts[cat] += 1
                        flagged_in_file += 1

                print(f"  {fname}: {flagged_in_file} flagged")

        except Exception as exc:
            print(f"  ERROR reading {fname}: {exc}", file=sys.stderr)
            files_skipped += 1

    if not output_rows:
        print("\nNo flagged rows found.")
        return

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=output_headers, extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"\n{'=' * 60}")
    print(f"Files scanned: {files_ok}  |  Skipped: {files_skipped}")
    print(f"Flagged rows:  {len(output_rows):,}")
    print(f"Output:        {args.output}")
    print(f"\nCategory breakdown (rows can appear in multiple categories):")
    for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
        print(f"  {count:7,d}  {cat}")


if __name__ == "__main__":
    main()
