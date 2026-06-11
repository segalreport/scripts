# flock_flag.py - Flock Safety Audit Log Scanner

A single-file Python script that scans [Flock Safety](https://www.flocksafety.com/) automated license plate reader (ALPR) audit log exports for **immigration-related searches** and **other potentially concerning uses** - protest surveillance, ethnic targeting, civil custody disputes, personal use, sensitive PII, and more.

It was built to analyze audit logs obtained through a public records request to a Minnesota police department, where it surfaced thousands of immigration-related searches (ICE, HSI, Border Patrol) and hundreds of other questionable entries run by outside agencies through the city's cameras. It is published here so anyone can run the same analysis against their own city's Flock data.

**The script never modifies your source data.** It reads the original CSVs, copies flagged rows verbatim into a new file, and adds exactly two new columns: which file the row came from, and why it was flagged.

---

## Requirements

- Python 3.6+
- No dependencies - standard library only (`csv`, `re`, `os`, `sys`, `argparse`, `collections`)

## Usage

Put `flock_flag.py` in the folder with your Flock audit CSV exports and run:

```bash
python flock_flag.py
```

By default it scans the current directory and a `completed/` subdirectory (if present), and writes results to `FLAGGED_SEARCHES.csv`.

Options:

```bash
python flock_flag.py --input /path/to/csvs /another/path   # scan specific directories
python flock_flag.py --output my_results.csv               # custom output filename
python flock_flag.py --all-rows                            # include every row, flagged
                                                            # or not (Flag_Category left
                                                            # blank on unflagged rows)
```

When it finishes, it prints a per-file count of flagged rows and a category breakdown:

```
Files scanned: 32  |  Skipped: 0
Flagged rows:  5,926
Output:        FLAGGED_SEARCHES.csv

Category breakdown (rows can appear in multiple categories):
    1,331  Immigration - HSI
      856  No-Purpose / Open-Ended Search
      752  Immigration - ICE
      ...
```

## Input format

The script expects Flock Safety audit CSV exports - the files a department produces in response to a records request. A typical export has 13 columns:

```
ID, Name, Org Name, Total Networks Searched, Time Frame, License Plate,
Reason, Case #, Filters, Search Time, Search Type, Text Prompt, Moderation
```

The script locates the **Reason** column by header name (case-insensitive), not by position, so it tolerates exports with different column orders or extra columns. Files without a `Reason` header are skipped with a notice.

Two quirks of Flock exports the script handles for you:

- **Multi-line fields.** The `Time Frame` field contains a start date and end date on separate lines inside one quoted cell. This breaks `grep`-based analysis and some spreadsheet imports. Python's `csv` module parses it correctly.
- **Encoding noise.** Files are read as UTF-8 with BOM tolerance (`utf-8-sig`) and undecodable bytes are replaced rather than crashing the run.

It also deduplicates by filename across input directories (so a file present in two scanned folders is only processed once - note this means two *different* files that share a name will not both be read). Its own previous output files are automatically detected by their `Flag_Category` column and skipped, even if renamed.

## Output format

A new CSV containing **every original column, copied verbatim**, plus two columns prepended:

| Column | Contents |
|---|---|
| `Source_File` | Filename the row came from, so every row is traceable to its source |
| `Flag_Category` | One or more category labels, joined with ` \| ` |

If your files don't all share the same columns, the output uses the union of every column seen across all files (cells a given file didn't have are left blank), so nothing is dropped.

Rows whose Reason field is empty or redacted (`***`) are normally skipped - there is nothing to match against. Two exceptions: a row with a vendor moderation note is always kept regardless of its Reason, and `--all-rows` keeps everything.

Why a separate file instead of a new tab in the original spreadsheet? Two reasons: writing into an existing Excel file would require third-party libraries (this script is deliberately dependency-free), and keeping the output physically separate guarantees the source files are never touched.

---

## What it flags (and why)

There are two groups of categories with deliberately different matching rules.

### Group 1: Immigration categories - mutually exclusive

Each row gets **at most one** immigration label. Patterns are checked in priority order and the first match wins, so a search is never double-counted across immigration categories. This matters when you want defensible totals ("X immigration-related searches") rather than overlapping ones.

| Category | Matches | Why it's included |
|---|---|---|
| **Immigration - ICE Hold / Detainer** | "ice hold", "ice detainer", "ice warrant", "ice pickup", "ice administrative…" | The most explicit immigration-enforcement phrasing. Checked before the bare ICE pattern so these rows get the more descriptive label. |
| **Immigration - ICE** | the word "ice" standing alone (word-boundary match), anywhere in the reason | Catches "ICE" as the entire reason and inside phrases like "assist ICE with locate". See the false-positive note below - in audit data this almost always means the agency, but verify against your data. |
| **Immigration - HSI** | "HSI", "Homeland Security Investigations" | HSI is ICE's investigative arm. In our dataset this was the single largest immigration category. |
| **Immigration - ERO** | "ERO", "enforcement and removal" | ICE's Enforcement and Removal Operations - the deportation arm. |
| **Immigration - CBP / Border Patrol / USBP** | "CBP", "USBP", "border patrol", "customs and border" | Customs and Border Protection searching an interior city's cameras is worth surfacing on its own. |
| **Immigration - Deportation / Removal** | "deportat…", "removal order", "order of removal" | Explicit deportation language without naming an agency. |
| **Immigration - DHS** | "DHS", "Department of Homeland Security" | Parent department references. |
| **Immigration - USCIS** | "USCIS" | Rare, but it appears. |
| **Immigration - Structured Dropdown** | "Immigration (" | In 2026 Flock replaced free-text reasons with dropdown menus. The immigration option produces reasons like `Immigration (civil/administrative)`. **This pattern must run before the General pattern** - those strings also contain "immigra" and would otherwise be mislabeled. The dropdown change matters for transparency: the detail field is usually blank, so you can no longer tell whether a search was ICE-directed. |
| **Immigration - General** | "immigra…" | The catch-all: "immigration violation", "immigration inv", "assist immigration", etc. Runs last so the more specific labels above take precedence. |

### Group 2: "Iffy" categories - multiple matches 

A single search can legitimately be several things at once (a protest search whose reason field also contains someone's date of birth), so these labels stack. All matched labels are joined with ` | ` in the `Flag_Category` column.

| Category | Matches | Why it's included |
|---|---|---|
| **Protest / Political Surveillance** | "protest(s/ers/ing)", "demonstration(s)", "demonstrators", "DxE", "political sign", "rally/rallies", "picket(ing)", "sit-in" (hyphenated or joined), "activist vehicle" | ALPR networks used to track vehicles at protests and political events. Real examples from our dataset: `"2025 PROTEST"`, `"political signs"`, `"DxE Protest Suspect Vehicle"` (DxE is an animal-rights group). First Amendment activity is not a crime. |
| **Civil Unrest / Riot Response** | "riot(s/ing/ers)", "unrest", "civil disturbance", "looting" | Kept separate from protest because riot response can be legitimate, but it deserves review, especially single-word `"Riot"` reasons with no case number. |
| **Political / Extremist Group Tracking** | "proud boys", "oath keeper", "boogaloo", "antifa", "sovereign citizen", "militia member", "extremist activity", etc. | Tracking people by political-group affiliation rather than by a specific crime. `"Extremist Activity"` with no elaboration appeared in our data as the entire justification for a multi-state camera search. |
| **Racial/Ethnic - Officer Noted No PC or Not Wanted** | "NOT PC", "no probable cause", "not wanted…suspect" | Searches where the officer *wrote in the reason field* that there was no probable cause and the vehicle was not wanted - then ran the search anyway. The agencies flagged themselves. |
| **Racial/Ethnic - Ethnicity as Primary Descriptor** | nationality/ethnicity + crime-group noun: "romanian crew", "asian burglary", "somali gang", "haitian crew", "locating chinese…", and a generic race-word + "gang/crew/crime ring" pattern | Reasons where ethnicity is the *primary* search descriptor instead of a named suspect or a specific crime. This list is fuzzy by design and will need tuning per dataset - see the "Please Improve the Script" section. |
| **Sensitive PII - Race/Gender Codes in Reason** | shorthand codes like `B/M`, `W/F`, `H/M`, `A/F` | Police shorthand (Black Male, White Female, …) entered into a free-text field stored indefinitely on a commercial vendor's servers, usually alongside names and DOBs. |
| **Civil Use - Child / Family Custody** | **any** mention of "custody" except common criminal-custody phrasings ("in custody", "into custody", "escaped custody", "chain of custody", "custody of the suspect/prisoner/fugitive…", "custody status"), plus explicit civil phrases ("custody dispute", "parental custody", "visitation dispute", "parental abduction") | Custody disputes are civil matters. Using a criminal surveillance network to locate vehicles in family-court fights (without a criminal warrant) is a misuse. This pattern is deliberately broad; some criminal-custody language will get through the exclusions. **Review this category's rows by hand before citing them.** |
| **Civil Use - Restraining Order / Civil Matter** | "restraining order", "civil matter", "civil case", order-of-protection acronyms (TPO, OFP, HRO, DVPO, NCPO) | Same logic: civil process is not criminal investigation. Order-of-protection *violations* are crimes, so violation/arrest/warrant phrasing is excluded on every alternative, but free-text is messy and some criminal rows will still land here (e.g. a dropdown assault category with "ofp" in the detail field); review them. |
| **Reproductive Healthcare - Abortion-Related Search** | "abortion(s)", "planned parenthood", "reproductive health/clinic/care", "miscarriage", "mifepristone", "misoprostol", "fetal remains" | In May 2025, a Texas sheriff's office searched ~83,000 Flock cameras nationwide for a woman who self-managed an abortion - the logged reason was literally *"had an abortion, search for female"* (reported by 404 Media; the search reached cameras in Illinois, prompting a state investigation). Post-Dobbs, agencies using ALPR networks to track people over reproductive healthcare is a documented abuse vector. Most datasets will have **zero** hits here - that's the good outcome, but check every time. Some matches may be legitimate (a crime at a clinic); review before citing. |
| **Religious Targeting - Faith-Based Search Descriptor** | "mosque", "muslim", "islamic", "synagogue", "jewish", "sikh", "hindu", "imam", "rabbi", "jewish/buddhist/hindu/sikh temple" | Religion used as a search descriptor, or surveillance of worshippers. The bare words "church" and "temple" are deliberately excluded: in our 1.8M-row test dataset, every "church" hit was the church as a *burglary or theft victim* (plus an officer surnamed Church), and "temple" collides with place names - including them buries the signal in noise. If you suspect faith-institution surveillance phrased via "church", review those rows manually. |
| **Press Freedom - Journalist / Media Targeting** | "journalist", "reporter", "news media", "newsroom", "press pass/credential/conference" | Surveillance of journalists is a canonical ALPR abuse scenario. Zero hits in our test dataset - that's the good outcome, but check every time. The bare word "press" is excluded ("press charges" appears constantly in police logs). |
| **Gender Identity - Trans / LGBTQ+ / Gender-Affirming Care** | "transgender", "trans woman/man/youth…", "gender-affirming", "gender clinic", "LGBTQ", "drag show/queen", "pride parade/event/fest" | Several states criminalize gender-affirming care for minors, and refuge-state camera networks are searchable by agencies from those states - the same interstate abuse vector as the abortion case. Zero hits across 1.8M test rows (the substring "gender" appeared in zero reason fields). Zero is the good outcome; check every time. Bare "trans", "drag", and "pride" are excluded ("transport", "drag racing"). |
| **Private Use - Bail Bond / Bounty Recovery** | "bounty", "bail bond(sman)", "bail recovery", "fugitive recovery agent" | Bounty hunters and bail bondsmen are private commercial actors - locating bail skips for a bond company is not a criminal investigation. "Bail jumping" is deliberately NOT matched: it is itself a crime, and police searching for a bail jumper with a warrant is legitimate. Zero hits in our test dataset. |
| **Personal Use of System** | "my vehicle", "my car", "test my car", "personal vehicle… training" | Officers looking up their own vehicles. Small in count, big in what it says about access controls. |
| **No-Purpose / Open-Ended Search** | "daytime search for best result" | A Flock UI artifact: this exact phrase appears hundreds of times across dozens of unrelated agencies, satisfying the mandatory "reason" field with what is actually a *camera image filter setting*, not an investigative purpose. No crime, no case, no suspect. It demonstrates the audit log's accountability mechanism accepting a button-press as a justification. |
| **Mission Creep - Non-Criminal Use** | "city planning", "traffic analysis", "traffic study", "parking study", "pedestrian count" | A criminal-investigation database used for municipal planning. Whatever you think of traffic studies, they are a different legal basis than criminal investigation, and using the system this way normalizes mass collection. |
| **Sensitive PII - DOB in Reason** | "DOB", "date of birth" | Full dates of birth typed into the reason field, usually alongside full names. |
| **Sensitive PII - ID / License Number in Reason** | "SSN", "social security", driver's-license numbers | Government ID numbers in a free-text field on a vendor's servers. |
| **Sensitive Case - Rape / Child Exploitation in Reason** | "rape suspect", "CSAM", "child porn…", "child exploit…" | These searches may well be legitimate investigations - the issue is that the *case details* now live in a commercial vendor's database, attached to a license-plate search, accessible across the camera-sharing network. (Deliberately excluded: "sex offender", which appears constantly in routine compliance checks and would bury the signal.) |
| **CI / Controlled Buy Operation** | "buy walk", "controlled buy", "drug buy", "CI vehicle", "undercover buy" | Active undercover operations - sometimes with full case numbers - documented in plaintext in a third-party vendor's audit log. An operational-security problem as much as a privacy one. |
| **Highway Interdiction / Travel Profiling** | "interdiction check", "travel pattern", "suspicious traveler", "highway interdiction" | Interdiction policing stops vehicles based on travel-pattern profiling rather than specific criminal information. Our dataset included named individuals run through a multi-state camera network as `"interdiction check <name>"`. |
| **Juvenile Suppression Detail** | "juvenile suppression" | Targeted enforcement sweeps directed at minors, run through an ALPR network. Rare but worth surfacing. |
| **Vendor Moderation Note** | *any non-empty `Moderation` column* (not a keyword pattern - this is a special case checked on every row, even rows whose Reason is blank or redacted) | This column is almost always blank. When Flock itself writes something there, you want to see it. In our dataset, the only moderation notes were Flock disclosing a bug that let searches run against *"a larger set of cameras than intended by the user"*, attached to two ICE-detainer searches by an out-of-state task force that supposedly no longer had access. |

---

## Caveats & limitations

**This is keyword matching, not intelligence.** The script is deliberately a dumb, deterministic, auditable filter - the same input always produces the same output, and anyone can read the regexes and verify what it does. That's the right property for journalism and public-records work, but it means:

- **False positives are expected.** "Ice" can mean methamphetamine in narcotics contexts or a suspect's nickname. "Custody" patterns can catch criminal custodial language despite the lookaheads. Every flagged row should be reviewed by a human before being cited.
- **False negatives are guaranteed.** The script only knows the words it was taught. Misspellings (our dataset had `"whitwortth protest"`, caught only because "protest" was spelled right), novel phrasings, and categories of misuse we haven't seen yet will slip through. **This is the most important limitation - see below.**
- **The standalone-ICE judgment call:** most matches in the ICE category are the bare word "ice" as the entire reason. In our dataset we verified these were agency references by checking companion entries from the same agencies ("ICE pick up", "ICE+ERO", "ice administrative warrant"). You should run the same check on your data before citing the number.
- The output file contains the most sensitive rows from your dataset by design - names, DOBs, case details. Handle it accordingly, and redact before publishing.

## Please Improve the Script

This script gets better only if you run it and report back.

**1. False positives: help hone the patterns.**
If you run this against your data and a category is noisy, please open an issue with the category name and a few example reason strings (redact names/plates as needed). Pattern fixes are usually one-line changes and benefit everyone downstream.

**2. Most importantly - misses: tell me what the script didn't catch.**
If you review your data and find concerning searches this script did **not** flag - an abuse category we haven't thought of, agency-specific phrasing, regional slang, a new Flock UI artifact - please open an issue describing it (or a PR adding the pattern). Every category in this script exists because it showed up in one department's real data. Your dataset will contain things ours didn't. Reporting them is how the next person's Flock audit logs gets analyzed properly.

When reporting, the ideal issue includes: the verbatim reason string (redacted as needed), the agency type, and what you believe it indicates.

---

## Background

This script was developed while analyzing 16 months of Flock Safety audit logs (~1.8 million search records) from St. Louis Park, Minnesota, obtained through a public records request. Findings from that analysis included over 2,500 immigration-related searches by outside agencies through one city's cameras, protest and activist tracking by out-of-state departments, ethnicity-as-descriptor searches, civil custody locates, and Flock's own in-log disclosure of a bug that ran searches against more cameras than users intended.

You can request this same data from your own city. Flock audit logs are public records in most states - ask for the "Audit" and "Network Audit" CSV exports for your local police department, covering as long a date range as they'll give you.

## License

MIT - use it, fork it, improve it.
