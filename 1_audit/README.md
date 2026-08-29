# Network traffic classification literature audit

This directory contains the artifacts generated through the literature audit of network traffic classification research published between 2020 and 2025. It presents one consolidated workflow from proceedings enumeration through paper selection, dataset and evaluation normalization and condition coding.

## Headline counts

| Stage or analytical unit | Count |
|---|---:|
| Enumerated publication records | 48,876 |
| Records retained after venue and publication filtering | 43,463 |
| Records outside candidate review | 41,892 |
| Candidate records reviewed | 1,571 |
| Candidate exclusions | 1,462 |
| Included papers | 109 |
| Complete class schemes used for RQ1 | 447 |
| Eligible evaluation designs used for RQ2 | 554 |

## Directory guide

- [`methods/`](methods/README.md) defines the venue frame, publication filtering, candidate searches, eligibility rules, and condition-coding rules. The exact RQ rules are in [`methods/CODING_RULES.md`](methods/CODING_RULES.md).
- [`corpus/`](corpus/README.md) contains the frozen publication universe, candidate frame, final selection decisions, and included-paper metadata.
- [`coding/`](coding/README.md) contains canonical datasets, paper-dataset uses, class schemes, evaluation designs, RQ1 and RQ2 decisions, evidence, and normalization decisions.
- [`results/`](results/README.md) contains summaries regenerated from the released row-level tables.
- [`schemas/`](schemas/README.md) describes public identifiers, fields, enumerations, and table relationships.
- [`scripts/`](scripts/README.md) contains the offline rebuild command.

## Reproduce

The rebuild script require Python 3.9 or newer and use only the Python standard library. It uses only files distributed in this directory and does not require network access.

From this directory, run:

```bash
python3 scripts/rebuild.py
```

## Evidence policy

Coding evidence is source-located. Evidence rows identify the source type, canonical URL where applicable, and a page, section, table, appendix, or metadata locator. The artifact does not redistribute publisher PDFs.