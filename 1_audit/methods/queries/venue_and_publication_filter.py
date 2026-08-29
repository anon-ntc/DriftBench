#!/usr/bin/env python3
"""Normalize a DBLP query export and apply the publication filtering rules."""

from __future__ import annotations

import csv
import re
import sys
from pathlib import Path


VENUES = {
    "sp": "IEEE S&P",
    "ccs": "ACM CCS",
    "uss": "USENIX Security",
    "ndss": "NDSS",
    "sigcomm": "SIGCOMM",
    "nsdi": "NSDI",
    "sigmetrics": "SIGMETRICS",
    "aaai": "AAAI",
    "nips": "NeurIPS",
    "www": "The Web Conference (WWW)",
    "asiaccs": "AsiaCCS",
    "raid": "RAID",
    "dsn": "DSN",
    "popets": "PETS/PoPETs",
    "conext": "CoNEXT",
    "imc": "IMC",
}


def strip_uri(value: str) -> str:
    return str(value or "").strip().removeprefix("<").removesuffix(">")


def field(row: dict[str, str], name: str) -> str:
    return row.get(name, row.get("?" + name, ""))


def canonical_venue(stream: str) -> str:
    return VENUES[strip_uri(stream).rstrip("/").split("/")[-1]]


def main_toc(venue: str, year: int) -> str:
    prefixes = {
        "IEEE S&P": "sp",
        "ACM CCS": "ccs",
        "USENIX Security": "uss",
        "NDSS": "ndss",
        "SIGCOMM": "sigcomm",
        "NSDI": "nsdi",
        "SIGMETRICS": "sigmetrics",
        "AAAI": "aaai",
        "NeurIPS": "neurips",
        "The Web Conference (WWW)": "www",
        "AsiaCCS": "asiaccs",
        "RAID": "raid",
        "DSN": "dsn",
        "PETS/PoPETs": "popets",
        "CoNEXT": "conext",
        "IMC": "imc",
    }
    return prefixes[venue] + str(year)


def classify(record: dict[str, object]) -> tuple[str, str, bool, str]:
    title = str(record["title"]).lower()
    toc = str(record["toc_key"]).lower()
    label = str(record["venue_label"]).lower()
    types = str(record["rdf_types"]).lower()
    expected = main_toc(str(record["venue"]), int(record["year"]))

    if "editorship" in types:
        return "Proceedings metadata record", "Proceedings container", False, "E01"
    if record["venue"] == "PETS/PoPETs" and toc == expected and "article" in types:
        return "PoPETs full research paper presented at PETS", "Full research paper PoPETs article", True, "R01"
    if "article" in types:
        return label or toc, "Journal article cross-listed in conference stream", False, "E01"
    if re.search(r"workshop|soups|cset|woot|foci|bridge|supplement", label + " " + toc):
        return str(record["venue_label"] or record["toc_key"]), "Non-main or associated track", False, "E01"
    if "companion" in label or re.search(r"www\d{4}c$", toc):
        return str(record["venue_label"] or record["toc_key"]), "Companion paper", False, "E01"
    if re.search(r"poster|demo|competition", label + " " + toc + " " + title):
        return str(record["venue_label"] or record["toc_key"]), "Poster demo or competition item", False, "E02"
    if "abstract" in label + " " + title or record["venue"] == "SIGMETRICS" and toc == expected:
        return str(record["venue_label"] or record["toc_key"]), "Abstract-only publication", False, "E02"
    if "short paper" in label or re.search(r"conext2023c$", toc) or record["venue"] == "CoNEXT" and int(record["year"]) >= 2024 and toc == expected:
        return str(record["venue_label"] or record["toc_key"]), "Venue-designated short paper", False, "E02"
    if record["venue"] == "NeurIPS" and toc == "neurips2021db":
        return "Datasets and Benchmarks full archival special track", "Full research paper", True, "R01"
    if toc != expected:
        return str(record["venue_label"] or record["toc_key"]), "Non-main track", False, "E01"
    return "Main research proceedings", "Full-paper status to verify", True, "R01"


def normalized_title(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def clean_doi(value: str) -> str:
    value = strip_uri(value).lower()
    value = re.sub(r"^https?://(?:dx\.)?doi\.org/", "", value)
    return value.rstrip("?").strip()


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: venue_and_publication_filter.py INPUT_TSV OUTPUT_CSV", file=sys.stderr)
        return 2
    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    with input_path.open(newline="", encoding="utf-8") as stream:
        source = list(csv.DictReader(stream, delimiter="\t"))

    seen: set[str] = set()
    records: list[dict[str, object]] = []
    for source_row in source:
        stream_url = strip_uri(field(source_row, "stream"))
        venue = canonical_venue(stream_url)
        year = int(field(source_row, "year").strip('"').split("^")[0])
        title = field(source_row, "title").strip('"')
        doi = clean_doi(field(source_row, "doi"))
        toc_url = strip_uri(field(source_row, "toc"))
        dedup_key = "doi:" + doi if doi else "title:" + normalized_title(title) + "|venue:" + venue + "|year:" + str(year)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        record: dict[str, object] = {
            "record_id": "P" + str(len(records) + 1).zfill(5),
            "dblp_key": strip_uri(field(source_row, "publ")).replace("https://dblp.org/rec/", ""),
            "title": title,
            "authors": field(source_row, "authors").strip('"'),
            "venue": venue,
            "year": year,
            "pages": field(source_row, "pages").strip('"'),
            "doi": doi,
            "canonical_url": strip_uri(field(source_row, "documentPage")),
            "dblp_record_url": strip_uri(field(source_row, "publ")),
            "toc_url": toc_url,
            "toc_key": toc_url.rstrip("/").split("/")[-1],
            "venue_label": field(source_row, "venueLabel").strip('"'),
            "rdf_types": field(source_row, "rdfTypes").strip('"'),
            "dedup_key": dedup_key,
        }
        track, publication_type, retained, reason_code = classify(record)
        record.update(
            {
                "track": track,
                "publication_type": publication_type,
                "retained_for_candidate_identification": str(retained).lower(),
                "publication_filter_code": reason_code,
            }
        )
        records.append(record)

    fields = list(records[0]) if records else []
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(records)
    return 0


if __name__ == "__main__":
    sys.exit(main())

