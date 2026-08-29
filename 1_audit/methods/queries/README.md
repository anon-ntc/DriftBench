# Executable queries

`dblp_universe.sparql` enumerates the 16 publication streams for 2020 through 2025.

`venue_and_publication_filter.py` converts the DBLP tab-separated result into canonical venue names, deduplicates records, assigns stable record identifiers, and applies the ordered publication filtering rules.

The expected tab-separated input columns are `publ`, `stream`, `year`, `title`, `authors`, `toc`, `proceedings`, `venueLabel`, `pages`, `doi`, `documentPage`, and `rdfTypes`. SPARQL clients that prefix variable names with `?` are also accepted. Run the conversion from the package root as:

```bash
python3 methods/queries/venue_and_publication_filter.py INPUT_TSV OUTPUT_CSV
```

The conversion output is the bibliographic and publication-filtering core. The frozen `corpus/publication_records.csv.gz` also supplies venue-family labels, available abstracts and their source URLs, the common retrieval date, candidate membership, and final dispositions. Abstracts were obtained separately from publication enumeration. The release contains 16,652 Semantic Scholar abstracts and 504 abstracts from official venue or publisher pages, for 17,156 available abstracts.

The offline rebuild starts from the frozen compressed publication table. It does not query DBLP or retrieve abstracts.

`candidate_identification.py` reads `../../corpus/publication_records.csv.gz` and `../../corpus/general_route_components.csv`. It reconstructs the grouped title-and-abstract route and the protocol-focused title route from `../candidate_queries.json`, joins the recorded general-route membership, and checks all route and overlap counts.