# Table columns and field meanings

This document is the cross-directory data dictionary for the released CSV files. Exact column order for coding tables is also machine-readable in `coding_tables.schema.json`. Exact reliability file-family headers are declared in the `reliability_*.schema.json` files.

## Shared storage conventions

- CSV text is UTF-8. `publication_records.csv.gz` is UTF-8 CSV compressed with gzip.
- Empty text means that a value is unavailable or does not apply.
- Boolean fields use lowercase `true` and `false` in corpus tables.
- Fields ending in `_ids` contain zero or more identifiers separated by ` | `.
- Counts use base-10 integers. Years use four digits where known.
- A canonical URL identifies an authoritative publication, dataset, code, or metadata page. It is not a local file path.

## Identifier fields

| Field | Meaning |
|---|---|
| `record_id` | Stable identifier for one enumerated publication record |
| `paper_id` | Stable identifier for one included paper |
| `dataset_id` | Stable identifier for one canonical traffic dataset |
| `use_id` | Identifier for one paper and canonical-dataset association |
| `scheme_id` | Public identifier for one paper-specific class scheme |
| `design_id` | Public identifier for one evaluation design |
| `evidence_id` | Public identifier for one source-located evidence record |
| `rq1_scheme_decision_id` | Identifier for one scheme and RQ1 dimension decision |
| `rq1_dataset_summary_id` | Identifier for one dataset and RQ1 dimension summary |
| `rq2_design_decision_id` | Identifier for one design and RQ2 dimension decision |
| `rq2_paper_summary_id` | Identifier for one paper and RQ2 dimension summary |
| `normalization_id` | Identifier for one structural normalization decision |
| `condition_decision_id` | Identifier for one condition-interpretation decision |

## Methods tables

### `methods/venue_frame.csv`

Columns are `venue`, `abbreviation`, `full_name`, `venue_family`, `start_year`, `end_year`, `dblp_stream_url`, and `venue_specific_handling`.

`venue` is the canonical release name. `abbreviation` and `full_name` provide display forms. `venue_family` is the disciplinary grouping used in summary tables. The year fields define the inclusive frame. `dblp_stream_url` identifies the enumerated DBLP stream. `venue_specific_handling` records rules such as PoPETs article treatment or special-track handling.

### `methods/venue_year_coverage.csv`

Columns are `venue`, `venue_family`, `year`, `enumerated_records`, `retained_records`, `candidate_records`, `included_papers`, `dblp_stream_url`, `dblp_toc_url`, `official_proceedings_url`, `coverage_status`, and `retrieval_date`.

The four count fields reconcile each venue-year cell. The three URL fields identify the DBLP stream, DBLP table of contents, and official provider page. `coverage_status` records whether the cell is represented in the release. `retrieval_date` is the recorded metadata retrieval date.

### `methods/publication_filter_rules.csv`

Columns are `priority`, `scope`, `implemented_condition`, `assigned_publication_type`, `retained_for_candidate_identification`, `reason_code`, and `matched_records`.

`priority` gives rule order. `scope` names the venue or record scope. `implemented_condition` states the operational test. The assigned type, retained flag, and reason code give the resulting disposition. `matched_records` is the mutually exclusive count assigned by the rule set.

## Corpus tables

### `corpus/publication_records.csv.gz`

Columns are `record_id`, `dblp_key`, `title`, `authors`, `venue`, `venue_family`, `year`, `track`, `publication_type`, `pages`, `doi`, `canonical_url`, `dblp_record_url`, `toc_url`, `abstract`, `abstract_source_url`, `dedup_key`, `retrieval_date`, `retained_for_candidate_identification`, `publication_filter_code`, `publication_filter_label`, `candidate_record`, `included_paper`, `final_disposition_code`, and `final_disposition_label`.

The bibliographic fields preserve the enumerated metadata. `abstract` contains available abstract text and `abstract_source_url` identifies its source. `dedup_key` is a normalized DOI key when a DOI exists, otherwise a normalized title, venue, and year key. The retained, candidate, and included flags record movement through the corpus pipeline. Publication-filter and final-disposition fields retain the applicable code and human-readable label.

### `corpus/candidate_records.csv`

Columns are `record_id`, `title`, `venue`, `venue_family`, `year`, `route_G`, `route_R`, `route_P`, `route_membership`, `abstract_available`, `eligibility_decision`, `reason_code`, `reason_label`, and `decision_evidence`.

The three route flags record candidate-search membership. `route_membership` is their exact nonempty combination. `abstract_available` records whether abstract text was available during screening. The remaining fields give the final paper-level eligibility decision and its evidence.

### `corpus/selection_decisions.csv`

Columns are `record_id`, `title`, `venue`, `venue_family`, `year`, `retained_for_candidate_identification`, `candidate_record`, `eligibility_decision`, `reason_code`, `reason_label`, and `decision_evidence`.

This table gives one final disposition for every enumerated record. The retained and candidate flags locate the stage at which an excluded record left the pipeline.

### `corpus/included_papers.csv`

Columns are `paper_id`, `title`, `authors`, `venue`, `venue_family`, `year`, `track`, `publication_type`, `pages`, `doi`, `canonical_url`, `task_family`, `input_unit`, `label_scheme`, `class_cardinality`, `traffic_input_evidence`, `learned_classifier_evidence`, `fixed_label_evidence`, `centrality_evidence`, `evidence_location`, and `evidence_source_url`.

The bibliographic fields identify the included publication. The task, input, label, and cardinality fields summarize paper-level eligibility. The four evidence fields explain traffic observability, learned modeling, fixed labels, and task centrality. The location and source URL identify the supporting source.

### Candidate and flow support tables

| File | Columns | Meaning |
|---|---|---|
| `general_route_components.csv` | `record_id`, `direct_title_pattern`, `abstract_promotion_pattern`, `strong_keyword_recall`, `quality_assurance_sample`, `supplemental_relevance_review`, `primary_component` | Exact Route G membership and component flags |
| `general_route_component_summary.csv` | `primary_component`, `records` | Mutually exclusive Route G component counts |
| `candidate_route_overlap.csv` | `membership`, `records` | Exact candidate-route overlap cells |
| `screening_flow.csv` | `stage`, `records` | Record counts at each screening stage |
| `venue_family_summary.csv` | `venue_family`, `enumerated_records`, `retained_records`, `candidate_records`, `included_papers` | Counts by disciplinary venue family |
| `publication_filter_summary.csv` | `publication_type`, `retained_for_candidate_identification`, `records` | Publication-filter assignments |
| `final_disposition_summary.csv` | `reason_code`, `reason_label`, `records` | Final mutually exclusive record dispositions |
| `exclusion_codes.csv` | `code`, `label`, `definition` | Decision-code dictionary |

## Coding tables

### Dataset and use fields

`canonical_datasets.csv` contains `dataset_id`, `canonical_name`, `origin_type`, `collection_years`, `capture_provenance`, `dataset_boundary_basis`, `canonical_citation_key`, `canonical_citation`, `doi`, `canonical_url`, `identity_confidence`, `paper_ids`, `scheme_ids`, `use_ids`, and `evidence_ids`.

`origin_type` distinguishes self-collected, reused, fresh-recapture, and other source types. `collection_years` records documented capture years. `capture_provenance` describes how traffic was obtained. `dataset_boundary_basis` explains why records were merged into or separated between canonical datasets. Citation and URL fields identify the canonical source. `identity_confidence` records confidence in that identity decision. Identifier lists provide reverse links.

`paper_dataset_uses.csv` contains `use_id`, `paper_id`, `dataset_id`, `reported_names`, `evaluation_roles`, `task_families`, `scheme_ids`, `design_ids`, `complete_scheme_count`, `partial_component_scheme_count`, and `evidence_ids`.

`reported_names` preserves names used by the evaluated paper. `evaluation_roles` records training, validation, testing, calibration, or other roles. The two count fields distinguish complete schemes from component-only schemes for that paper-dataset use.

### Class-scheme fields

`class_schemes.csv` contains `scheme_id`, `paper_id`, `dataset_id`, `task_family`, `task_name`, `label_scheme_key`, `label_semantics`, `class_cardinality`, `cardinality_type`, `class_type`, `input_units`, `design_ids`, `component_roles`, `complete_scheme_in_dataset`, `eligibility_status`, `exclusion_reason`, and `evidence_ids`.

`task_family` is the high-level downstream-task group. `task_name` is the paper-specific task. `label_scheme_key` is a stable description of the exact label mapping. `label_semantics` explains what the classes mean. `class_cardinality` records the number of labels. `cardinality_type` and `class_type` distinguish binary, multiclass, and mixed forms. `input_units` states the classifier input. `component_roles` explains how a partial scheme participates in a multi-dataset design. `complete_scheme_in_dataset` determines RQ1 eligibility together with `eligibility_status`.

### Evaluation-design fields

`evaluation_designs.csv` contains `design_id`, `paper_id`, `task_family`, `task_name`, `label_semantics`, `class_cardinality`, `class_type`, `dataset_ids`, `scheme_ids`, `training_description`, `validation_description`, `test_description`, `split_design_primary`, `split_design_secondary`, `split_unit`, `split_grouping`, `eligibility_status`, `exclusion_reason`, and `evidence_ids`.

The three partition descriptions state what data enter training, validation, and testing. `split_design_primary` names the main construction, while `split_design_secondary` records an additional split property. `split_unit` is the atomic partitioned object. `split_grouping` records the parent grouping applied before sample selection. Eligibility determines whether the design enters RQ2.

### RQ1 fields

`rq1_scheme_decisions.csv` contains `rq1_scheme_decision_id`, `scheme_id`, `paper_id`, `dataset_id`, `dimension`, `outcome`, `condition_pair`, `complete_class_count`, `common_pair_class_count`, `complete_scheme_verified`, `stable_semantics_verified`, `condition_membership_recoverable`, `fresh_parent_traffic_both_values`, `evidence_ids`, `decision_basis`, and `confidence`.

`complete_class_count` is the number of labels in the complete scheme. `common_pair_class_count` is the number present under both contrasted values. The four verification fields record the positive-gate tests. `condition_pair` states the two values. `decision_basis` explains the outcome. `confidence` describes evidentiary confidence.

`rq1_dataset_summary.csv` contains `rq1_dataset_summary_id`, `dataset_id`, `dimension`, `outcome`, `scheme_count`, `supported_scheme_ids`, `documented_no_support_scheme_ids`, and `not_documented_scheme_ids`. It is an any-supported aggregation over complete schemes, with not documented taking precedence over documented no support when no scheme is supported.

### RQ2 fields

`rq2_design_decisions.csv` contains `rq2_design_decision_id`, `design_id`, `paper_id`, `scheme_ids`, `dimension`, `outcome`, `condition_pair`, `complete_scheme_verified`, `condition_grouping_before_sample_split`, `parent_captures_disjoint`, `condition_status`, `evidence_ids`, `decision_basis`, and `confidence`.

The three verification fields record complete-scheme coverage, grouping before sample splitting, and disjoint parent captures or sessions. `condition_status` is a compact final-state description of the design's condition treatment.

`rq2_paper_summary.csv` contains `rq2_paper_summary_id`, `paper_id`, `dimension`, `outcome`, `evaluation_count`, `holdout_design_ids`, `documented_no_holdout_design_ids`, and `not_documented_design_ids`. It is an any-holdout aggregation over eligible designs. A paper with no reconstructable eligible design remains represented as not documented.

### Evidence and normalization fields

`evidence.csv` contains `evidence_id`, `paper_id`, `dataset_id`, `scheme_id`, `design_id`, `dimension`, `evidence_type`, `source_type`, `source_url`, `pdf_page`, `paper_page_label`, `section_or_table`, `evidence_text`, and `confidence`.

Entity identifiers are populated when the evidence applies to that entity. `evidence_type` states the claim supported. `source_type` identifies the source category. Locator fields preserve printed page, document page label, and section or table location where available. `evidence_text` is a concise source-based statement.

`structural_corrections.csv` contains `normalization_id`, `entity_type`, `operation`, `public_entity_ids`, `normalized_field`, `normalized_value`, `evidence_ids`, and `decision_basis`. It records the final normalization operation and retained public targets.

`condition_interpretation_decisions.csv` contains `condition_decision_id`, `record_type`, `decision_record_id`, `outcome`, `condition_pair`, and `decision_basis`. It records the final interpretation projected exactly into the targeted RQ decision.