# Dataset and evaluation coding rules

This document defines the analytical units and decision gates for RQ1 and RQ2. Paper eligibility is defined separately in `ELIGIBILITY_CRITERIA.md`.

## Dataset identity

A canonical dataset is a named traffic corpus or coordinated release with shared capture provenance. Names are merged only when citations or repository identity and sample provenance establish that they refer to the same source traffic. Classes, captures, collection conditions, partitions, filtered subsets, alternate label views, and transformed or repackaged copies remain components of that source. A version that adds newly collected traffic is a separate canonical source. Sources with only partial sample overlap are kept separate unless the evidence establishes one coordinated release boundary.

The dataset registry preserves two traceability-only sources that do not supply a qualifying complete class scheme. Only datasets that supply at least one complete eligible scheme enter the dataset-level RQ1 summary.

## Class schemes

A class scheme is a paper-specific mapping from one dataset's traffic to a fixed set of mutually exclusive labels. Binary and multiclass schemes qualify. Different label granularities and explicitly evaluated subsets are separate records. If two papers evaluate the same canonical dataset and nominal label mapping, each paper has its own scheme record because its reported task, labels, and evidence are paper-specific.

Repeated experiments within one paper do not create repeated schemes when the dataset and label mapping are unchanged. They may create distinct evaluation designs. A component dataset in a cross-dataset evaluation is complete only if it contains every evaluated label. A shared complete label set assembled across several component datasets is represented by one evaluation design linked to those component schemes.

## Collection-condition dimensions

Client, network, and temporal conditions are coded separately. There is no fourth combined-condition outcome. A design that changes more than one dimension may receive a positive code for each dimension whose gate is satisfied.

### Client

Distinct client values require identifiable differences in device or hardware platform, operating system or major version, application or browser, software library, or execution environment.

### Network

Distinct network values require different collection sites or access networks, access technologies, Internet service providers, or upstream providers. A change only in remote service, resolver, route, tunnel, VPN state, Tor circuit or guard, traffic shaping, simulation, or another software-controlled network parameter does not establish a network-condition change.

### Temporal

Distinct temporal values require identifiable, non-overlapping periods or collection campaigns. No minimum elapsed-time threshold is imposed. The code establishes campaign separation, not the magnitude or cause of drift. Replayed, defended, augmented, obfuscated, or otherwise transformed copies do not create a new temporal value.

## RQ1 scheme support

The primary RQ1 coding unit is one complete paper-specific class scheme and one collection-condition dimension. A scheme is `supported` only when all of the following are established:

1. Every label in the complete evaluated scheme appears under both condition values.
2. Label meanings remain stable across the values.
3. Condition membership is recoverable from samples, captures, files, timestamps, or authoritative metadata.
4. Both values represent independently collected parent traffic rather than transformed copies of one capture.

Partial class overlap does not qualify. Dataset-level provenance may support a decision when the evaluated scheme can be linked to that authoritative documentation. Evidence does not have to be repeated verbatim in every paper, but the link between the paper's exact evaluated scheme and the documented dataset must be established.

RQ1 outcomes are:

- `supported`
- `documented_no_support`
- `not_documented`

`documented_no_support` requires evidence that the gate fails. Missing detail is coded `not_documented`, not as a negative. A canonical dataset is supported when any complete scheme associated with it is supported. It is `documented_no_support` only when every associated complete scheme establishes non-support. Otherwise its aggregate outcome is `not_documented`.

The manuscript-facing RQ1 denominator is 447 unique complete scheme records. The alternate dataset aggregation contains 172 canonical datasets.

## RQ2 evaluation holdout

The primary RQ2 coding unit is one evaluated fixed-label task or complete scheme and one materially distinct training, validation, and test construction within a paper. A design is `documented_holdout` for a dimension only when all of the following are established:

1. The complete label scheme is evaluated under two documented values of that condition.
2. Condition membership determines the train and test partition before any sample-level split.
3. Parent captures contributing test samples do not contribute training samples.

The normalized design table records validation construction. The formal positive gate requires train and test separation. It does not by itself assert that validation is condition-disjoint. Target-condition access during feature selection or model selection is retained in the evidence and decision rationale where it affects a specific design.

RQ2 outcomes are:

- `documented_holdout`
- `documented_no_holdout`
- `not_documented`

A random or stratified sample split is `documented_no_holdout` when the source establishes that samples were pooled before splitting. If grouping order or parent independence cannot be reconstructed, the result is `not_documented`. A chronological split qualifies for temporal holdout only when time defines the partition first, the complete scheme is present in the separated periods, and parent traffic is disjoint. Leave-one-condition-out and cross-dataset evaluations qualify only when the held-out grouping represents the audited condition and satisfies the same gate.

Changing the model, feature representation, random seed, cross-validation fold, or reported metric does not create another design. Ordinary cross-validation is one design for the task, not one design per fold. A materially different source-target data construction, partition method, direction, or complete class scheme can create a distinct design. The validation description is part of design identity when it changes what data inform model selection.

An included paper is positive when any eligible design has a documented holdout. It is `documented_no_holdout` only when every eligible design establishes non-holdout. Otherwise it is `not_documented`. A paper whose authoritative record establishes an eligible central task but does not expose a reconstructable design remains in the paper summary as `not_documented` and contributes design row.

The manuscript-facing RQ2 denominator is 554 unique eligible design records. The alternate paper aggregation contains all 109 included papers.

## Evidence and disagreement handling

Coding uses the evaluated paper, its appendices and supplementary material, linked public code or configuration material, authoritative dataset papers or documentation, and repository or publisher metadata when relevant. Evidence records preserve the source type, canonical URL, and page, section, table, appendix, repository, or metadata locator where available.

Paper-specific task definitions and train, validation, and test constructions are taken from evidence tied to that paper. Dataset identity and collection provenance may use authoritative dataset documentation. If evidence conflicts or does not establish the required mapping, grouping order, or parent independence, the corresponding condition outcome is `not_documented`. Missing information is never converted into a negative finding.

Every positive RQ decision links source evidence. Every `not_documented` decision retains linked source-located records and a decision basis describing what could not be established. 