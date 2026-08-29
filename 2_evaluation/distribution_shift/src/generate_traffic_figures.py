#!/usr/bin/env python3
"""Regenerate the three DriftBench traffic-distribution paper figures."""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg", force=True)
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns


VERSION = "driftbench-open-science-distribution-assets-v1"
FEATURES = (
    "ip_total_length_bytes",
    "ipv4_ttl",
    "tcp_window_raw",
    "iat_us",
    "direction",
    "tcp_flag_pattern",
)
SEQUENTIAL_FEATURES = (
    "signed_ip_total_length_bytes",
    "direction",
    "iat_us",
    "ipv4_ttl",
    "tcp_window_raw",
    "tcp_payload_length_bytes",
)
CONTRASTS = (
    "client_browser",
    "client_os",
    "client_browser_and_os",
    "network",
    "temporal",
)
FEATURE_DISPLAY = {
    "ip_total_length_bytes": "Packet length / size",
    "ipv4_ttl": "IP TTL",
    "tcp_window_raw": "Raw TCP window",
    "iat_us": "Inter-arrival time",
    "direction": "Packet direction",
    "tcp_flag_pattern": "TCP flag pattern",
    "signed_ip_total_length_bytes": "Signed packet length / size",
    "tcp_payload_length_bytes": "TCP payload length",
}
CONTRAST_DISPLAY = {
    "client_browser": "Browser only",
    "client_os": "OS only",
    "client_browser_and_os": "Browser + OS",
    "network": "Network access",
    "temporal": "Temporal",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def save_figure(
    fig: matplotlib.figure.Figure,
    stem: Path,
    *,
    layout_rect: tuple[float, float, float, float] | None = None,
) -> None:
    fig.tight_layout(rect=layout_rect)
    for suffix, metadata in (
        ("png", {"Software": VERSION}),
        ("svg", {"Date": None, "Creator": VERSION}),
        ("pdf", {"CreationDate": None, "ModDate": None, "Creator": VERSION}),
    ):
        fig.savefig(
            stem.with_suffix(f".{suffix}"),
            dpi=180,
            bbox_inches="tight",
            facecolor="white",
            metadata=metadata,
        )
    plt.close(fig)


def render(data_root: Path, output_root: Path) -> None:
    data_root = data_root.resolve()
    output_root = output_root.resolve()
    require(data_root.is_dir(), f"figure-data directory is absent: {data_root}")
    require(not output_root.exists(), f"figure output already exists: {output_root}")
    output_root.mkdir(parents=True)

    heat = pd.read_csv(data_root / "2_distribution_heatmap.csv")
    per_class = pd.read_csv(data_root / "3_per_class_distances.csv")
    sequential = pd.read_csv(data_root / "4_packet_sequence_shifts.csv")
    require(len(heat) == 30, "heatmap row count differs")
    require(len(per_class) == 1080, "per-class row count differs")
    require(len(sequential) == 1195, "first-40 row count differs")
    require(set(heat["feature"]) == set(FEATURES), "heatmap features differ")
    require(set(per_class["feature"]) == set(FEATURES), "per-class features differ")
    require(int(sequential["position"].min()) == 1, "minimum position differs")
    require(int(sequential["position"].max()) == 40, "maximum position differs")
    require(
        not ((sequential["feature"] == "iat_us") & (sequential["position"] == 1)).any(),
        "position-one IAT must remain missing",
    )

    rc = {
        "svg.hashsalt": VERSION,
        "pdf.compression": 9,
        "font.family": "DejaVu Sans",
        "figure.dpi": 100,
        "savefig.dpi": 180,
    }
    palette = dict(zip(CONTRASTS, sns.color_palette("colorblind", len(CONTRASTS))))
    with matplotlib.rc_context(rc), sns.axes_style("whitegrid"):
        pivot = heat.pivot(index="feature", columns="contrast", values="median_distance")
        pivot = pivot.reindex(index=FEATURES, columns=CONTRASTS)
        pivot.index = [FEATURE_DISPLAY[value] for value in pivot.index]
        pivot.columns = [CONTRAST_DISPLAY[value] for value in pivot.columns]
        fig, ax = plt.subplots(figsize=(8.1, 4.8))
        sns.heatmap(
            pivot,
            annot=True,
            fmt=".3f",
            cmap="mako",
            vmin=0,
            vmax=0.5,
            linewidths=0.4,
            cbar_kws={"label": "Median distance"},
            ax=ax,
        )
        ax.set(xlabel="Configuration contrast", ylabel="Traffic characteristic")
        save_figure(fig, output_root / "2_distribution_heatmap")

        fig, ax = plt.subplots(figsize=(10.8, 4.8))
        sns.boxplot(
            data=per_class,
            x="contrast",
            y="distance",
            hue="feature",
            order=list(CONTRASTS),
            hue_order=list(FEATURES),
            showfliers=False,
            linewidth=0.8,
            ax=ax,
        )
        ax.set_xticks(range(len(CONTRASTS)), [CONTRAST_DISPLAY[value] for value in CONTRASTS])
        ax.set(xlabel="Configuration contrast", ylabel="Within-class distance", ylim=(0, 0.55))
        handles, labels = ax.get_legend_handles_labels()
        ax.legend(
            handles,
            [FEATURE_DISPLAY[value] for value in labels],
            title="Traffic characteristic",
            fontsize=7,
            title_fontsize=8,
            ncol=3,
            loc="upper center",
            bbox_to_anchor=(0.5, 1.20),
        )
        save_figure(fig, output_root / "3_per_class_distances")

        fig, axes = plt.subplots(2, 3, figsize=(12.4, 6.4), sharex=True, sharey=True)
        legend_handles = []
        for ax, feature in zip(axes.flat, SEQUENTIAL_FEATURES, strict=True):
            subset = sequential[sequential["feature"] == feature]
            for contrast in CONTRASTS:
                rows = subset[subset["contrast"] == contrast].sort_values("position")
                x = rows["position"].to_numpy(dtype=float)
                median = rows["median"].to_numpy(dtype=float)
                q25 = rows["q25"].to_numpy(dtype=float)
                q75 = rows["q75"].to_numpy(dtype=float)
                (line,) = ax.plot(
                    x,
                    median,
                    label=CONTRAST_DISPLAY[contrast],
                    color=palette[contrast],
                    linewidth=1.35,
                )
                ax.fill_between(x, q25, q75, color=palette[contrast], alpha=0.10)
                if ax is axes.flat[0]:
                    legend_handles.append(line)
            ax.axhline(0.10, color="0.55", linestyle="--", linewidth=0.8)
            ax.axhline(0.20, color="0.55", linestyle=":", linewidth=0.8)
            ax.set_title(FEATURE_DISPLAY[feature], fontsize=9)
            ax.set(xlim=(1, 40), ylim=(0, 1), xticks=(1, 10, 20, 30, 40))
        require(len(legend_handles) == 5, "sequential legend differs")
        fig.legend(
            legend_handles,
            [CONTRAST_DISPLAY[value] for value in CONTRASTS],
            title="Configuration contrast",
            loc="upper center",
            ncol=5,
            fontsize=8,
            title_fontsize=8,
            bbox_to_anchor=(0.5, 1.03),
        )
        fig.supxlabel("Retained packet position")
        fig.supylabel("Median within-class distance")
        save_figure(
            fig,
            output_root / "4_packet_sequence_shifts",
            layout_rect=(0.02, 0.02, 1.0, 0.88),
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    render(args.data_root, args.output_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
