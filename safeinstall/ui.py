"""Streamlit interface for running SafeInstall scans locally."""

import json
from collections import Counter
from pathlib import Path
from typing import Any

from safeinstall.config import SandboxLimits
from safeinstall.contracts import RunArtifacts
from safeinstall.orchestrator import Orchestrator


def load_report(path: str | Path) -> RunArtifacts:
    """Load a persisted report for display."""
    return RunArtifacts.model_validate_json(Path(path).read_text(encoding="utf-8"))


def finding_rows(artifacts: RunArtifacts) -> list[dict[str, Any]]:
    """Convert findings into rows suitable for a Streamlit table."""
    return [
        {
            "severity": finding.severity.value.upper(),
            "rule": finding.rule_id,
            "title": finding.title,
            "evidence_count": len(finding.evidence),
        }
        for finding in artifacts.findings
    ]


def timeline_rows(artifacts: RunArtifacts) -> list[dict[str, Any]]:
    """Convert normalized events into sorted timeline rows."""
    return [
        {
            "time": f"{event.ts:.3f}",
            "source": event.source.value,
            "process": event.process,
            "activity": event.type.value,
            "detail": json.dumps(event.detail, sort_keys=True),
        }
        for event in sorted(artifacts.events, key=lambda event: event.ts)
    ]


def network_rows(artifacts: RunArtifacts) -> list[dict[str, Any]]:
    """Summarize observed network hosts."""
    hosts = Counter(
        str(event.detail["host"])
        for event in artifacts.events
        if event.type.value in {"dns", "net_connect", "http_request"}
        and event.detail.get("host")
    )
    return [{"host": host, "events": count} for host, count in sorted(hosts.items())]


def recent_reports(runs_root: str | Path = "runs", limit: int = 10) -> list[dict[str, Any]]:
    """Discover completed report files for the sidebar run history."""
    reports: list[dict[str, Any]] = []
    root = Path(runs_root)
    if not root.exists():
        return reports

    for report_path in sorted(root.glob("*/report.json"), reverse=True):
        try:
            artifacts = load_report(report_path)
        except Exception:
            continue
        verdict = artifacts.verdict.value if artifacts.verdict else "UNKNOWN"
        reports.append(
            {
                "run_id": artifacts.run_id,
                "input": artifacts.meta.input,
                "verdict": verdict,
                "path": report_path,
            }
        )
        if len(reports) >= limit:
            break
    return reports


def severity_counts(artifacts: RunArtifacts) -> dict[str, int]:
    """Count findings by severity for dashboard metrics."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
    for finding in artifacts.findings:
        key = finding.severity.value.upper()
        counts[key] = counts.get(key, 0) + 1
    return counts


def _css() -> str:
    return """
    <style>
      .stApp { background: linear-gradient(135deg, #f7f9fc 0%, #eef3f8 100%); }
      [data-testid=\"stSidebar\"] {
        background: #0f172a;
        border-right: 1px solid #1e293b;
      }
      [data-testid=\"stSidebar\"] * { color: #e2e8f0; }
      [data-testid=\"stHeader\"] { background: transparent; }
      .block-container { max-width: 1180px; padding-top: 2rem; }
      [data-testid=\"stWidgetLabel\"] p,
      [data-testid=\"stWidgetLabel\"] label,
      label,
      .stSelectbox label,
      .stTextInput label,
      .stNumberInput label {
        color: #172033 !important;
        font-size: 0.95rem !important;
        font-weight: 700 !important;
        opacity: 1 !important;
      }
      [data-baseweb=\"input\"] input,
      [data-baseweb=\"textarea\"] textarea,
      [data-baseweb=\"select\"] span {
        color: #0f172a !important;
      }
      [data-testid=\"stExpander\"] summary,
      [data-testid=\"stExpander\"] summary p,
      [data-testid=\"stExpander\"] summary span {
        color: #f8fafc !important;
        font-weight: 700 !important;
        opacity: 1 !important;
      }
      .hero {
        background: linear-gradient(120deg, #172554 0%, #1d4ed8 58%, #0891b2 100%);
        border-radius: 18px;
        padding: 26px 30px;
        color: white;
        margin-bottom: 18px;
        box-shadow: 0 14px 35px rgba(30, 64, 175, 0.18);
      }
      .hero h1 { color: white; margin: 0 0 6px 0; font-size: 2.2rem; }
      .hero p { color: #dbeafe; margin: 0; }
      .verdict-card {
        border-radius: 16px;
        padding: 22px;
        margin: 8px 0 18px 0;
        border: 1px solid;
      }
      .verdict-block { background: #fff1f2; border-color: #fecdd3; color: #9f1239; }
      .verdict-warning { background: #fffbeb; border-color: #fde68a; color: #92400e; }
      .verdict-green { background: #ecfdf5; border-color: #a7f3d0; color: #065f46; }
      .verdict-card h2 { margin: 0 0 4px 0; }
      .verdict-card p { margin: 0; opacity: 0.85; }
      [data-testid=\"stMetric\"] {
        background: white;
        border: 1px solid #e2e8f0;
        border-radius: 14px;
        padding: 14px;
        box-shadow: 0 5px 16px rgba(15, 23, 42, 0.05);
      }
      [data-testid=\"stDataFrame\"] {
        border: 1px solid #e2e8f0;
        border-radius: 12px;
        overflow: hidden;
      }
      div.stButton > button, div.stDownloadButton > button {
        border-radius: 10px;
        font-weight: 700;
        min-height: 44px;
      }
      div.stButton > button[kind=\"primary\"] {
        background: linear-gradient(90deg, #2563eb, #0891b2);
        border: none;
      }
      .run-row {
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 9px 10px;
        margin-bottom: 8px;
        background: #1e293b;
      }
      .run-row strong { display: block; overflow: hidden; text-overflow: ellipsis; }
      .run-row span { color: #94a3b8; font-size: 0.8rem; }
    </style>
    """


def main() -> None:
    """Run the Streamlit application."""
    import streamlit as st

    st.set_page_config(page_title="SafeInstall", page_icon="🛡️", layout="wide")
    st.markdown(_css(), unsafe_allow_html=True)

    with st.sidebar:
        st.markdown("## 🛡️ SafeInstall")
        st.caption("Pre-flight package analysis")
        st.divider()
        st.markdown("### Recent runs")
        recent = recent_reports()
        if not recent:
            st.caption("No completed reports yet.")
        for run in recent:
            selected = st.button(
                f"{run['input']} · {run['verdict']}",
                key=f"run-{run['run_id']}",
                use_container_width=True,
            )
            if selected:
                st.session_state["artifacts"] = load_report(run["path"])
                st.session_state["run_dir"] = run["path"].parent
        st.divider()
        st.markdown(
            '<div class="run-row"><strong>Safety boundary</strong>'
            '<span>Authorized packages only · Docker isolation</span></div>',
            unsafe_allow_html=True,
        )

    st.markdown(
        '<div class="hero"><h1>SafeInstall Control Room</h1>'
        '<p>Inspect package installs in a disposable, network-jailed sandbox.</p></div>',
        unsafe_allow_html=True,
    )

    with st.expander("Start a new analysis", expanded=True):
        with st.form("scan"):
            ecosystem_col, target_col = st.columns([0.22, 0.78])
            with ecosystem_col:
                ecosystem = st.selectbox("Package type", ["pip", "npm"])
            with target_col:
                target = st.text_input(
                    "Package target",
                    placeholder="requests==2.32.0 · ./demo/evil-pkg · Pillow",
                )
            smoke_col, timeout_col = st.columns([0.62, 0.38])
            with smoke_col:
                smoke = st.text_input(
                    "Smoke-test import (optional)",
                    help="Python import module or Node require module.",
                )
            with timeout_col:
                timeout = st.number_input(
                    "Observation window",
                    min_value=1,
                    max_value=3600,
                    value=120,
                    step=10,
                )
            submitted = st.form_submit_button("Run sandbox analysis", type="primary")

    if submitted:
        if not target.strip():
            st.error("Enter a package target before starting a scan.")
            return
        with st.spinner("Running the package in the sandbox..."):
            try:
                result = Orchestrator(runs_root=Path("runs")).run(
                    ecosystem=ecosystem,
                    target=target.strip(),
                    smoke_module=smoke.strip() or None,
                    limits=SandboxLimits(timeout_seconds=int(timeout)),
                )
                artifacts = load_report(result.run_dir / "report.json")
            except Exception as exc:
                st.error(f"Scan failed: {exc}")
                return
        st.session_state["artifacts"] = artifacts
        st.session_state["run_dir"] = result.run_dir

    artifacts = st.session_state.get("artifacts")
    if not artifacts:
        st.info("Start a scan or select a recent run to view its report.")
        return

    verdict = artifacts.verdict.value if artifacts.verdict else "UNKNOWN"
    if verdict == "BLOCK":
        st.markdown(
            f'<div class="verdict-card verdict-block"><h2>BLOCK</h2>'
            f'<p>{len(artifacts.findings)} findings · critical behavior detected</p></div>',
            unsafe_allow_html=True,
        )
    elif verdict in ("WARNING", "INCONCLUSIVE"):
        st.markdown(
            f'<div class="verdict-card verdict-warning"><h2>WARNING</h2>'
            f'<p>{len(artifacts.findings)} findings · review before proceeding</p></div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="verdict-card verdict-green"><h2>NO SUSPICIOUS BEHAVIOR OBSERVED</h2>'
            '<p>No rules matched during this run.</p></div>',
            unsafe_allow_html=True,
        )

    severity = severity_counts(artifacts)
    peak_mb = (
        f"{artifacts.meta.peak_mem / (1024 * 1024):.1f} MB"
        if artifacts.meta.peak_mem is not None
        else "N/A"
    )
    metric_cols = st.columns(4)
    metric_cols[0].metric("Events", len(artifacts.events))
    metric_cols[1].metric("Findings", len(artifacts.findings))
    metric_cols[2].metric("Peak memory", peak_mb)
    metric_cols[3].metric("Critical findings", severity["CRITICAL"])

    st.caption(
        f"Run `{artifacts.run_id}` · Target `{artifacts.meta.input}`"
        + (
            f" · Exit `{artifacts.meta.exit_code}`"
            if artifacts.meta.exit_code is not None
            else ""
        )
    )

    findings_tab, timeline_tab, network_tab = st.tabs(
        ["Findings", "Event timeline", "Network summary"]
    )
    with findings_tab:
        rows = finding_rows(artifacts)
        if rows:
            st.dataframe(rows, use_container_width=True, hide_index=True)
        else:
            st.success("No rule findings for this run.")
    with timeline_tab:
        rows = timeline_rows(artifacts)
        if rows:
            st.dataframe(rows, use_container_width=True, hide_index=True)
        else:
            st.info("No normalized events captured.")
    with network_tab:
        rows = network_rows(artifacts)
        if rows:
            st.dataframe(rows, use_container_width=True, hide_index=True)
            st.bar_chart(
                {row["host"]: row["events"] for row in rows},
                horizontal=True,
                height=280,
            )
        else:
            st.info("No network hosts captured.")

    run_dir = Path(st.session_state["run_dir"])
    col_json, col_html = st.columns(2)
    with col_json:
        st.download_button(
            "Download JSON report",
            data=(run_dir / "report.json").read_text(encoding="utf-8"),
            file_name=f"{artifacts.run_id}.json",
            mime="application/json",
        )
    with col_html:
        st.download_button(
            "Download HTML report",
            data=(run_dir / "report.html").read_text(encoding="utf-8"),
            file_name=f"{artifacts.run_id}.html",
            mime="text/html",
        )


if __name__ == "__main__":
    main()
