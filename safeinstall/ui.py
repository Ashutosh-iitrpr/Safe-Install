"""Streamlit interface for running SafeInstall scans locally."""

import html
import json
from collections import Counter
from pathlib import Path
from typing import Any

from safeinstall.config import SandboxLimits
from safeinstall.contracts import RunArtifacts
from safeinstall.gateway.proxy import DEFAULT_REGISTRY_ALLOWLIST, hostname as normalize_host
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


def classify_host(host: str) -> str:
    """Classify an observed network host for the Network summary table."""
    norm = normalize_host(host)
    if norm in DEFAULT_REGISTRY_ALLOWLIST:
        return "Allowlisted"
    if norm in {"localhost", "127.0.0.1", "::1", "gateway"} or norm.endswith(".local"):
        return "Internal / Sandbox"
    return "Flagged / External"


def recent_reports(runs_root: str | Path = "runs", limit: int = 10) -> list[dict[str, Any]]:
    """Discover completed report files for the run history."""
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
                "started_at": artifacts.meta.started_at,
                "findings_count": len(artifacts.findings),
                "events_count": len(artifacts.events),
                "exit_code": artifacts.meta.exit_code,
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
      .stApp {
        background: #f8fafc;
        color: #0f172a;
      }
      [data-testid="stHeader"] {
        background: rgba(248, 250, 252, 0.88);
        backdrop-filter: blur(8px);
      }
      [data-testid="stSidebar"] {
        background: #ffffff;
        border-right: 1px solid #e2e8f0;
      }
      [data-testid="stSidebar"] .stMarkdown h2 {
        color: #0f172a;
        font-size: 1.35rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        margin-bottom: 0;
      }
      [data-testid="stSidebar"] .stCaptionContainer p {
        color: #64748b;
        font-size: 0.85rem;
      }
      [data-testid="stSidebar"] hr {
        margin: 0.75rem 0;
      }
      /* Stacked vertical modern navigation tabs in sidebar */
      [data-testid="stSidebar"] div.stButton > button {
        width: 100%;
        display: flex !important;
        justify-content: flex-start !important;
        text-align: left !important;
        border-radius: 10px;
        padding: 10px 14px;
        min-height: 42px;
        font-weight: 600;
        font-size: 0.92rem;
        transition: all 0.15s ease;
        margin-bottom: 4px;
      }
      [data-testid="stSidebar"] div.stButton > button > div {
        width: 100%;
        text-align: left !important;
        justify-content: flex-start !important;
      }
      [data-testid="stSidebar"] div.stButton > button[kind="secondary"] {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        color: #334155;
      }
      [data-testid="stSidebar"] div.stButton > button[kind="secondary"]:hover {
        background: #f1f5f9;
        color: #0f172a;
        border-color: #cbd5e1;
      }
      [data-testid="stSidebar"] div.stButton > button[kind="primary"] {
        background: #eff6ff;
        border: 1px solid #bfdbfe;
        border-left: 4px solid #2563eb !important;
        color: #1d4ed8;
        font-weight: 700;
        box-shadow: 0 1px 3px rgba(37, 99, 235, 0.08);
      }
      [data-testid="stSidebar"] div.stButton > button[kind="primary"]:hover {
        background: #dbeafe;
        color: #1e40af;
      }
      .block-container {
        max-width: 1140px;
        padding-top: 2.2rem;
        padding-bottom: 3rem;
      }
      [data-testid="stWidgetLabel"] p,
      [data-testid="stWidgetLabel"] label,
      .stSelectbox label,
      .stTextInput label,
      .stNumberInput label {
        color: #1e293b !important;
        font-size: 0.9rem !important;
        font-weight: 600 !important;
        opacity: 1 !important;
      }
      [data-baseweb="input"] input,
      [data-baseweb="textarea"] textarea,
      [data-baseweb="select"] span {
        color: #0f172a !important;
      }
      /* Clean light expander card */
      [data-testid="stExpander"] {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 14px;
        box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04);
        margin-bottom: 16px;
      }
      [data-testid="stExpander"] summary,
      [data-testid="stExpander"] summary p,
      [data-testid="stExpander"] summary span,
      [data-testid="stExpander"] summary svg {
        color: #0f172a !important;
        fill: #0f172a !important;
        font-weight: 700 !important;
        font-size: 0.98rem !important;
        opacity: 1 !important;
      }
      .hero {
        background: linear-gradient(125deg, #1e3a8a 0%, #2563eb 55%, #0284c7 100%);
        border-radius: 16px;
        padding: 24px 28px;
        color: #ffffff;
        margin-bottom: 18px;
        box-shadow: 0 10px 28px rgba(37, 99, 235, 0.14);
      }
      .hero h1 {
        color: #ffffff;
        margin: 0 0 6px 0;
        font-size: 1.95rem;
        font-weight: 800;
        letter-spacing: -0.02em;
      }
      .hero p {
        color: #e0f2fe;
        margin: 0;
        font-size: 0.96rem;
      }
      .verdict-card {
        border-radius: 14px;
        padding: 20px 22px;
        margin: 6px 0 16px 0;
        border: 1px solid;
        box-shadow: 0 2px 8px rgba(15, 23, 42, 0.04);
      }
      .verdict-block { background: #fff1f2; border-color: #fecdd3; color: #9f1239; }
      .verdict-warning { background: #fffbeb; border-color: #fde68a; color: #92400e; }
      .verdict-inconclusive { background: #eef2ff; border-color: #c7d2fe; color: #3730a3; }
      .verdict-green { background: #ecfdf5; border-color: #a7f3d0; color: #065f46; }
      .verdict-card h2 { margin: 0 0 4px 0; font-size: 1.35rem; font-weight: 800; }
      .verdict-card p { margin: 0; opacity: 0.9; font-size: 0.94rem; }
      .badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 9999px;
        font-weight: 700;
        font-size: 0.72rem;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        vertical-align: middle;
      }
      .badge-block { background: #fee2e2; color: #991b1b; }
      .badge-warning { background: #fef3c7; color: #92400e; }
      .badge-inconclusive { background: #e0e7ff; color: #3730a3; }
      .badge-clean { background: #dcfce7; color: #166534; }
      .run-card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 12px;
        padding: 12px 16px;
        margin-bottom: 6px;
      }
      .run-card-title {
        font-weight: 700;
        color: #0f172a;
        font-size: 0.96rem;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      }
      .run-card-meta {
        color: #475569;
        font-size: 0.8rem;
        margin-top: 4px;
      }
      .report-meta-bar {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        align-items: center;
        margin: 10px 0 14px 0;
        color: #334155;
        font-size: 0.85rem;
      }
      .meta-pill {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 4px 10px;
        color: #1e293b;
        font-weight: 500;
      }
      .meta-pill-warn {
        background: #fffbeb;
        border-color: #fde68a;
        color: #92400e;
      }
      .evidence-item {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-left: 3px solid #94a3b8;
        border-radius: 8px;
        padding: 8px 12px;
        margin-bottom: 6px;
        font-size: 0.86rem;
        color: #1e293b;
      }
      .evidence-item code {
        color: #0f172a;
        background: #e2e8f0;
        padding: 1px 5px;
        border-radius: 4px;
      }
      @media (max-width: 900px) {
        [data-testid="stHorizontalBlock"] {
          flex-wrap: wrap !important;
          gap: 10px !important;
        }
        [data-testid="stHorizontalBlock"] > [data-testid="stColumn"] {
          flex: 1 1 45% !important;
          min-width: 150px !important;
        }
      }
      [data-testid="stMetric"] {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 12px;
        padding: 14px 16px;
        box-shadow: 0 2px 8px rgba(15, 23, 42, 0.03);
      }
      [data-testid="stMetric"] label {
        color: #475569 !important;
        font-weight: 600 !important;
      }
      [data-testid="stDataFrame"] {
        border: 1px solid #e2e8f0;
        border-radius: 12px;
        overflow: hidden;
        background: #ffffff;
      }
      div.stButton > button, div.stDownloadButton > button {
        border-radius: 10px;
        font-weight: 600;
        min-height: 40px;
      }
      div.stButton > button[kind="primary"] {
        background: linear-gradient(90deg, #2563eb, #0284c7);
        border: none;
        color: #ffffff;
      }
      .sidebar-note {
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        padding: 10px 12px;
        background: #f8fafc;
      }
      .sidebar-note strong {
        display: block;
        color: #0f172a;
        font-size: 0.85rem;
        margin-bottom: 2px;
      }
      .sidebar-note span {
        color: #475569;
        font-size: 0.8rem;
      }
    </style>
    """


def main() -> None:
    """Run the Streamlit application."""
    import streamlit as st
    import streamlit.components.v1 as components

    st.set_page_config(page_title="SafeInstall", layout="wide")
    st.markdown(_css(), unsafe_allow_html=True)

    if st.session_state.pop("scroll_to_top", False):
        components.html(
            """<script>
            const resetScroll = () => {
              const doc = window.parent.document;
              for (const sel of ['[data-testid="stAppViewContainer"]', '[data-testid="stMain"]', 'section.main']) {
                const el = doc.querySelector(sel);
                if (el) el.scrollTop = 0;
              }
              doc.documentElement.scrollTop = 0;
              window.parent.scrollTo(0, 0);
            };
            resetScroll();
            requestAnimationFrame(resetScroll);
            setTimeout(resetScroll, 80);
            </script>""",
            height=0,
        )

    if "active_page" not in st.session_state:
        st.session_state["active_page"] = "SafeInstall"

    with st.sidebar:
        st.markdown("## SafeInstall")
        st.caption("Pre-flight package analysis")
        st.divider()

        active_page = st.session_state["active_page"]
        if st.button(
            "SafeInstall",
            key="nav_safeinstall",
            use_container_width=True,
            type="primary" if active_page == "SafeInstall" else "secondary",
        ):
            st.session_state["active_page"] = "SafeInstall"
            st.rerun()

        if st.button(
            "Recent Runs",
            key="nav_recent_runs",
            use_container_width=True,
            type="primary" if active_page == "Recent Runs" else "secondary",
        ):
            st.session_state["active_page"] = "Recent Runs"
            st.rerun()

        st.divider()
        st.markdown(
            '<div class="sidebar-note"><strong>Safety boundary</strong>'
            '<span>Authorized packages only · Docker isolation</span></div>',
            unsafe_allow_html=True,
        )

    page = st.session_state["active_page"]

    if page == "Recent Runs":
        st.markdown(
            '<div class="hero"><h1>Recent Analysis Runs</h1>'
            '<p>Browse, review, and inspect past package sandbox runs.</p></div>',
            unsafe_allow_html=True,
        )
        reports = recent_reports(limit=50)
        if not reports:
            st.info("No completed reports found in `runs/`.")
            return

        total = len(reports)
        blocked = sum(1 for r in reports if r["verdict"] == "BLOCK")
        warnings = sum(1 for r in reports if r["verdict"] == "WARNING")
        clean = sum(1 for r in reports if "NO SUSPICIOUS" in r["verdict"])
        inconclusive = sum(1 for r in reports if r["verdict"] == "INCONCLUSIVE")

        m_cols = st.columns(5)
        m_cols[0].metric("Total Runs", total)
        m_cols[1].metric("Blocked", blocked)
        m_cols[2].metric("Warnings", warnings)
        m_cols[3].metric("Clean", clean)
        m_cols[4].metric("Inconclusive", inconclusive)

        st.markdown("### Run History")
        filter_col, verdict_col = st.columns([0.65, 0.35])
        with filter_col:
            search_query = st.text_input(
                "Filter runs",
                placeholder="Search by package target or Run ID...",
                label_visibility="collapsed",
            ).strip().lower()
        with verdict_col:
            verdict_filter = st.selectbox(
                "Verdict",
                ["All verdicts", "BLOCK", "WARNING", "CLEAN", "INCONCLUSIVE"],
                label_visibility="collapsed",
            )

        filtered_reports = []
        for r in reports:
            v = r["verdict"]
            if verdict_filter == "CLEAN" and "NO SUSPICIOUS" not in v:
                continue
            elif verdict_filter not in ("All verdicts", "CLEAN") and v != verdict_filter:
                continue
            if search_query and (
                search_query not in str(r["input"]).lower()
                and search_query not in str(r["run_id"]).lower()
            ):
                continue
            filtered_reports.append(r)

        if not filtered_reports:
            st.info("No runs match the current filter.")
            return

        for r in filtered_reports:
            with st.container(border=True):
                c_info, c_btn = st.columns([0.82, 0.18], vertical_alignment="center")
                with c_info:
                    v = r["verdict"]
                    badge_class = "badge-clean"
                    if v == "BLOCK":
                        badge_class = "badge-block"
                    elif v == "WARNING":
                        badge_class = "badge-warning"
                    elif v == "INCONCLUSIVE":
                        badge_class = "badge-inconclusive"

                    safe_input = html.escape(str(r["input"]))
                    safe_run_id = html.escape(str(r["run_id"]))
                    safe_verdict = html.escape(str(v))
                    started_str = r["started_at"].strftime("%b %d, %H:%M UTC")
                    f_count = r["findings_count"]
                    e_count = r["events_count"]
                    f_label = "finding" if f_count == 1 else "findings"
                    exit_str = (
                        f" · Exit {r['exit_code']}"
                        if r.get("exit_code") not in (None, 0)
                        else ""
                    )

                    st.markdown(
                        f'<span class="run-card-title">{safe_input}</span> &nbsp; '
                        f'<span class="badge {badge_class}">{safe_verdict}</span>'
                        f'<div class="run-card-meta">'
                        f"{started_str} · {f_count} {f_label} · {e_count:,} events{exit_str} · "
                        f"Run ID: <code>{safe_run_id}</code>"
                        f"</div>",
                        unsafe_allow_html=True,
                    )
                with c_btn:
                    if st.button("View Report", key=f"view-{r['run_id']}", use_container_width=True):
                        st.session_state["artifacts"] = load_report(r["path"])
                        st.session_state["run_dir"] = r["path"].parent
                        st.session_state["active_page"] = "SafeInstall"
                        st.session_state["scroll_to_top"] = True
                        st.rerun()
        return

    st.markdown(
        '<div class="hero"><h1>SafeInstall Control Room</h1>'
        '<p>Inspect package installs in a disposable, network-jailed sandbox.</p></div>',
        unsafe_allow_html=True,
    )

    has_report = st.session_state.get("artifacts") is not None
    with st.expander("Start a new analysis", expanded=not has_report):
        with st.form("scan", border=False):
            ecosystem_col, target_col = st.columns([0.22, 0.78])
            with ecosystem_col:
                ecosystem = st.selectbox("Package type", ["pip", "npm"])
            with target_col:
                target = st.text_input(
                    "Package target",
                    placeholder="e.g., requests==2.32.0, ./demo/evil-pkg, or left-pad",
                )
            smoke_col, timeout_col = st.columns([0.62, 0.38])
            with smoke_col:
                smoke = st.text_input(
                    "Smoke-test import (optional)",
                    placeholder="e.g., requests, PIL.Image, or left-pad",
                    help="Python import module (for pip) or Node require module (for npm).",
                )
            with timeout_col:
                timeout = st.number_input(
                    "Observation window (seconds)",
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
        st.rerun()

    artifacts = st.session_state.get("artifacts")
    if not artifacts:
        st.info("Start a scan above or browse past reports from Recent Runs.")
        if st.button("Browse Recent Runs", key="empty_browse_runs"):
            st.session_state["active_page"] = "Recent Runs"
            st.rerun()
        return

    verdict = artifacts.verdict.value if artifacts.verdict else "UNKNOWN"
    finding_count = len(artifacts.findings)
    finding_word = "finding" if finding_count == 1 else "findings"

    if verdict == "BLOCK":
        st.markdown(
            f'<div class="verdict-card verdict-block"><h2>BLOCK</h2>'
            f'<p>{finding_count} {finding_word} · critical behavior detected</p></div>',
            unsafe_allow_html=True,
        )
    elif verdict == "WARNING":
        st.markdown(
            f'<div class="verdict-card verdict-warning"><h2>WARNING</h2>'
            f'<p>{finding_count} {finding_word} · review before proceeding</p></div>',
            unsafe_allow_html=True,
        )
    elif verdict == "INCONCLUSIVE":
        exit_note = (
            f" (exit code {artifacts.meta.exit_code})"
            if artifacts.meta.exit_code not in (None, 0)
            else ""
        )
        st.markdown(
            f'<div class="verdict-card verdict-inconclusive"><h2>INCONCLUSIVE</h2>'
            f'<p>Run incomplete or failed{exit_note} · no conclusion can be drawn</p></div>',
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
    metric_cols[0].metric("Events", f"{len(artifacts.events):,}")
    metric_cols[1].metric("Findings", f"{finding_count:,}")
    metric_cols[2].metric("Peak memory", peak_mb)
    metric_cols[3].metric("Critical findings", f"{severity['CRITICAL']:,}")

    started_label = artifacts.meta.started_at.strftime("%b %d, %H:%M UTC")
    exit_pill = ""
    if artifacts.meta.exit_code is not None:
        pill_cls = "meta-pill meta-pill-warn" if artifacts.meta.exit_code != 0 else "meta-pill"
        exit_pill = (
            f'<span class="{pill_cls}">Exit: '
            f'<code>{html.escape(str(artifacts.meta.exit_code))}</code></span>'
        )
    version_pill = (
        f'<span class="meta-pill">Version: <code>{html.escape(str(artifacts.meta.resolved_version))}</code></span>'
        if artifacts.meta.resolved_version
        else ""
    )
    st.markdown(
        f'<div class="report-meta-bar">'
        f'<span class="meta-pill">Started: <code>{html.escape(started_label)}</code></span>'
        f'<span class="meta-pill">Run: <code>{html.escape(str(artifacts.run_id))}</code></span>'
        f'<span class="meta-pill">Target: <code>{html.escape(str(artifacts.meta.input))}</code></span>'
        f"{version_pill}"
        f"{exit_pill}"
        f"</div>",
        unsafe_allow_html=True,
    )

    findings_tab, timeline_tab, network_tab = st.tabs(
        ["Findings", "Event timeline", "Network summary"]
    )
    with findings_tab:
        rows = finding_rows(artifacts)
        if rows:
            st.dataframe(
                rows,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "severity": st.column_config.TextColumn("Severity", width="small"),
                    "rule": st.column_config.TextColumn("Rule", width="medium"),
                    "title": st.column_config.TextColumn("Title", width="large"),
                    "evidence_count": st.column_config.NumberColumn("Evidence", width="small"),
                },
            )
            st.markdown("#### Evidence Details")
            for finding in artifacts.findings:
                sev_label = finding.severity.value.upper()
                with st.expander(
                    f"[{sev_label}] {finding.rule_id} — {finding.title}",
                    expanded=True,
                ):
                    if not finding.evidence:
                        st.caption("No individual evidence entries recorded.")
                    else:
                        for ev in finding.evidence:
                            safe_summary = html.escape(ev.summary)
                            st.markdown(
                                f'<div class="evidence-item">'
                                f"<code>Event #{ev.event_ref}</code> &nbsp; {safe_summary}"
                                f"</div>",
                                unsafe_allow_html=True,
                            )
        elif verdict == "INCONCLUSIVE":
            exit_detail = (
                f" (exit code {artifacts.meta.exit_code})"
                if artifacts.meta.exit_code not in (None, 0)
                else ""
            )
            st.warning(
                f"Run did not complete{exit_detail}; no rule findings were recorded."
            )
        else:
            st.success("No rule findings for this run.")

    with timeline_tab:
        raw_rows = timeline_rows(artifacts)
        if raw_rows:
            base_ts = artifacts.events[0].ts if artifacts.events else 0.0
            if artifacts.events:
                base_ts = min(e.ts for e in artifacts.events)

            all_sources = sorted({r["source"] for r in raw_rows})
            all_activities = sorted({r["activity"] for r in raw_rows})

            t_search_col, t_src_col, t_act_col = st.columns([0.46, 0.27, 0.27])
            with t_search_col:
                tl_query = st.text_input(
                    "Search events",
                    placeholder="Filter by process or detail...",
                    label_visibility="collapsed",
                ).strip().lower()
            with t_src_col:
                tl_source = st.selectbox(
                    "Source",
                    ["All sources"] + all_sources,
                    label_visibility="collapsed",
                )
            with t_act_col:
                tl_activity = st.selectbox(
                    "Activity",
                    ["All activities"] + all_activities,
                    label_visibility="collapsed",
                )

            display_rows = []
            for r in raw_rows:
                if tl_source != "All sources" and r["source"] != tl_source:
                    continue
                if tl_activity != "All activities" and r["activity"] != tl_activity:
                    continue
                if tl_query and (
                    tl_query not in r["detail"].lower()
                    and tl_query not in r["process"].lower()
                ):
                    continue
                rel_ts = max(0.0, float(r["time"]) - base_ts)
                display_rows.append(
                    {
                        "time": f"+{rel_ts:.3f}s",
                        "source": r["source"],
                        "process": r["process"],
                        "activity": r["activity"],
                        "detail": r["detail"],
                    }
                )

            st.caption(f"Showing {len(display_rows):,} of {len(raw_rows):,} events")
            st.dataframe(
                display_rows,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "time": st.column_config.TextColumn("Time", width="small"),
                    "source": st.column_config.TextColumn("Source", width="small"),
                    "process": st.column_config.TextColumn("Process", width="small"),
                    "activity": st.column_config.TextColumn("Activity", width="small"),
                    "detail": st.column_config.TextColumn("Detail", width="large"),
                },
            )
        else:
            st.info("No normalized events captured.")

    with network_tab:
        rows = network_rows(artifacts)
        if rows:
            enriched_net = [
                {
                    "host": row["host"],
                    "events": row["events"],
                    "status": classify_host(row["host"]),
                }
                for row in rows
            ]
            st.dataframe(
                enriched_net,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "host": st.column_config.TextColumn("Host", width="large"),
                    "events": st.column_config.NumberColumn("Events", width="small"),
                    "status": st.column_config.TextColumn("Status", width="medium"),
                },
            )
            try:
                import altair as alt

                max_ev = max(row["events"] for row in rows)
                chart = (
                    alt.Chart(alt.Data(values=rows))
                    .mark_bar(color="#2563eb", cornerRadiusEnd=4, size=22)
                    .encode(
                        x=alt.X(
                            "events:Q",
                            title="Events",
                            scale=alt.Scale(domain=[0, max(max_ev + 1, 2)]),
                            axis=alt.Axis(tickMinStep=1, format="d"),
                        ),
                        y=alt.Y("host:N", title="Host", sort="-x"),
                        tooltip=["host:N", "events:Q"],
                    )
                    .properties(height=max(160, len(rows) * 38 + 40))
                    .configure_view(strokeWidth=0)
                )
                st.altair_chart(chart, use_container_width=True)
            except Exception:
                st.bar_chart(
                    {row["host"]: row["events"] for row in rows},
                    horizontal=True,
                    height=280,
                )
        else:
            st.info("No network hosts captured.")

    run_dir = Path(st.session_state["run_dir"])
    col_json, col_html, _ = st.columns([0.22, 0.22, 0.56])
    with col_json:
        st.download_button(
            "Download JSON",
            data=(run_dir / "report.json").read_text(encoding="utf-8"),
            file_name=f"{artifacts.run_id}.json",
            mime="application/json",
            use_container_width=True,
        )
    with col_html:
        st.download_button(
            "Download HTML",
            data=(run_dir / "report.html").read_text(encoding="utf-8"),
            file_name=f"{artifacts.run_id}.html",
            mime="text/html",
            use_container_width=True,
        )


if __name__ == "__main__":
    main()
