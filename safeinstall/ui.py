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


def main() -> None:
    """Run the Streamlit application."""
    import streamlit as st

    st.set_page_config(page_title="SafeInstall", page_icon="🛡️", layout="wide")
    st.title("SafeInstall")
    st.caption("Run package behavior analysis inside a disposable sandbox.")
    st.warning(
        "Only scan packages you are authorized to analyze. Every scan runs through Docker."
    )

    with st.form("scan"):
        ecosystem = st.selectbox("Ecosystem", ["pip", "npm"])
        target = st.text_input(
            "Package name, version, local path, or URL",
            placeholder="requests==2.32.0 or ./demo/evil-pkg",
        )
        smoke = st.text_input(
            "Smoke-test module (optional)",
            help="Python import module or Node require module.",
        )
        timeout = st.number_input(
            "Observation timeout (seconds)",
            min_value=1,
            max_value=3600,
            value=120,
            step=10,
        )
        submitted = st.form_submit_button("Run analysis", type="primary")

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
        st.info("Enter a target and start a scan to view its report.")
        return

    verdict = artifacts.verdict.value if artifacts.verdict else "UNKNOWN"
    if verdict == "BLOCK":
        st.error(f"Verdict: {verdict}")
    elif verdict == "WARNING":
        st.warning(f"Verdict: {verdict}")
    else:
        st.success(f"Verdict: {verdict}")

    st.caption(f"Run ID: {artifacts.run_id} | Input: {artifacts.meta.input}")
    st.subheader("Findings")
    st.dataframe(finding_rows(artifacts), use_container_width=True, hide_index=True)
    st.subheader("Network summary")
    st.dataframe(network_rows(artifacts), use_container_width=True, hide_index=True)
    st.subheader("Event timeline")
    st.dataframe(timeline_rows(artifacts), use_container_width=True, hide_index=True)

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
