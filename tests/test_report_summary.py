"""
Tests for report_summary.py: fail-closed status and traceable suppression.

Each test runs report_summary.py as a subprocess against a temporary report
directory, exactly as buildspec.yml does, then checks summary.json,
summary.txt, and the SNS subject file.

Run from the repo root:  python3 -m unittest discover tests
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "report_summary.py"
POLICY = REPO / "tools" / "zap-baseline.conf"

EMPTY_SEMGREP = {"results": [], "errors": []}
EMPTY_TRIVY = {"SchemaVersion": 2, "Results": []}
EMPTY_GITLEAKS = []


def zap_report(alerts, site="https://target.example"):
    return {"site": [{"@name": site, "alerts": alerts}]}


def zap_alert(plugin_id, name, risk, count=1):
    return {"pluginid": str(plugin_id), "name": name,
            "riskdesc": f"{risk} (Medium)", "count": str(count)}


class ReportSummaryTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.reports = self.root / "reports"
        self.reports.mkdir()
        self.subject_file = self.root / ".sns_subject"

    def tearDown(self):
        self.tmp.cleanup()

    # -- helpers ----------------------------------------------------------

    def write(self, name, content):
        p = self.reports / name
        p.write_text(content if isinstance(content, str) else json.dumps(content))

    def run_summary(self, target_type, rc, policy=POLICY, report_dir=None):
        env = {
            "PATH": os.environ.get("PATH", ""),
            "REPORT_DIR": str(report_dir or self.reports),
            "SUBJECT_FILE": str(self.subject_file),
            "ZAP_POLICY": str(policy),
            "TARGET_TYPE": target_type,
            "SCAN_RC": str(rc),
            "SCAN_ID": "test-scan",
            "CLIENT_NAME": "test-client",
            "TARGET_DESC": "test-target",
            "REPORT_BUCKET": "test-bucket",
        }
        proc = subprocess.run([sys.executable, str(SCRIPT)], env=env, cwd=self.root,
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        subject = self.subject_file.read_text() if self.subject_file.exists() else None
        out = Path(report_dir or self.reports)
        summary = json.loads((out / "summary.json").read_text()) if (out / "summary.json").exists() else None
        text = (out / "summary.txt").read_text() if (out / "summary.txt").exists() else ""
        return summary, text, subject

    def write_clean_repo_reports(self):
        self.write("semgrep.json", EMPTY_SEMGREP)
        self.write("trivy.json", EMPTY_TRIVY)
        self.write("gitleaks.json", EMPTY_GITLEAKS)

    def assert_not_clean(self, summary, text, subject):
        self.assertNotEqual(summary["status_code"], "CLEAN")
        self.assertNotIn("completed cleanly", text)
        self.assertNotIn(": clean", subject)

    # -- baseline ---------------------------------------------------------

    def test_repo_all_reports_valid_rc0_is_clean(self):
        self.write_clean_repo_reports()
        summary, text, subject = self.run_summary("repo", 0)
        self.assertEqual(summary["status_code"], "CLEAN")
        self.assertEqual(subject, "Scan test-client: clean")

    def test_repo_findings_reported(self):
        self.write_clean_repo_reports()
        self.write("gitleaks.json", [{"RuleID": "aws-key", "Description": "AWS key",
                                      "File": "a.py", "StartLine": 3}])
        summary, text, subject = self.run_summary("repo", 1)
        self.assertEqual(summary["status_code"], "FINDINGS")
        self.assertEqual(summary["total_findings"], 1)

    # -- failed scan / missing report can never be CLEAN --------------------

    def test_missing_report_is_incomplete(self):
        self.write("semgrep.json", EMPTY_SEMGREP)
        self.write("gitleaks.json", EMPTY_GITLEAKS)          # trivy.json missing
        summary, text, subject = self.run_summary("repo", 0)
        self.assertEqual(summary["status_code"], "INCOMPLETE")
        self.assertIn("trivy.json missing", summary["report_problems"])
        self.assert_not_clean(summary, text, subject)

    def test_corrupt_report_is_incomplete(self):
        self.write_clean_repo_reports()
        self.write("semgrep.json", "{not json")
        summary, text, subject = self.run_summary("repo", 0)
        self.assertEqual(summary["status_code"], "INCOMPLETE")
        self.assert_not_clean(summary, text, subject)

    def test_empty_report_file_is_incomplete(self):
        self.write_clean_repo_reports()
        self.write("gitleaks.json", "")
        summary, text, subject = self.run_summary("repo", 0)
        self.assertEqual(summary["status_code"], "INCOMPLETE")
        self.assert_not_clean(summary, text, subject)

    def test_wrong_structure_is_incomplete(self):
        self.write_clean_repo_reports()
        self.write("trivy.json", {"unexpected": True})
        summary, text, subject = self.run_summary("repo", 0)
        self.assertEqual(summary["status_code"], "INCOMPLETE")
        self.assert_not_clean(summary, text, subject)

    def test_web_missing_zap_report_is_incomplete(self):
        # Regression for the July 2026 false clean: ZAP could not write its
        # report, yet the build was green.
        summary, text, subject = self.run_summary("web", 0)
        self.assertEqual(summary["status_code"], "INCOMPLETE")
        self.assertIn("zap.json missing", summary["report_problems"])
        self.assert_not_clean(summary, text, subject)

    def test_web_target_not_reached_is_incomplete(self):
        self.write("zap.json", {"site": []})
        summary, text, subject = self.run_summary("web", 0)
        self.assertEqual(summary["status_code"], "INCOMPLETE")
        self.assert_not_clean(summary, text, subject)

    def test_nonzero_rc_without_findings_is_failed(self):
        self.write_clean_repo_reports()
        summary, text, subject = self.run_summary("repo", 2)
        self.assertEqual(summary["status_code"], "FAILED")
        self.assert_not_clean(summary, text, subject)

    def test_unknown_rc_is_failed(self):
        self.write_clean_repo_reports()
        summary, text, subject = self.run_summary("repo", "unknown")
        self.assertEqual(summary["status_code"], "FAILED")
        self.assert_not_clean(summary, text, subject)

    def test_summary_crash_is_failed_not_clean(self):
        # REPORT_DIR points at a regular file, so the script cannot write its
        # summaries. It must still leave a FAILED subject, never "clean".
        blocker = self.root / "not-a-directory"
        blocker.write_text("x")
        self.run_summary("repo", 0, report_dir=blocker)
        self.assertEqual(self.subject_file.read_text(), "Scan test-client: FAILED")

    def test_stale_subject_is_not_reused(self):
        self.subject_file.write_text("Scan test-client: clean")
        summary, text, subject = self.run_summary("web", 0)   # zap.json missing
        self.assertNotIn(": clean", subject)

    # -- suppression stays traceable --------------------------------------

    def test_suppressed_alerts_listed_with_reason(self):
        self.write("zap.json", zap_report([
            zap_alert(10096, "Timestamp Disclosure - Unix", "Low", 5),
            zap_alert(10038, "Content Security Policy (CSP) Header Not Set", "Medium", 5),
        ]))
        summary, text, subject = self.run_summary("web", 1)
        self.assertEqual(summary["status_code"], "FINDINGS")
        self.assertEqual(summary["total_findings"], 1)
        self.assertEqual(summary["suppressed_count"], 1)
        s = summary["suppressed_findings"][0]
        self.assertEqual(s["id"], "10096")
        self.assertTrue(s["suppression_reason"])
        self.assertIn("Suppressed by policy", text)
        self.assertIn("Reason:", text)
        self.assertIn("10096", text)

    def test_only_suppressed_alerts_is_clean_but_listed(self):
        self.write("zap.json", zap_report([zap_alert(10109, "Modern Web Application", "Informational")]))
        summary, text, subject = self.run_summary("web", 0)
        self.assertEqual(summary["status_code"], "CLEAN")
        self.assertEqual(summary["suppressed_count"], 1)
        self.assertIn("Suppressed by policy", text)

    def test_high_risk_alert_is_never_suppressed(self):
        self.write("zap.json", zap_report([zap_alert(10096, "Timestamp Disclosure - Unix", "High")]))
        summary, text, subject = self.run_summary("web", 0)
        self.assertEqual(summary["suppressed_count"], 0)
        self.assertEqual(summary["counts_by_severity"]["HIGH"], 1)
        self.assertEqual(summary["status_code"], "FINDINGS")
        self.assertIn("never suppressed", text)

    def test_ignore_without_reason_is_not_suppressed(self):
        policy = self.root / "policy.conf"
        policy.write_text("10096\tIGNORE\t(Timestamp Disclosure - Unix)\n")
        self.write("zap.json", zap_report([zap_alert(10096, "Timestamp Disclosure - Unix", "Low")]))
        summary, text, subject = self.run_summary("web", 0, policy=policy)
        self.assertEqual(summary["suppressed_count"], 0)
        self.assertEqual(summary["status_code"], "FINDINGS")
        self.assertIn("no reason recorded", text)

    def test_missing_policy_suppresses_nothing(self):
        self.write("zap.json", zap_report([zap_alert(10096, "Timestamp Disclosure - Unix", "Low")]))
        summary, text, subject = self.run_summary("web", 0, policy=self.root / "absent.conf")
        self.assertEqual(summary["suppressed_count"], 0)
        self.assertIn("not found", summary["suppression_policy"])

    def test_policy_file_every_ignore_has_reason(self):
        for line in POLICY.read_text().splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split("\t")
            self.assertGreaterEqual(len(parts), 3, f"malformed policy line: {line!r}")
            self.assertIn(parts[1], {"FAIL", "WARN", "INFO", "IGNORE"}, line)
            self.assertLessEqual(len(parts), 4, f"reason must not contain tabs: {line!r}")
            if parts[1] == "IGNORE":
                self.assertTrue(len(parts) == 4 and parts[3].strip(), f"IGNORE without reason: {line!r}")


if __name__ == "__main__":
    unittest.main()
