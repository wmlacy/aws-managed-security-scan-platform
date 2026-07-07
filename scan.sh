#!/usr/bin/env bash
# scan.sh — Execute scanners for the configured TARGET_TYPE.
#
# Reads (from environment, set by buildspec.yml):
#   TARGET_TYPE         repo | web | api
#   TARGET_AUTH_HEADER  (web/api) header to inject into ZAP; 'none' or empty = no header
#   TARGET_URL          (web) URL to scan
#   OPENAPI_SPEC        (api) OpenAPI spec URL/path
#   REPORT_DIR          where scanner reports are written
#
# For repo scans, expects target-src/ to already exist in the working
# directory (cloned by buildspec.yml pre_build).
#
# Exits with the worst scanner exit code observed (0 = clean, non-zero
# = at least one scanner found issues or errored). The buildspec
# captures this rather than propagating it, so post_build always
# uploads reports and SNS reflects the true result.

SCAN_RC=0

# Optional ZAP auth header. The secret must hold a value (Secrets
# Manager rejects empty), so 'none' AND empty both mean "no header".
ZAP_AUTH=()
if [ -n "${TARGET_AUTH_HEADER}" ] && [ "${TARGET_AUTH_HEADER}" != "none" ]; then
  ZAP_AUTH=(-z "header=${TARGET_AUTH_HEADER}")
fi

case "${TARGET_TYPE}" in
  repo)
    semgrep scan --error --metrics off --config p/default --json --output "${REPORT_DIR}/semgrep.json" target-src || SCAN_RC=$?
    trivy fs --exit-code 1 --scanners vuln,secret,misconfig --format json --output "${REPORT_DIR}/trivy.json" target-src || SCAN_RC=$?
    gitleaks detect --source target-src --report-format json --report-path "${REPORT_DIR}/gitleaks.json" || SCAN_RC=$?
    ;;
  web)
    # ZAP runs as uid 1000; the bind-mounted REPORT_DIR is root-owned, so
    # the container can't write its reports without this. -j adds the AJAX
    # spider, required to crawl JS/SPA apps the traditional spider misses.
    chmod 777 "${REPORT_DIR}"
    docker run --rm -v "$(pwd)/${REPORT_DIR}:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
      zap-baseline.py -t "${TARGET_URL}" -j -J zap.json -r zap.html \
      "${ZAP_AUTH[@]}" || SCAN_RC=$?
    ;;
  api)
    # See web branch: REPORT_DIR must be writable by the ZAP container user.
    chmod 777 "${REPORT_DIR}"
    docker run --rm -v "$(pwd)/${REPORT_DIR}:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
      zap-api-scan.py -t "${OPENAPI_SPEC}" -f openapi -J zap.json -r zap.html \
      "${ZAP_AUTH[@]}" || SCAN_RC=$?
    ;;
  *)
    echo "Unknown TARGET_TYPE: ${TARGET_TYPE}" >&2
    exit 1
    ;;
esac

echo "Scan finished with rc=${SCAN_RC}" | tee "${REPORT_DIR}/scan_status.txt"
exit "${SCAN_RC}"
