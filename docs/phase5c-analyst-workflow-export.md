# Phase 5C — Scan Context and UI Review Export

The dashboard keeps the configuration used for each successful API response in a separate in-memory context snapshot: target ID and allowlisted label, rule profile ID and label, experimental flag, returned `scan_status`, and the time the browser received the response. The receive time is a local UI record only. It is not a Semgrep execution timestamp, a source snapshot timestamp, or a scan identity. The UI never displays an absolute target path.

Changing the selected target or profile after a response does not change that snapshot. The result panel names the settings that produced the displayed result and warns that a new scan is needed when the current selection differs. A new request clears the previous result before it starts, so an HTTP failure is not combined with stale findings. While scanning, configuration controls remain disabled.

## Markdown UI summary

Use **현재 검사 결과 내보내기** to download a summary of the current API response. The action runs only after an explicit click. It does not call the API, start another Semgrep process, or reproduce the CLI `--format review-md` report. It uses the runtime-validated response already held by the page and includes all Findings in that response (at most 50), regardless of list filters.

The document records the target/profile context, experimental status, browser response receive time, returned scan status, total/displayed/omitted counts, severity counts, issues, limitations, and each displayed Finding's server-provided claim status. Supported claims are copied only when evidence validation is `validated`; restricted claim decisions and reason codes are retained. The exporter does not infer claims or add a scan ID, file hash, source location, or trace.

The UTF-8 output is capped at 512 KiB. Export fails with a fixed UI message if it exceeds the cap; it does not silently remove claims or Findings. When the API omitted Findings, the summary warns that it is incomplete and that the omitted items' individual validation status is unknown.

API-controlled identifiers and paths are escaped for Markdown and HTML delimiter syntax, line breaks, control characters, and Unicode format controls. This reduces injection risk but is not a guarantee for every Markdown renderer or downstream processing pipeline. The summary excludes code, Semgrep free-form messages, raw JSON, stderr, absolute paths, and the API token. The relative paths and rule IDs may still reveal repository structure, so review the file before sharing it.

The browser uses a fixed filename and a temporary Blob URL, revoked after the download click. No automatic download, upload, external request, localStorage, sessionStorage, or report cache is used. Browser downloads do not inherit the CLI's owner-only file permission policy: the browser and operating system determine the save location and permissions, and the file can remain on disk.

## Clearing and retention

**결과 지우기** clears the response, request context, selected Finding, filters, and transient export status from React memory. It does not cancel a running request, delete a downloaded file, or clear the token. The separate token control clears only the in-memory token. Reloading the page clears both token and analysis result because neither is persisted.

## Verification and limits

The UI continues to distinguish `verification_status=unverified` from `evidence_validation_status=validated`. A structurally validated claim is not a confirmed vulnerability. Partial and failed Semgrep states are exported as returned; an HTTP error is not a scan result and cannot be exported. Browser tests cover explicit download, filename/content, profile changes, result clearing, and reload. Automated tests do not establish user comprehension, universal Markdown renderer safety, or filesystem permission guarantees for browser downloads.
