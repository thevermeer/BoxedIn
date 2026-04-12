# BoxedIn

A Chrome extension that combines **defensive network blocking** with an **offensive red-team analysis toolkit** in a single floating overlay. BoxedIn blocks LinkedIn telemetry, extension-fingerprinting probes, and third-party collectors at both the declarativeNetRequest (DNR) and JavaScript API layers, while optionally exposing passive security analysis tools for cookie auditing, exfiltration monitoring, injection surface mapping, and tech-stack reconnaissance.

Manifest V3 · CC0 1.0 License

---

## Table of Contents

- [Architecture](#architecture)
- [Installation](#installation)
- [Defensive Features](#defensive-features)
  - [Bundled DNR Rules](#bundled-dnr-rules)
  - [Page-Guard JS Layer](#page-guard-js-layer)
  - [Per-Host Blocking](#per-host-blocking)
  - [Custom DNR Rules](#custom-dnr-rules)
  - [Hostname Capture](#hostname-capture)
  - [Block Stats Overlay](#block-stats-overlay)
- [Offensive Features (Red-Team Toolkit)](#offensive-features-red-team-toolkit)
  - [Auth Tab](#auth-tab)
  - [Exfil Tab](#exfil-tab)
  - [Inject Tab](#inject-tab)
  - [Recon Tab](#recon-tab)
  - [Request Repeater](#request-repeater)
- [Options Page](#options-page)
- [File Reference](#file-reference)
- [DNR Rule ID Ranges](#dnr-rule-id-ranges)
- [Permissions](#permissions)

---

## Architecture

BoxedIn operates across three execution contexts that communicate through `postMessage`, `chrome.runtime` messaging, and `chrome.storage.local`:

- **page-guard.js** runs in the MAIN world at `document_start` in all frames. It patches `fetch`, `XMLHttpRequest`, `sendBeacon`, DOM insertion methods, and property setters (`src`, `href`, `setAttribute`) to intercept blocked URLs before they leave the page. When red-team mode is enabled, it also scans for sensitive storage tokens, reflected parameters, CSRF gaps, XSS sinks, and tech-stack fingerprints.
- **background.js** is the Manifest V3 service worker. It manages static and dynamic DNR rules, listens to `webRequest` events for header-based analysis (security headers, auth cookies, Set-Cookie issues, CORS, CSP, tech-stack headers), maintains per-tab in-memory data maps, handles the request repeater, and coordinates the enable/disable lifecycle.
- **stats-overlay.js** is the content script (isolated world) injected on every top-level page. It renders the floating overlay panel with tabbed navigation, polls the background for data, and relays page-guard `postMessage` events to the background for storage.

Page-guard posts findings to the overlay via `window.postMessage`. The overlay forwards them to the background via `chrome.runtime.sendMessage` for per-tab storage. Settings and cumulative stats are persisted in `chrome.storage.local`.

---

## Installation

1. Clone or download this repository.
2. Open `chrome://extensions` in Chrome (or a Chromium-based browser).
3. Enable **Developer mode** (toggle in the top-right corner).
4. Click **Load unpacked** and select the `BoxedIn` folder.
5. The extension icon appears in the toolbar. Click it to toggle the extension on/off.

The floating overlay appears at the bottom-left of every page when the extension is enabled.

---

## Defensive Features

### Bundled DNR Rules

Eight static declarativeNetRequest rules ship in `rules.json` (ruleset `ruleset_1`). They block telemetry, tracking, and fingerprinting traffic at the network level before requests leave the browser:

- **Rule 1** — `*linkedin.com/sensorCollect*` — blocks LinkedIn sensor/collect telemetry.
- **Rule 2** — `*chrome-extension://invalid*` — blocks extension-scheme fingerprinting probes.
- **Rule 3** — `*linkedin.com/li/track*` — blocks LinkedIn tracking beacons.
- **Rule 4** — `*collector-pxdojv695v.protechts.net*` — blocks the PerimeterX / Protechts third-party collector.
- **Rule 5** — `*linkedin.com/realtime/realtimeFrontendClientConnectivityTracking*` — blocks realtime connectivity tracking.
- **Rule 6** — `*linkedin.com/tscp-serving*` — blocks TSCP ad/content serving.
- **Rule 7** — `*cs.ns1p.net*` — blocks NS1-related third-party telemetry.
- **Rule 8** — `*linkedin.com/li/tscp/sct*` — blocks TSCP SCT session telemetry (POST).

When the extension is disabled, the entire bundled ruleset is toggled off via `updateEnabledRulesets`.

### Page-Guard JS Layer

`page-guard.js` runs in the MAIN world at `document_start` in every frame, providing a JavaScript-level defense that complements (and cannot be bypassed by) the DNR rules:

- `**fetch()` wrapper** — resolves blocked URLs with a 502 response (no uncaught rejections).
- `**XMLHttpRequest.open()` wrapper** — throws `TypeError` for blocked URLs.
- `**navigator.sendBeacon()` wrapper** — returns `false` for blocked URLs.
- `**src` / `href` property setters** — neutralizes extension-scheme and collector URLs on `HTMLImageElement`, `HTMLIFrameElement`, `HTMLScriptElement`, `HTMLAnchorElement`, and `HTMLLinkElement`.
- `**setAttribute()` wrapper** — catches `src`/`href` attribute assignment.
- **DOM insertion hooks** — patches `appendChild`, `insertBefore`, `replaceChild`, `Element.append`, and `Element.prepend` to drop `<script>` elements whose inline text contains bundled extension-ID probe lists (heuristic: 3+ extension-scheme URLs in 400+ chars of script text).
- **LinkedIn blocklist** — blocks `sensorCollect`, `li/track`, `realtime/realtimeFrontendClientConnectivityTracking`, `tscp-serving`, opaque-token paths (`/[A-Za-z0-9_-]{10,96}` with mixed alphanumeric), and `li/tscp/sct` POST requests.
- **Third-party collectors** — blocks `cs.ns1p.net` and `collector-pxdojv695v.protechts.net`.

Block counts from the JS layer are reported separately in the overlay as **page-guard JS** stats.

### Per-Host Blocking

From the overlay's hostname list, check any hostname to block all sub-resource requests to it. Each checked host creates a dynamic DNR rule (IDs 20000-20499, up to 500 hosts) using `requestDomains`. Hosts can also be managed from the options page.

### Custom DNR Rules

Add up to 50 custom `urlFilter` patterns from the options page. Each pattern becomes a dynamic DNR rule (IDs 10000-10049). Patterns are validated client-side (max 4096 chars, no control characters, not only wildcards) and applied asynchronously by the service worker. Apply status is shown on the options page.

### Hostname Capture

When enabled (off by default), the extension records every unique hostname contacted in each tab via the `webRequest` API. Data is held in memory only (cleared on service worker restart or tab close). The overlay displays the sorted hostname list with per-host block checkboxes. A "Copy all" button exports the list.

### Block Stats Overlay

The floating overlay at the bottom-left of every page shows:

- **Total blocked count** across all rules.
- **Per-rule breakdown** split into "Network & API traffic" and "Extension sniffing" sections.
- **Page-guard JS counts** for LinkedIn blocklist and extension-scheme blocks (independent of DNR).
- Collapse/expand and maximize/restore controls.
- Persistent view state across page loads (`collapsed`, `normal`, `maximized`).

Stats are cumulative across the browser profile and can be reset from the overlay header.

---

## Offensive Features (Red-Team Toolkit)

Enable red-team mode from the options page (`redteamEnabled` checkbox). This activates five additional capabilities in the overlay. All analysis is **passive and local** — no traffic is modified, no requests are injected.

### Auth Tab

Audits authentication and session security with findings grouped by severity (Critical / Warning / Info):

**Critical findings:**

- Authorization headers sent over plain HTTP.
- Session-like cookies (`session`, `token`, `auth`, `sid`, `jwt` in name) missing `HttpOnly`.
- JWT tokens or API key patterns (`sk-`, `AKIA`, `ghp_`, etc.) found in `localStorage` or `sessionStorage`.

**Warning findings:**

- Cookies missing `Secure` flag.
- `SameSite=None` without `Secure`.
- Excessive cookie expiry (>30 days for session-like cookies).
- `Set-Cookie` header issues (missing `HttpOnly`, `Secure`, or `SameSite` misconfigurations).
- Missing security headers: `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`.
- CSP in report-only mode.

**Info findings:**

- Token type classification (JWT, Basic, Bearer) per observed `Authorization` header.
- Cookie inventory with flag summary.

Data sources: `chrome.cookies.getAll()` for the current URL, `webRequest.onBeforeSendHeaders` for request headers, `webRequest.onHeadersReceived` for response headers, and page-guard `scanStorage()` for client-side token detection.

### Exfil Tab

Monitors data exfiltration vectors in real time with a reverse-chronological event stream. Seven event types are tracked:

- **fetch** — captured by page-guard's patched `window.fetch` wrapper.
- **xhr** — captured by page-guard's patched `XMLHttpRequest.open`.
- **clipboard-write** — captured by page-guard's patched `navigator.clipboard.writeText`.
- **clipboard-read** — captured by page-guard's patched `navigator.clipboard.readText`.
- **websocket** — captured by page-guard's wrapped `WebSocket` constructor.
- **form-submit** — captured by page-guard's patched `HTMLFormElement.prototype.submit`.
- **large-request** — detected by the background's `webRequest.onBeforeRequest` listener when a request body exceeds 5KB.

**Third-party alerting:** requests to hostnames other than the current page origin are highlighted in red. Add trusted hosts to the exfiltration allowlist (options page or inline "allow" button) to suppress alerts.

**Filtering:** click subtype buttons (fetch, xhr, clipboard-write, etc.) to filter the stream.

**Repeater integration:** click any event row to open the Request Repeater pre-filled with the captured request's URL, method, headers, and body.

### Inject Tab

Maps the injection attack surface with four analysis sections:

**CSP Analysis:**

- Detects missing Content-Security-Policy headers (Critical).
- Flags `script-src` allowing `unsafe-inline`, `unsafe-eval`, or wildcard `*` (Critical).
- Warns on missing `frame-ancestors` directive (clickjacking risk).
- Flags report-only CSP (not enforced).
- Displays full directive table for manual review.

**CORS Analysis:**

- Flags `Access-Control-Allow-Origin: *` (any origin).
- Flags `Access-Control-Allow-Credentials: true` with permissive origin.

**CSRF Gaps:**

- Scans all `<form>` elements with non-GET methods.
- Flags forms missing hidden inputs matching CSRF token patterns (`csrf`, `_token`, `authenticity_token`, `__RequestVerificationToken`, `antiforgery`).

**XSS Sinks:**

- Monitors `document.write()` calls containing `<script` or `on*=` patterns.
- Monitors all `eval()` calls.
- Flags reflected query parameters and URL fragments found verbatim in `document.body.innerHTML`.

### Recon Tab

Performs passive tech-stack fingerprinting to identify the site's CMS, JavaScript frameworks, analytics services, and server software. Findings are grouped by category with detection evidence and attack-surface notes.

**Detection methods:**

- **Meta tags** (page-guard) — parses `<meta name="generator">` content for CMS signatures like `WordPress 6.x`, `Drupal`, `Joomla`, etc.
- **Window globals** (page-guard) — probes well-known objects such as `window.wp`, `window.React`, `window.__NEXT_DATA__`, `window.jQuery`, `window.ga`, and `window.fbq`.
- **Script/link URL patterns** (page-guard) — scans `document.scripts` and stylesheets for CDN substrings like `wp-content/`, `cdn.shopify.com`, `googletagmanager.com`, and `connect.facebook.net`.
- **Response headers** (background) — extracts technology from `X-Powered-By` and `Server` headers (e.g., `PHP/8.x`, `nginx`, `cloudflare`).

**Detection catalog:**

- **CMS** — WordPress, Drupal, Joomla, Shopify, Squarespace, Wix, Ghost, Webflow.
- **Frameworks** — React, Vue, Angular, jQuery, Next.js, Nuxt, Svelte, Ember, Backbone.
- **Analytics** — Google Analytics, Google Tag Manager, Facebook Pixel, Hotjar, Mixpanel, Segment, Heap, Amplitude.
- **Server** — PHP, Express, Nginx, Apache, ASP.NET, Cloudflare, OpenResty, IIS, Gunicorn, Uvicorn.

Each finding includes an **attack-surface note** summarizing relevant risks. For example: WordPress findings note XML-RPC and plugin/theme CVE exposure; jQuery findings flag DOM XSS via `$.html()` and version-specific CVEs; React findings highlight `dangerouslySetInnerHTML` and client-side state in DevTools; analytics findings warn about PII leakage through query strings and custom dimensions; server header findings flag version disclosure and known CVE risk.

### Request Repeater

A pop-out panel (bottom-right) for replaying captured HTTP requests:

- **Method selector:** GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS.
- **URL input:** pre-filled from exfil event clicks or manual entry.
- **Headers textarea:** one per line (`Name: Value`), browser-managed headers stripped automatically (`Cookie`, `Sec-*`, `Host`, `Connection`, `Content-Length`, `Accept-Encoding`).
- **Body textarea:** for POST/PUT/PATCH payloads.
- **Response viewer:** status badge (color-coded: green 2xx, yellow 3xx, red 4xx/5xx), elapsed time, collapsible response headers, and scrollable response body (up to 50KB).

Requests are executed from the service worker via `fetch()` with `credentials: "include"` and `redirect: "follow"`, preserving the browser's cookie jar for authenticated replay.

---

## Options Page

Open from the extension's context menu or `chrome://extensions` > BoxedIn > Details > Extension options.

- **Hostname capture** — a toggle to record unique hostnames per tab via `webRequest`. Off by default.
- **Bundled rules** — a reference table of the 8 static DNR rules with IDs, patterns, purpose, and removal risk.
- **Blocked hostnames** — lists every host blocked from the overlay, with per-host remove buttons and a "Clear all" action.
- **Custom network block rules** — add, edit, or remove up to 50 `urlFilter` patterns. Patterns are validated on input and apply status is reported after the service worker processes them.
- **Red-team tools** — a toggle to enable the Auth, Exfil, Inject, and Recon tabs in the overlay. Off by default.
- **Exfiltration allowlist** — manage trusted hostnames that won't trigger third-party exfil alerts. The page's own origin is always allowed.
- **Export findings** — downloads all stored data (settings, stats, findings) as a timestamped JSON file (`boxedin-findings-YYYY-MM-DD.json`).

---

## File Reference

- `**manifest.json`** — Manifest V3 declaration: permissions, background service worker, content scripts, and DNR rulesets.
- `**background.js**` — Service worker handling DNR rule management, `webRequest` listeners, per-tab in-memory data maps, header-based analysis, and request replay.
- `**page-guard.js**` — MAIN-world content script injected at `document_start` in all frames. Patches browser APIs to block telemetry and collector URLs, and runs red-team DOM scans when enabled.
- `**stats-overlay.js**` — Isolated-world content script injected at `document_idle` in the top frame. Renders the floating overlay with tabbed panels (Blocks, Auth, Exfil, Inject, Recon) and the Request Repeater.
- `**stats-overlay.css**` — Styles for the overlay and repeater, with light/dark mode support and responsive layout.
- `**rules.json**` — The 8 bundled static DNR block rules.
- `**rules-ids.txt**` — Documents DNR rule ID ranges to prevent overlaps when editing.
- `**options.html**` / `**options.js**` / `**options.css**` — The options page: settings UI, storage read/write, validation, and live change listeners.
- `empty.js` — No-op script reserved for optional DNR redirects.
- `LICENSE` — CC0 1.0 Universal.

---

## DNR Rule ID Ranges

Keep these ranges non-overlapping when adding rules:

- **1 — 9999** — Bundled static rules defined in `rules.json`. Currently IDs 1 through 8 are in use; pick the next free ID when adding a new bundled rule.
- **10000 — 10049** — User-defined custom `urlFilter` patterns, managed as dynamic rules by `background.js`.
- **20000 — 20499** — Per-hostname blocking from the overlay checkboxes, managed as dynamic rules by `background.js` using `requestDomains` conditions.

See `rules-ids.txt` for the canonical reference.

---

## Permissions

- `**declarativeNetRequest`** — required for static and dynamic network block rules.
- `**declarativeNetRequestFeedback**` — enables `onRuleMatched` events so the overlay can show per-rule block counts.
- `**storage**` — persists settings, cumulative stats, blocked hosts, and user rules.
- `**webRequest**` — powers hostname capture, request body capture for the repeater, and header analysis for the red-team toolkit.
- `**contextMenus**` — adds the enable/disable toggle to the toolbar context menu.
- `**scripting**` — dynamically registers `page-guard.js` in the MAIN world when the extension is enabled.
- `**cookies**` — used by the Auth tab to audit cookies for the current URL via `chrome.cookies.getAll()`.
- `**<all_urls>**` (host permission) — allows content scripts and `webRequest` listeners to operate on all sites.

