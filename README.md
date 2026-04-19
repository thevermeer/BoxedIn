# BoxedIn

A Chrome extension that combines **defensive network blocking** with an **offensive red-team analysis toolkit** in a single floating overlay. BoxedIn blocks LinkedIn telemetry, extension-fingerprinting probes, and third-party collectors at both the declarativeNetRequest (DNR) and JavaScript API layers, while optionally exposing passive security analysis tools for cookie auditing, exfiltration monitoring, injection surface mapping, and tech-stack reconnaissance.

Manifest V3 · CC0 1.0 License

## Chrome Extension in Development
This simple chrome extension block LinkedIn extension sniffing and teelemetry callback

<img width="739" height="271" alt="image" src="https://github.com/user-attachments/assets/5660d68e-9e09-4ac5-9c5f-f48cb142c973" />

## Installed via Developer Mode
I am not publishing this to Chrome extensions so, to install in Chrome:
- Clone the repo
- Goto to the extensions
- Select `Load Unpacked` in the top-left corner
<img width="423" height="110" alt="image" src="https://github.com/user-attachments/assets/5c42fd0f-1b39-4ae6-bea2-aeecd2330144" />

- Choose the folder and select `open`
- Refresh LinkedIn in Chrome and inspect the JS console.

## Suggestions?
LMK if this works, if you have additional URLs to add, or suggestions on improving the functionality

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
  - [APIs Tab](#apis-tab)
  - [OSINT Tab](#osint-tab)
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
- Exposed secrets in inline scripts and meta tags — scans for 17 secret patterns including AWS access/secret keys, Google API keys, Google OAuth client IDs, Stripe keys, Slack tokens/webhooks, GitHub tokens/PATs, private keys (RSA/EC/DSA/OPENSSH), Mailgun keys, Twilio keys, SendGrid keys, Firebase keys, Heroku API keys, and generic bearer tokens.

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

Data sources: `chrome.cookies.getAll()` for the current URL, `webRequest.onBeforeSendHeaders` for request headers, `webRequest.onHeadersReceived` for response headers, page-guard `scanStorage()` for client-side token detection, and page-guard `scanExposedSecrets()` for secret pattern scanning in DOM content.

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

Maps the injection attack surface with eight analysis sections:

**CSP Analysis:**

- Detects missing Content-Security-Policy headers (Critical).
- Flags `script-src` allowing `unsafe-inline`, `unsafe-eval`, or wildcard `*` (Critical).
- Warns on missing `frame-ancestors` directive (clickjacking risk).
- Flags report-only CSP (not enforced).
- Displays full directive table for manual review.

**CORS Analysis (passive):**

- Flags `Access-Control-Allow-Origin: *` (any origin).
- Flags `Access-Control-Allow-Credentials: true` with permissive origin.

**CSRF Gaps:**

- Scans all `<form>` elements with non-GET methods.
- Flags forms missing hidden inputs matching CSRF token patterns (`csrf`, `_token`, `authenticity_token`, `__RequestVerificationToken`, `antiforgery`).

**XSS Sinks:**

- Monitors `document.write()` calls containing `<script` or `on*=` patterns.
- Monitors all `eval()` calls.
- Flags reflected query parameters and URL fragments found verbatim in `document.body.innerHTML`.

**Open Redirects:**

- Scans URL query parameters for redirect-like names (`redirect`, `next`, `url`, `return`, `returnUrl`, `returnTo`, `goto`, `destination`, `target`, `continue`, `redir`, `forward`, `out`, `link`, `to`).
- Flags parameters whose values start with `http://`, `https://`, `//`, or `/` — indicating potential open redirect vectors.

**Mixed Content:**

- On HTTPS pages, scans all resource-loading elements (`<script>`, `<img>`, `<link>`, `<iframe>`, `<video>`, `<source>`, `<audio>`, `<object>`, `<embed>`) for HTTP URLs.
- Each insecure resource is listed with its tag type and URL.

**CORS Probe (active):**

- A "Test CORS" button sends a fetch from the service worker with `Origin: https://evil-cors-test.example.com` and inspects the response for `Access-Control-Allow-Origin` reflection. Reports whether the server is vulnerable to arbitrary-origin CORS, including wildcard, origin reflection, or `null` ACAO values, with credential escalation noted.

**Form Surface:**

- Enumerates all `<form>` elements on the page with their action URL, method, and fields. For each visible input field, shows the tag, type, name, autocomplete attribute, required status, and pattern constraint.
- Lists standalone inputs (outside any `<form>` tag) separately.
- Useful for mapping the application's input surface, identifying autocomplete risks (e.g., `autocomplete="off"` on password fields), and understanding the data the page collects.

### Recon Tab

Performs passive tech-stack fingerprinting, subdomain enumeration, source map detection, and sensitive path probing. Findings are grouped by category with detection evidence and attack-surface notes.

**Subdomains:**

- Scans all resource-loading elements (`<a>`, `<link>`, `<script>`, `<img>`, `<iframe>`, etc.) and inline script URL references for hostnames that are subdomains of the current page's base domain.
- Lists each discovered subdomain for further investigation.

**Source Maps:**

- Scans `<script>` elements for `//# sourceMappingURL=` comments, `.map` file references in script src attributes, and `<link rel="sourcemap">` elements.
- Source maps in production expose original source code — a significant information leak.

**Sensitive Paths:**

- A "Probe Paths" button sends HEAD requests from the service worker to 30 common paths (`/.env`, `/.git/HEAD`, `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`, `/wp-admin/`, `/graphql`, `/swagger.json`, `/openapi.json`, `/api-docs`, `/phpinfo.php`, `/server-status`, `/actuator`, and more).
- Results are categorized by risk level (Critical, High, Medium, Info) and only found paths (HTTP 2xx/3xx) are displayed.

**DNS Security Audit:**

A "Run DNS Audit" button queries public DNS-over-HTTPS (dns.google) to analyse the domain's DNS configuration. Checks performed:

- **SPF** — Detects missing SPF records (Critical), overly permissive `+all`/`?all` mechanisms (Critical/High), softfail `~all` (Medium), and excessive DNS lookups nearing the 10-lookup limit.
- **DMARC** — Detects missing `_dmarc` TXT records (Critical), monitoring-only `p=none` policy (High), missing aggregate report address `rua=` (Medium), and verifies `p=quarantine` or `p=reject` enforcement.
- **DKIM** — Probes 9 common DKIM selectors (`default._domainkey`, `google._domainkey`, `k1._domainkey`, `selector1._domainkey`, `selector2._domainkey`, `s1._domainkey`, `s2._domainkey`, `dkim._domainkey`, `mail._domainkey`) for DKIM1 records.
- **DNSSEC** — Checks for DNSKEY records and the AD (Authenticated Data) flag indicating DNSSEC validation.
- **CAA** — Detects missing Certificate Authority Authorization records (any CA can issue certs) and lists authorized issuers when present.
- **MX** — Inventories mail servers and identifies the mail provider (Google Workspace, Microsoft 365, ProtonMail, Mimecast, Proofpoint, etc.).
- **NS** — Lists nameservers and flags single-provider risk (all NS at one registrar).
- **CNAME** — Checks `www.<domain>` for CNAME targets (useful for identifying hosting/CDN providers and potential dangling CNAME takeover).

Results are sorted by severity (Critical > High > Medium > Info) with a summary count line.

**Tech-stack fingerprinting:**

Identifies the site's CMS, JavaScript frameworks, analytics services, and server software. Where possible, version numbers are extracted automatically.

**Detection methods (7 layers):**

- **Meta tags** (page-guard) — parses `<meta name="generator">` and `<meta name="application-name">` content for CMS signatures. Extracts version numbers where present (e.g., `WordPress 6.4`, `Drupal 10.2`, `Hugo 0.120`).
- **Window globals** (page-guard) — probes 30+ well-known objects including `window.wp`, `window.React`, `window.Vue`, `window.__NEXT_DATA__`, `window.__NUXT__`, `window.__remixContext`, `window.__GATSBY`, `window.htmx`, `window.Alpine`, `window.Turbo`, `window.jQuery`, `window.ga`, `window.gtag`, `window.dataLayer`, `window.fbq`, `window.plausible`, `window._paq`, `window.clarity`, and `window.webpackJsonp`. Extracts runtime versions from `React.version`, `Vue.version`, `angular.version.full`, `jQuery.fn.jquery`, `jQuery.ui.version`, and `_.VERSION`.
- **DOM attribute probes** (page-guard) — scans for framework signatures in the DOM: `data-reactroot`, `data-reactid`, `data-react-helmet` (React); `ng-version` with version extraction (Angular); `data-v-`, `data-vue-app`, `#__vue_app__` (Vue); `data-svelte` (Svelte); `#__next` (Next.js), `#__nuxt` (Nuxt), `#___gatsby` (Gatsby); `data-turbo`, `data-turbo-frame` (Turbo); `data-controller` (Stimulus); `x-data`, `x-init`, `x-bind` (Alpine.js); `hx-get`, `hx-post`, `hx-trigger` (HTMX); `astro-island`, `astro-slot` (Astro).
- **HTML comment/content probes** (page-guard) — scans the first 8 KB of HTML for embedded signatures like WordPress comments, Drupal footprints, Hugo generator tags, and Vite client scripts.
- **Script/link URL patterns** (page-guard) — scans `document.scripts` and stylesheets using precise CDN and path patterns (70+ patterns) to avoid false positives. Patterns target specific CDN hostnames (`code.jquery.com`, `cdn.jsdelivr.net/npm/vue`, `unpkg.com/react`, `stackpath.bootstrapcdn.com`) and unambiguous path segments (`/react.`, `/vue@`, `/_next/`, `bootstrap.min.js`).
- **Script URL version extraction** (page-guard) — parses version numbers from script URLs using the pattern `/@-<semver>` (e.g., `jquery-3.7.1.min.js` → jQuery 3.7.1, `vue@3.4.21` → Vue 3.4.21). Updates any previously version-less finding with the discovered version.
- **Response headers** (background) — extracts technology from `X-Powered-By`, `Server`, `X-Generator`, `X-Drupal-Cache`, `X-Drupal-Dynamic-Cache`, `X-WordPress`, `X-Pingback`, `X-Shopify-Stage`, `X-Shopid`, `X-ASPNet-Version`, `X-ASPNetMvc-Version`, `X-Varnish`, `Via`, and `X-Turbo-Charged-By` headers.
- **Set-Cookie fingerprinting** (background) — identifies server-side technologies from cookie names: `PHPSESSID` (PHP), `ASP.NET_SessionId` (ASP.NET), `JSESSIONID` (Java Servlet), `laravel_session`/`XSRF-TOKEN` (Laravel), `csrftoken`/`django_language` (Django), `connect.sid` (Express), `_rails-session`/`rack.session` (Rails), `wp-settings-*`/`wordpress_logged_in`/`wordpress_test_cookie` (WordPress), `_shopify_s`/`_shopify_y` (Shopify), `drupal` (Drupal), `joomla_user_state` (Joomla).
- **Tailwind CSS heuristic** (page-guard) — detects Tailwind by counting elements with characteristic utility classes (`flex`, `grid`, `text-*`, `bg-*`, `px-*`, `py-*`, `mt-*`, `mb-*`); reports when five or more matches are found.

**Detection catalog:**

- **CMS** — WordPress, Drupal, Joomla, Shopify, Squarespace, Wix, Ghost, Webflow, Hugo, Jekyll, Contentful, Strapi, Sanity, Prismic.
- **Frameworks / Libraries** — React, Preact, Vue, Angular, AngularJS, jQuery, jQuery UI, Lodash, Underscore, Next.js, Nuxt, Gatsby, Remix, Astro, Svelte, SvelteKit, Ember, Backbone, Alpine.js, HTMX, Turbo, Stimulus, Lit, Stencil, Bootstrap, Tailwind CSS, Foundation, Material UI, Vite, Webpack.
- **Analytics** — Google Analytics, Google Tag Manager, Facebook Pixel, Hotjar, Mixpanel, Segment, Heap, Amplitude, Plausible, Matomo, Microsoft Clarity.
- **Server** — PHP, Express, Nginx, Apache, ASP.NET, Cloudflare, OpenResty, IIS, Gunicorn, Uvicorn, Kestrel, Cowboy, Jetty, Tomcat, LiteSpeed, Caddy, Deno, Tornado, Werkzeug, Flask, Django, Laravel, Ruby on Rails, Phusion Passenger, Varnish, Next.js (server), Nuxt (server), Java Servlet.

Each finding includes an **attack-surface note** summarizing relevant risks. For example: WordPress findings note XML-RPC and plugin/theme CVE exposure; jQuery findings flag DOM XSS via `$.html()` and version-specific CVEs; AngularJS findings highlight EOL status and known sandbox escapes; HTMX findings warn about hx-* attribute injection; Bootstrap findings reference XSS in tooltip/popover for older versions; cookie findings identify the server-side stack even when response headers are stripped; analytics findings warn about PII leakage through query strings and custom dimensions; server header findings flag version disclosure and known CVE risk.

### APIs Tab

Enumerates API endpoints discovered in the page through five complementary detection layers. Findings are split into two groups — **Found in Code** (static analysis) and **Observed at Runtime** (from captured fetch/XHR traffic).

**Detection layers:**

- **Layer 1 — Inline script regex** (page-guard) — walks inline `<script>` elements and matches URL-like strings from common API call patterns: `fetch("...")`, `axios.get/post/put/delete/patch("...")`, `$.ajax({url: "..."})`, `$.get("...")`, `$.post("...")`, `XMLHttpRequest .open("METHOD", "...")`, and string literals matching REST path patterns (`/api/`, `/v[0-9]/`, `/graphql`, `/rest/`, `/webhook`).
- **Layer 2 — Window config probing** (page-guard) — enumerates well-known global config shapes (`window.__CONFIG__`, `window.__APP_CONFIG__`, `window.__SETTINGS__`, `window.ENV`, `window.__ENV__`, `window.config`, `window.appConfig`, `window.settings`) and framework-specific objects (`window.__NEXT_DATA__.props`, `window.__NUXT__`, `window.__remixContext`). Deep-scans one level of each object for string values matching `https?://` or API path patterns.
- **Layer 3 — DOM attribute scan** (page-guard) — scans `<form action="...">`, `<a href="...">`, and data attributes (`data-api-url`, `data-api-endpoint`, `data-url`, `data-endpoint`) for API-like URL patterns.
- **Layer 4 — Runtime fetch/XHR capture** (background) — filters the existing exfil event stream for unique fetch/XHR URLs matching API path patterns (`/api/`, `/v[0-9]/`, `/graphql`, `/rest/`, `/webhook`). These appear in the "Observed at Runtime" section.
- **Layer 5 — Script src path patterns** (page-guard) — scans external `<script src="...">` URLs for API-suggestive paths.

**Display:**

- Each endpoint row shows a color-coded HTTP method badge (GET green, POST blue, PUT orange, DELETE red, PATCH orange, other gray), the URL, and the evidence/context snippet.
- Static findings are grouped by origin (Inline Scripts, Window Config Objects, DOM Attributes, Script Sources).
- Runtime findings are listed separately with their observed method.

**Data flow:** page-guard emits findings via `postMessage` with `type: "api"`. The overlay forwards them to the background via `BOXEDIN_STORE_API_FINDING` (deduplicated by URL, capped at 200 per tab). The APIs panel fetches both static findings and runtime API URLs via `BOXEDIN_GET_API_FINDINGS`.

### Deps Tab

Analyses the page's external dependencies for supply chain risks.

- **Third-party without SRI** — lists all third-party `<script>` and `<link rel="stylesheet">` elements that lack a `integrity` attribute. These are vulnerable to supply chain attacks if the hosting CDN is compromised.
- **Third-party dependencies** — full inventory of all third-party scripts and stylesheets, showing the host, URL, SRI status, and whether `async`/`defer` attributes are set.
- **First-party resources** — lists same-origin scripts and stylesheets for completeness.

**Data flow:** page-guard's `scanDependencies()` enumerates all `<script src>` and `<link rel="stylesheet" href>` elements, classifies each as first-party or third-party, and checks for SRI attributes. Findings are forwarded to the background via `BOXEDIN_STORE_DEPS_FINDING` (capped at 200 per tab).

### Timeline Tab

Provides a chronological view of all network and data-flow events captured during the page session.

- Merges exfiltration events (fetch, XHR, clipboard, WebSocket, form submit) with any additional timeline events, sorted by timestamp.
- Each row shows the wall-clock time, relative offset from the first event, event type badge (color-coded by severity), HTTP method (if applicable), and URL.
- Useful for understanding authentication flows, request sequencing, and identifying unexpected network activity.

**Data flow:** the timeline merges events from `exfilEventsByTab` and `timelineEventsByTab` in the background, sorted chronologically, and returns them via `BOXEDIN_GET_TIMELINE`.

### Export Button

A download arrow (⬇) button in the overlay header (visible when red-team mode is enabled) exports all in-memory findings for the current tab as a structured JSON report. The report includes:

- Auth findings (request headers, cookies, security headers, page-guard storage/secret scans)
- Exfiltration events
- Injection findings (CSP, CORS, CSRF, XSS, open redirects, mixed content, form inventory)
- Tech-stack findings
- API endpoints
- Dependencies (with SRI status)
- Timeline events
- Subdomain and source map discoveries
- A **severity summary** counting Critical, High, Medium, Low, and Info findings

The file is named `boxedin-report-YYYY-MM-DD.json`.

### OSINT Tab

Integrates with fourteen public OSINT search engines — **crt.sh**, **Shodan**, **WHOIS**, the **Wayback Machine**, **Intelligence X**, **urlscan.io**, **Censys**, **Domain Dossier**, **PhishTank**, **FOFA**, **Companies House**, **SecurityTrails**, **Have I Been Pwned**, and **DeHashed** — to perform external reconnaissance on domains and hosts. Searches open in a new browser tab; no API keys or accounts are required for basic lookups.

The OSINT panel is divided into fourteen sections:

**crt.sh — Certificate Transparency**

- **One-click search** — the current page's domain is shown with a "Search crt.sh" button that opens `https://crt.sh/?q=<domain>` in a new tab.
- **Manual domain input** — a text field for searching arbitrary domains not tied to the current page.
- Certificate transparency logs reveal every SSL/TLS certificate ever issued for a domain, which is useful for discovering subdomains (including staging, internal, and forgotten environments), identifying certificate misconfigurations, and mapping the full scope of an organization's public-facing infrastructure.

**Shodan — Internet-Wide Scan Data**

- **One-click search** — the current page's domain is shown with a "Search Shodan" button that opens `https://www.shodan.io/search?query=<domain>` in a new tab.
- **Manual query input** — a text field for searching arbitrary domains or IP addresses.
- Shodan indexes internet-facing hosts and reveals open ports, running services, SSL certificate details, banner data, known vulnerabilities, and organizational metadata. Useful for mapping exposed infrastructure and identifying misconfigured or forgotten services.

**WHOIS — Domain Registration**

- **One-click lookup** — the current page's domain is shown with a "WHOIS Lookup" button that opens `https://who.is/whois/<domain>` in a new tab.
- **Manual domain input** — a text field for looking up arbitrary domains.
- WHOIS records reveal domain registration details including the registrant organization, registrar, creation and expiry dates, name servers, and contact information. Useful for identifying domain ownership, spotting recently registered or expiring domains, and correlating infrastructure across organizations.

**Wayback Machine — Web Archive**

- **One-click search** — the current page's domain is shown with a "Search Wayback" button that opens `https://web.archive.org/web/*/<domain>` in a new tab.
- **Manual domain input** — a text field for searching arbitrary domains.
- The Wayback Machine (Internet Archive) indexes historical snapshots of web pages over time. Useful for finding removed pages, leaked or exposed content, old configurations, previous versions of login flows, deprecated API endpoints, and tracking how a site's security posture has changed.

**Intelligence X — Deep Search**

- **One-click search** — the current page's domain is shown with a "Search IntelX" button that opens `https://intelx.io/?s=<domain>` in a new tab.
- **Manual query input** — a text field for searching arbitrary selectors (domains, email addresses, IPs, CIDRs, etc.).
- Intelligence X indexes pastes, darknet content (Tor/I2P), leaked databases, WHOIS history, DNS records, and public web archives. The free tier allows 50 lookups per day. Useful for discovering leaked credentials, exposed data, historical DNS/WHOIS changes, and darknet mentions of a target domain or organization.

**urlscan.io — URL & Domain Scanner**

- **One-click search** — the current page's domain is shown with a "Search urlscan" button that opens `https://urlscan.io/search/#domain:<domain>` in a new tab.
- **Manual domain input** — a text field for searching arbitrary domains.
- urlscan.io scans and analyses URLs/domains for malicious indicators, HTTP transactions, DOM snapshots, technology stacks, and third-party resources. Useful for understanding what a page loads, detecting malicious redirects, and identifying tracker infrastructure.

**Censys — Internet-Wide Host Search**

- **One-click search** — the current page's domain is shown with a "Search Censys" button that opens `https://search.censys.io/search?resource=hosts&q=<domain>` in a new tab.
- **Manual query input** — a text field for searching arbitrary domains or IPs.
- Censys provides internet-wide scan data covering hosts, certificates, open ports, and services. Free accounts allow 250 queries per month. Useful for discovering exposed services, certificate transparency data, and mapping an organisation's internet-facing attack surface.

**Domain Dossier — DNS & WHOIS Report**

- **One-click search** — the current page's domain is shown with a "Run Dossier" button that opens `https://centralops.net/co/DomainDossier.aspx?addr=<domain>&dom_whois=true&dom_dns=true&net_whois=true` in a new tab.
- **Manual domain input** — a text field for searching arbitrary domains or IPs.
- Domain Dossier (CentralOps.net) runs DNS, domain WHOIS, and network WHOIS lookups in a single combined report. Useful for quick one-page reconnaissance when you need DNS records, registrar info, and network ownership all at once.

**PhishTank — Phishing URL Database**

- **One-click search** — the current page's domain is shown with a "Search PhishTank" button that opens `https://phishtank.org/phish_search.php?search=<domain>&action=search` in a new tab.
- **Manual domain input** — a text field for searching arbitrary domains.
- PhishTank is a community-driven database of verified phishing URLs operated by Cisco/OpenDNS. Useful for checking whether a domain has been reported for phishing activity, validating suspicious links, and assessing domain reputation.

**FOFA — Cyberspace Search Engine**

- **One-click search** — the current page's domain is shown with a "Search FOFA" button that opens `https://en.fofa.info/result?qbase64=<base64(domain="<domain>")>` in a new tab.
- **Manual domain input** — a text field for searching arbitrary domains.
- FOFA is a Chinese cyberspace mapping engine similar to Shodan and Censys. It indexes hosts, ports, protocols, banners, and web components globally. Free tier available. Useful as a complementary asset-discovery source with different crawling coverage and indexing.

**Companies House — UK Company Registry**

- **One-click search** — the current page's domain is shown with a "Search Companies House" button that opens `https://find-and-update.company-information.service.gov.uk/search?q=<domain>` in a new tab.
- **Manual query input** — a text field for searching by company name or domain.
- Companies House is the official UK government registry of companies. Useful for identifying the legal entity behind a domain, finding director names, registered addresses, filing history, and accounts — key data for social engineering assessments and target profiling.

**SecurityTrails — DNS History & Intelligence**

- **One-click search** — the current page's domain is shown with a "View DNS History" button that opens `https://securitytrails.com/domain/<domain>/dns` in a new tab.
- **Manual domain input** — a text field for searching arbitrary domains.
- SecurityTrails provides historical DNS records, WHOIS changes, associated domains, subdomain enumeration, and hosting history. The free tier allows limited lookups. Useful for tracking infrastructure changes, discovering related domains, finding previous IP addresses, and identifying hosting patterns over time. Complements the built-in DNS Security Audit with historical perspective.

**Have I Been Pwned — Domain Breach Search**

- **One-click search** — the current page's domain is shown with a "Search Breaches" button that opens `https://haveibeenpwned.com/DomainSearch?domain=<domain>` in a new tab.
- **Manual domain input** — a text field for searching arbitrary domains.
- Have I Been Pwned is the gold standard for data-breach lookups. The domain search shows which breaches have affected email accounts under a given domain. Domain ownership verification may be required for full results, but the landing page provides a useful starting point for assessing breach exposure.

**DeHashed — Breach & Credential Search**

- **One-click search** — the current page's domain is shown with a "Search DeHashed" button that opens `https://dehashed.com/search?query=domain:<domain>` in a new tab.
- **Manual domain input** — a text field for searching arbitrary domains.
- DeHashed aggregates billions of leaked records from data breaches, allowing you to search for breached credentials, emails, names, and other data associated with a domain. A free search preview is available; full results require an account. Useful for identifying credential exposure, assessing breach impact, and informing password-reset campaigns.

In addition to the dedicated tab, search icons appear inline across other panels:

- **Blocks panel** — a magnifying glass (crt.sh), globe (Shodan), document (WHOIS), hourglass (Wayback Machine), and detective (Intelligence X) icon next to each observed hostname in the hostname capture list (when red-team mode is enabled).
- **Exfil panel** — a magnifying glass (crt.sh) and globe (Shodan) icon next to each third-party host in the exfiltration event stream, alongside the existing "allow" button.

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
- **Red-team tools** — a toggle to enable the Auth, Exfil, Inject, Recon, APIs, Deps, Timeline, and OSINT tabs in the overlay. Off by default.
- **Exfiltration allowlist** — manage trusted hostnames that won't trigger third-party exfil alerts. The page's own origin is always allowed.
- **Blocked cookies** — a persistent list of cookies that are automatically deleted whenever the browser tries to set them. Cookies blocked from the Auth tab in the overlay are added here automatically. Entries can also be added manually by specifying a cookie name and domain, or removed individually or cleared entirely. The service worker enforces the blocklist in real time via `chrome.cookies.onChanged`.
- **Export findings** — downloads all stored data (settings, stats, findings) as a timestamped JSON file (`boxedin-findings-YYYY-MM-DD.json`).

---

## File Reference

- `**manifest.json`** — Manifest V3 declaration: permissions, background service worker, content scripts, and DNR rulesets.
- `**background.js**` — Service worker handling DNR rule management, `webRequest` listeners, per-tab in-memory data maps, header-based analysis, and request replay.
- `**page-guard.js**` — MAIN-world content script injected at `document_start` in all frames. Patches browser APIs to block telemetry and collector URLs, and runs red-team DOM scans when enabled.
- `**stats-overlay.js**` — Isolated-world content script injected at `document_idle` in the top frame. Renders the floating overlay with tabbed panels (Blocks, Auth, Exfil, Inject, Recon, APIs, Deps, Timeline, OSINT), the Request Repeater, and the export button.
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
- `**cookies**` — used by the Auth tab to audit cookies for the current URL via `chrome.cookies.getAll()`, to delete cookies via `chrome.cookies.remove()`, and to enforce the persistent cookie blocklist in real time via `chrome.cookies.onChanged`.
- `**<all_urls>**` (host permission) — allows content scripts and `webRequest` listeners to operate on all sites.

