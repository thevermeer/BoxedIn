/**
 * Overlay (isolated world): tabbed DNR + page-guard block stats and red-team
 * panels (Auth, Exfil, Inject). Listens for page-guard postMessage (same tab,
 * inc. iframes). Injected on all sites.
 */
(function () {
  "use strict";

  var POLL_MS = 4000;
  var STORAGE_VIEW_STATE = "overlayViewState";
  var STORAGE_ACTIVE_TAB = "overlayActiveTab";
  var STORAGE_REDTEAM_ENABLED = "redteamEnabled";
  var STORAGE_EXFIL_ALLOWLIST = "redteamExfilAllowlist";
  var root;
  var viewState = "normal";
  var activeTab = "blocks";
  var redteamEnabled = false;
  var exfilAllowlist = [];
  var pendingPg = { linkedInBlocklist: 0, extensionScheme: 0 };
  var pgFlushTimer = null;

  var cachedBlocksPayload = null;
  var cachedExfilEvents = [];
  var cachedPageGuardAuth = [];
  var cachedSubdomains = [];
  var cachedBaseDomain = "";
  var cachedSourceMaps = [];
  var cachedProbeResults = null;
  var cachedDnsFindings = null;
  var cachedDnsDomain = "";
  var cachedCorsProbe = null;
  var exfilFilter = null;

  var repeaterRoot = null;

  /* ── Page-guard stat flush ─────────────────────────────────────────── */

  /** Batch-send accumulated page-guard block deltas to the background. */
  function flushPendingPageGuard() {
    pgFlushTimer = null;
    var li = pendingPg.linkedInBlocklist;
    var es = pendingPg.extensionScheme;
    pendingPg.linkedInBlocklist = 0;
    pendingPg.extensionScheme = 0;
    if (li <= 0 && es <= 0) return;
    var payload = { type: "BOXEDIN_PAGE_GUARD_STAT" };
    if (li > 0) payload.linkedInBlocklist = li;
    if (es > 0) payload.extensionScheme = es;
    try {
      chrome.runtime.sendMessage(payload, function () {
        if (chrome.runtime.lastError) { /* ignore */ }
      });
    } catch (e) { /* ignore */ }
  }

  /* ── Page-guard message handler (stats + red-team events) ──────────── */

  /**
   * Handle postMessage from page-guard (MAIN world): accumulate block-stat
   * deltas, forward exfil/auth/inject findings to the background and caches.
   */
  function onPageGuardMessage(ev) {
    try {
      if (ev.origin !== window.location.origin) return;
    } catch (e) {
      return;
    }
    var data = ev.data;
    if (!data || data.source !== "boxedin-page-guard") return;

    if (data.type === "stat") {
      if (data.key === "linkedInBlocklist") {
        var d1 = typeof data.delta === "number" && data.delta > 0 ? data.delta : 1;
        pendingPg.linkedInBlocklist += d1;
      } else if (data.key === "extensionScheme") {
        var d2 = typeof data.delta === "number" && data.delta > 0 ? data.delta : 1;
        pendingPg.extensionScheme += d2;
      } else {
        return;
      }
      if (pgFlushTimer !== null) clearTimeout(pgFlushTimer);
      pgFlushTimer = setTimeout(flushPendingPageGuard, 200);
      return;
    }

    if (!redteamEnabled) return;

    if (data.type === "exfil") {
      try {
        chrome.runtime.sendMessage({
          type: "BOXEDIN_STORE_EXFIL_EVENT", event: data
        }, function () { if (chrome.runtime.lastError) {} });
      } catch (e) { /* ignore */ }
      cachedExfilEvents.push(data);
      if (cachedExfilEvents.length > 200) cachedExfilEvents = cachedExfilEvents.slice(-200);
      if (activeTab === "exfil") renderActivePanel();
      return;
    }

    if (data.type === "auth") {
      cachedPageGuardAuth.push(data);
      if (activeTab === "auth") renderActivePanel();
      return;
    }

    if (data.type === "inject") {
      try {
        chrome.runtime.sendMessage({
          type: "BOXEDIN_STORE_INJECT_FINDING", finding: data
        }, function () { if (chrome.runtime.lastError) {} });
      } catch (e) { /* ignore */ }
      if (activeTab === "inject") renderActivePanel();
      return;
    }

    if (data.type === "api") {
      try {
        chrome.runtime.sendMessage({
          type: "BOXEDIN_STORE_API_FINDING", finding: data
        }, function () { if (chrome.runtime.lastError) {} });
      } catch (e) { /* ignore */ }
      if (activeTab === "apis") renderActivePanel();
      return;
    }

    if (data.type === "tech") {
      try {
        chrome.runtime.sendMessage({
          type: "BOXEDIN_STORE_TECH_FINDING", finding: data
        }, function () { if (chrome.runtime.lastError) {} });
      } catch (e) { /* ignore */ }
      if (activeTab === "recon") renderActivePanel();
      return;
    }
    if (data.type === "tech-version") {
      try {
        chrome.runtime.sendMessage({
          type: "BOXEDIN_UPDATE_TECH_VERSION", name: data.name, version: data.version
        }, function () { if (chrome.runtime.lastError) {} });
      } catch (e) { /* ignore */ }
      if (activeTab === "recon") renderActivePanel();
      return;
    }
    if (data.type === "recon") {
      if (data.subtype === "subdomains") {
        cachedSubdomains = data.subdomains || [];
        cachedBaseDomain = data.baseDomain || "";
      } else if (data.subtype === "sourcemaps") {
        cachedSourceMaps = data.findings || [];
      }
      if (activeTab === "recon") renderActivePanel();
      return;
    }
    if (data.type === "deps") {
      try {
        chrome.runtime.sendMessage({
          type: "BOXEDIN_STORE_DEPS_FINDING", findings: data.findings || []
        }, function () { if (chrome.runtime.lastError) {} });
      } catch (e) { /* ignore */ }
      if (activeTab === "deps") renderActivePanel();
      return;
    }
  }

  window.addEventListener("message", onPageGuardMessage);

  /* ── Utility ───────────────────────────────────────────────────────── */

  /** Detect dark mode via DOM class, data attribute, or media query. */
  function isDarkUi() {
    try {
      if (document.documentElement) {
        if (document.documentElement.classList.contains("theme--dark")) return true;
        if (document.documentElement.getAttribute("data-theme") === "dark") return true;
      }
      if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) return true;
    } catch (e) { /* ignore */ }
    return false;
  }

  /** Escape HTML entities in a string for safe innerHTML insertion. */
  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  /** Escape for use inside HTML attribute values (extends escapeHtml with single-quote). */
  function escapeAttr(s) {
    return escapeHtml(s).replace(/'/g, "&#39;");
  }

  /** Format a unix-ms timestamp as a locale time string (HH:MM:SS). */
  function formatTime(ts) {
    if (!ts) return "";
    try {
      var d = new Date(ts);
      return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    } catch (e) { return ""; }
  }

  /** Persist the overlay view state (normal | collapsed | maximized) to storage. */
  function saveViewState(state) {
    viewState = state;
    try {
      var patch = {};
      patch[STORAGE_VIEW_STATE] = state;
      chrome.storage.local.set(patch);
    } catch (e) { /* ignore */ }
  }

  /** Apply the current viewState as CSS classes on the root element. */
  function applyViewState() {
    root.classList.remove("boxedin-stats--collapsed", "boxedin-stats--maximized");
    if (viewState === "collapsed") root.classList.add("boxedin-stats--collapsed");
    else if (viewState === "maximized") root.classList.add("boxedin-stats--maximized");
  }

  /** Copy text to clipboard, falling back to execCommand if Clipboard API unavailable. */
  function copyTextToClipboard(text, onDone) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(onDone).catch(function () {
        fallbackCopyText(text, onDone);
      });
      return;
    }
    fallbackCopyText(text, onDone);
  }

  /** execCommand("copy") fallback for browsers without Clipboard API. */
  function fallbackCopyText(text, onDone) {
    try {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      if (onDone) onDone();
    } catch (e) { /* ignore */ }
  }

  /* ── Enable page-guard red-team ────────────────────────────────────── */

  /** Signal the MAIN-world page-guard script to activate red-team hooks. */
  function enablePageGuardRedteam() {
    try {
      window.postMessage({ source: "boxedin-overlay", type: "enable-redteam" }, "*");
    } catch (e) { /* ignore */ }
  }

  /* ── Tab management ────────────────────────────────────────────────── */

  /** Switch the active overlay tab, persist choice, and re-render. */
  function switchTab(tab) {
    activeTab = tab;
    try {
      var patch = {};
      patch[STORAGE_ACTIVE_TAB] = tab;
      chrome.storage.local.set(patch);
    } catch (e) { /* ignore */ }
    renderActivePanel();
  }

  /** Open a crt.sh certificate transparency search for a domain in a new tab. */
  function openCrtShSearch(domain) {
    if (!domain) return;
    var url = "https://crt.sh/?q=" + encodeURIComponent(domain);
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_OPEN_TAB", url: url }, function () {
        if (chrome.runtime.lastError) { /* ignore */ }
      });
    } catch (e) { /* ignore */ }
  }

  /** Open a Shodan search for a domain/IP in a new tab. */
  function openShodanSearch(query) {
    if (!query) return;
    var url = "https://www.shodan.io/search?query=" + encodeURIComponent(query);
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_OPEN_TAB", url: url }, function () {
        if (chrome.runtime.lastError) { /* ignore */ }
      });
    } catch (e) { /* ignore */ }
  }

  /** Open a Wayback Machine search for a domain in a new tab. */
  function openWaybackSearch(domain) {
    if (!domain) return;
    var url = "https://web.archive.org/web/*/" + encodeURIComponent(domain);
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_OPEN_TAB", url: url }, function () {
        if (chrome.runtime.lastError) { /* ignore */ }
      });
    } catch (e) { /* ignore */ }
  }

  /** Open an Intelligence X search for a domain in a new tab. */
  function openIntelXSearch(query) {
    if (!query) return;
    var url = "https://intelx.io/?s=" + encodeURIComponent(query);
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_OPEN_TAB", url: url }, function () {
        if (chrome.runtime.lastError) { /* ignore */ }
      });
    } catch (e) { /* ignore */ }
  }

  /** Open a WHOIS lookup for a domain in a new tab. */
  function openWhoisSearch(domain) {
    if (!domain) return;
    var url = "https://who.is/whois/" + encodeURIComponent(domain);
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_OPEN_TAB", url: url }, function () {
        if (chrome.runtime.lastError) { /* ignore */ }
      });
    } catch (e) { /* ignore */ }
  }

  /** Open a urlscan.io search for a domain in a new tab. */
  function openUrlscanSearch(domain) {
    if (!domain) return;
    var url = "https://urlscan.io/search/#domain:" + encodeURIComponent(domain);
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_OPEN_TAB", url: url }, function () {
        if (chrome.runtime.lastError) { /* ignore */ }
      });
    } catch (e) { /* ignore */ }
  }

  /** Open a Censys search for a domain in a new tab. */
  function openCensysSearch(domain) {
    if (!domain) return;
    var url = "https://search.censys.io/search?resource=hosts&q=" + encodeURIComponent(domain);
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_OPEN_TAB", url: url }, function () {
        if (chrome.runtime.lastError) { /* ignore */ }
      });
    } catch (e) { /* ignore */ }
  }

  /** Open a Domain Dossier lookup for a domain in a new tab. */
  function openDomainDossierSearch(domain) {
    if (!domain) return;
    var url = "https://centralops.net/co/DomainDossier.aspx?addr=" + encodeURIComponent(domain) + "&dom_whois=true&dom_dns=true&net_whois=true";
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_OPEN_TAB", url: url }, function () {
        if (chrome.runtime.lastError) { /* ignore */ }
      });
    } catch (e) { /* ignore */ }
  }

  /** Open a PhishTank search for a domain in a new tab. */
  function openPhishTankSearch(domain) {
    if (!domain) return;
    var url = "https://phishtank.org/phish_search.php?search=" + encodeURIComponent(domain) + "&action=search";
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_OPEN_TAB", url: url }, function () {
        if (chrome.runtime.lastError) { /* ignore */ }
      });
    } catch (e) { /* ignore */ }
  }

  /** Open a FOFA search for a domain in a new tab. */
  function openFofaSearch(domain) {
    if (!domain) return;
    var query = 'domain="' + domain + '"';
    var url = "https://en.fofa.info/result?qbase64=" + btoa(query);
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_OPEN_TAB", url: url }, function () {
        if (chrome.runtime.lastError) { /* ignore */ }
      });
    } catch (e) { /* ignore */ }
  }

  /** Open a Companies House search for a domain/company in a new tab. */
  function openCompaniesHouseSearch(query) {
    if (!query) return;
    var url = "https://find-and-update.company-information.service.gov.uk/search?q=" + encodeURIComponent(query);
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_OPEN_TAB", url: url }, function () {
        if (chrome.runtime.lastError) { /* ignore */ }
      });
    } catch (e) { /* ignore */ }
  }

  /** Open a SecurityTrails DNS history lookup for a domain in a new tab. */
  function openSecurityTrailsSearch(domain) {
    if (!domain) return;
    var url = "https://securitytrails.com/domain/" + encodeURIComponent(domain) + "/dns";
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_OPEN_TAB", url: url }, function () {
        if (chrome.runtime.lastError) { /* ignore */ }
      });
    } catch (e) { /* ignore */ }
  }

  /** Dispatch a fetch-and-render cycle for whichever tab is active. */
  function renderActivePanel() {
    if (activeTab === "blocks") fetchStats();
    else if (activeTab === "auth") fetchAuthAndRender();
    else if (activeTab === "exfil") fetchExfilAndRender();
    else if (activeTab === "inject") fetchInjectAndRender();
    else if (activeTab === "recon") fetchReconAndRender();
    else if (activeTab === "apis") fetchApisAndRender();
    else if (activeTab === "deps") fetchDepsAndRender();
    else if (activeTab === "timeline") fetchTimelineAndRender();
    else if (activeTab === "osint") renderOsintPanel();
  }

  /* ── Wire helpers ──────────────────────────────────────────────────── */

  /** Bind the collapse/expand toggle button in the overlay header. */
  function wireToggle() {
    var btn = root.querySelector(".boxedin-stats__toggle");
    if (!btn) return;
    btn.addEventListener("click", function () {
      saveViewState(viewState === "collapsed" ? "normal" : "collapsed");
      applyViewState();
      var collapsed = viewState === "collapsed";
      btn.textContent = collapsed ? "\u25B2" : "\u25BC";
      btn.setAttribute("title", collapsed ? "Expand" : "Collapse");
      btn.setAttribute("aria-expanded", collapsed ? "false" : "true");
    });
  }

  /** Bind the maximize/restore button in the overlay header. */
  function wireMaximize() {
    var btn = root.querySelector(".boxedin-stats__maximize");
    if (!btn) return;
    btn.addEventListener("click", function () {
      saveViewState(viewState === "maximized" ? "normal" : "maximized");
      applyViewState();
      var maximized = viewState === "maximized";
      btn.textContent = maximized ? "\u25A3" : "\u25A1";
      btn.setAttribute("title", maximized ? "Restore" : "Maximize");
    });
  }

  /** Bind click handlers on all tab buttons in the tab strip. */
  function wireTabs() {
    var tabs = root.querySelectorAll(".boxedin-stats__tab");
    for (var i = 0; i < tabs.length; i++) {
      (function (btn) {
        btn.addEventListener("click", function () {
          var tab = btn.getAttribute("data-tab");
          if (tab && tab !== activeTab) switchTab(tab);
        });
      })(tabs[i]);
    }
  }

  /** Bind the repeater pop-out button in the overlay header. */
  function wireOpenRepeater() {
    var btn = root.querySelector(".boxedin-stats__open-repeater");
    if (!btn) return;
    btn.addEventListener("click", function () {
      openRepeater({});
    });
  }

  function wireExportFindings() {
    var btn = root.querySelector(".boxedin-stats__export-findings");
    if (!btn) return;
    btn.addEventListener("click", function () {
      btn.disabled = true;
      btn.textContent = "\u2026";
      try {
        chrome.runtime.sendMessage({ type: "BOXEDIN_EXPORT_ALL_FINDINGS" }, function (response) {
          if (chrome.runtime.lastError || !response || !response.report) {
            btn.textContent = "\u2717";
            setTimeout(function () { btn.textContent = "\u2B07"; btn.disabled = false; }, 2000);
            return;
          }
          var report = response.report;
          report.pageGuardAuth = cachedPageGuardAuth;
          report.subdomains = cachedSubdomains;
          report.sourceMaps = cachedSourceMaps;
          var blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
          var url = URL.createObjectURL(blob);
          var a = document.createElement("a");
          a.href = url;
          a.download = "boxedin-report-" + new Date().toISOString().slice(0, 10) + ".json";
          a.click();
          URL.revokeObjectURL(url);
          btn.textContent = "\u2713";
          setTimeout(function () { btn.textContent = "\u2B07"; btn.disabled = false; }, 2000);
        });
      } catch (e) {
        btn.textContent = "\u2717";
        setTimeout(function () { btn.textContent = "\u2B07"; btn.disabled = false; }, 2000);
      }
    });
  }

  /* ── Render shell (header + tabs + body) ───────────────────────────── */

  /**
   * Re-render the full overlay shell (header, tab strip, body).
   * Preserves scroll position of .boxedin-stats__body across re-paints.
   * @param {string} bodyHtml  Inner HTML for the body panel.
   * @param {Object} [opts]    Options; set extensionDisabled to hide the overlay.
   */
  function renderShell(bodyHtml, opts) {
    if (!root) return;
    opts = opts || {};
    if (opts.extensionDisabled) {
      root.style.display = "none";
      return;
    }
    root.style.display = "";

    var prevBodyScroll = 0;
    var bodyEl = root.querySelector(".boxedin-stats__body");
    if (bodyEl) prevBodyScroll = bodyEl.scrollTop;

    root.className = "";
    if (isDarkUi()) root.classList.add("boxedin-stats--dark");
    applyViewState();

    var collapsed = root.classList.contains("boxedin-stats--collapsed");
    var maximized = viewState === "maximized";

    var headerActions = "";
    if (activeTab === "blocks") {
      headerActions += '<button type="button" class="boxedin-stats__reset-stats" title="Clear cumulative DNR and page-guard block counts (this browser)">Reset stats</button>';
    }
    if (redteamEnabled) {
      headerActions += '<button type="button" class="boxedin-stats__export-findings" title="Export all findings as JSON">\u2B07</button>';
      headerActions += '<button type="button" class="boxedin-stats__open-repeater" title="Open request repeater">\u21C5</button>';
    }
    headerActions +=
      '<button type="button" class="boxedin-stats__maximize" title="' +
      (maximized ? "Restore" : "Maximize") + '">' +
      (maximized ? "\u25A3" : "\u25A1") + "</button>" +
      '<button type="button" class="boxedin-stats__toggle" title="' +
      (collapsed ? "Expand" : "Collapse") + '" aria-expanded="' +
      (collapsed ? "false" : "true") + '">' +
      (collapsed ? "\u25B2" : "\u25BC") + "</button>";

    var tabsHtml = "";
    if (redteamEnabled) {
      var tabDefs = [
        { id: "blocks", label: "Blocks" },
        { id: "auth", label: "Auth" },
        { id: "exfil", label: "Exfil" },
        { id: "inject", label: "Inject" },
        { id: "recon", label: "Recon" },
        { id: "apis", label: "APIs" },
        { id: "deps", label: "Deps" },
        { id: "timeline", label: "Timeline" },
        { id: "osint", label: "OSINT" }
      ];
      tabsHtml = '<div class="boxedin-stats__tabs">';
      for (var t = 0; t < tabDefs.length; t++) {
        var cls = tabDefs[t].id === activeTab ? " boxedin-stats__tab--active" : "";
        tabsHtml += '<button type="button" class="boxedin-stats__tab' + cls +
          '" data-tab="' + tabDefs[t].id + '">' + tabDefs[t].label + '</button>';
      }
      tabsHtml += '</div>';
    }

    root.innerHTML =
      '<div class="boxedin-stats__header">' +
        '<span class="boxedin-stats__title">BoxedIn</span>' +
        '<div class="boxedin-stats__header-actions">' + headerActions + '</div>' +
      '</div>' +
      tabsHtml +
      '<div class="boxedin-stats__body">' + bodyHtml + '</div>';

    wireToggle();
    wireMaximize();
    wireOpenRepeater();
    wireExportFindings();
    if (redteamEnabled) wireTabs();

    var newBody = root.querySelector(".boxedin-stats__body");
    if (newBody && prevBodyScroll) newBody.scrollTop = prevBodyScroll;
  }

  /* ── Blocks panel ──────────────────────────────────────────────────── */

  /** Toggle a per-host DNR block rule via the background. */
  function toggleHostBlock(host, block) {
    try {
      chrome.runtime.sendMessage(
        { type: "BOXEDIN_TOGGLE_HOST_BLOCK", host: host, block: block },
        function () {
          if (chrome.runtime.lastError) return;
          fetchStats();
        }
      );
    } catch (e) { /* ignore */ }
  }

  /** Ask the background to start recording unique hostnames for this tab. */
  function enableCaptureHosts() {
    try {
      chrome.runtime.sendMessage(
        { type: "BOXEDIN_SET_CAPTURE_HOSTS", enabled: true },
        function () {
          if (chrome.runtime.lastError) return;
          fetchStats();
        }
      );
    } catch (e) { /* ignore */ }
  }

  /** Split block rows into { network, sniff } for sectioned display. */
  function partitionBlockRows(rows) {
    var network = [];
    var sniff = [];
    for (var i = 0; i < rows.length; i++) {
      if (rows[i] && rows[i].kind === "extensionSniff") sniff.push(rows[i]);
      else network.push(rows[i]);
    }
    return { network: network, sniff: sniff };
  }

  /** Sum the .count field across an array of block rows. */
  function sumRowCounts(arr) {
    var s = 0;
    for (var j = 0; j < arr.length; j++) {
      var c = arr[j] && arr[j].count;
      if (typeof c === "number" && c > 0) s += c;
    }
    return s;
  }

  /**
   * Build the Blocks panel HTML: DNR + page-guard rows split by category,
   * optional hostname list with per-host block checkboxes.
   */
  function buildBlocksBody(payload) {
    if (payload && payload.unavailable) {
      return '<p class="boxedin-stats__hint">' +
        escapeHtml(payload.reason || "Block stats need declarativeNetRequestFeedback in a recent Chrome.") +
        '</p>';
    }

    var rows = (payload && payload.rows) || [];
    var total = (payload && payload.total) || 0;
    var parts = [];

    if (rows.length === 0) {
      parts.push('<p class="boxedin-stats__empty">No requests blocked yet on this profile.</p>');
    } else {
      parts.push('<div class="boxedin-stats__total">Total blocked: <strong>' + total + '</strong></div>');
      var split = partitionBlockRows(rows);

      parts.push(
        '<div class="boxedin-stats__section"><div class="boxedin-stats__section-head">' +
        '<span class="boxedin-stats__section-title">Network &amp; API traffic</span>' +
        '<span class="boxedin-stats__section-sub">' + sumRowCounts(split.network) + '</span></div>');
      if (split.network.length > 0) {
        for (var i = 0; i < split.network.length; i++) {
          var r = split.network[i];
          parts.push(
            '<div class="boxedin-stats__row"><span class="boxedin-stats__label" title="' +
            escapeAttr(r.detail || "") + '">' + escapeHtml(r.label) +
            '</span><span class="boxedin-stats__count">' + r.count + '</span></div>');
        }
      } else {
        parts.push('<p class="boxedin-stats__section-empty">None in this category yet.</p>');
      }
      parts.push('</div>');

      parts.push(
        '<div class="boxedin-stats__section"><div class="boxedin-stats__section-head">' +
        '<span class="boxedin-stats__section-title">Extension sniffing</span>' +
        '<span class="boxedin-stats__section-sub">' + sumRowCounts(split.sniff) + '</span></div>');
      if (split.sniff.length > 0) {
        for (var s = 0; s < split.sniff.length; s++) {
          var sr = split.sniff[s];
          parts.push(
            '<div class="boxedin-stats__row"><span class="boxedin-stats__label" title="' +
            escapeAttr(sr.detail || "") + '">' + escapeHtml(sr.label) +
            '</span><span class="boxedin-stats__count">' + sr.count + '</span></div>');
        }
      } else {
        parts.push(
          '<p class="boxedin-stats__section-empty">' +
          'None yet \u2014 counts DNR rule 2 (chrome-extension://\u2026) and page-guard JS blocks of extension URLs.' +
          '</p>');
      }
      parts.push('</div>');
    }

    var hosts = (payload && payload.observedHosts) || [];
    var blockedHosts = (payload && payload.blockedHosts) || [];
    var blockedSet = {};
    for (var bh = 0; bh < blockedHosts.length; bh++) blockedSet[blockedHosts[bh]] = true;
    var capOn = payload && payload.captureHostsEnabled;

    if (capOn) {
      parts.push(
        '<div class="boxedin-stats__hosts"><div class="boxedin-stats__hosts-head">' +
        '<span class="boxedin-stats__hosts-title">Hostnames (this tab)</span>' +
        '<div class="boxedin-stats__hosts-actions">');
      if (hosts.length > 0) {
        parts.push(
          '<button type="button" class="boxedin-stats__hosts-copy boxedin-stats__hosts-btn" ' +
          'title="Copy all hostnames (one per line)" data-label-copy="Copy all" data-label-copied="Copied">Copy all</button>');
      }
      parts.push(
        '<button type="button" class="boxedin-stats__hosts-reset boxedin-stats__hosts-btn" ' +
        'title="Clear the hostname list for this tab">Reset list</button></div></div>');
      if (hosts.length > 0) {
        parts.push('<p class="boxedin-stats__hosts-hint">Check a hostname to block all sub-resource requests to it.</p>');
        parts.push('<ul class="boxedin-stats__hosts-list">');
        for (var h = 0; h < hosts.length; h++) {
          var isBlocked = !!blockedSet[hosts[h]];
          parts.push(
            '<li class="boxedin-stats__host-item' +
            (isBlocked ? " boxedin-stats__host-item--blocked" : "") + '">' +
            '<label class="boxedin-stats__host-label">' +
            '<input type="checkbox" class="boxedin-stats__host-check" data-host="' +
            escapeAttr(hosts[h]) + '"' + (isBlocked ? " checked" : "") + ' />' +
            '<code>' + escapeHtml(hosts[h]) + '</code></label>' +
            (redteamEnabled ? '<button type="button" class="boxedin-rt__osint-btn" data-domain="' +
            escapeAttr(hosts[h]) + '" title="Search crt.sh">\uD83D\uDD0D</button>' +
            '<button type="button" class="boxedin-rt__shodan-btn" data-query="' +
            escapeAttr(hosts[h]) + '" title="Search Shodan">\uD83C\uDF10</button>' +
            '<button type="button" class="boxedin-rt__whois-btn" data-domain="' +
            escapeAttr(hosts[h]) + '" title="WHOIS lookup">\uD83D\uDCC4</button>' +
            '<button type="button" class="boxedin-rt__wayback-btn" data-domain="' +
            escapeAttr(hosts[h]) + '" title="Wayback Machine">\u231B</button>' +
            '<button type="button" class="boxedin-rt__intelx-btn" data-query="' +
            escapeAttr(hosts[h]) + '" title="Intelligence X">\uD83D\uDD75</button>' : '') +
            '</li>');
        }
        parts.push('</ul>');
      } else {
        parts.push('<p class="boxedin-stats__hosts-empty">Host capture on \u2014 no hostnames recorded yet in this tab.</p>');
      }
      parts.push('</div>');
    } else {
      parts.push(
        '<div class="boxedin-stats__hosts-off">' +
        '<p class="boxedin-stats__hosts-empty">Hostname capture is off.</p>' +
        '<button type="button" class="boxedin-stats__enable-capture boxedin-stats__hosts-btn">Enable host capture</button>' +
        '</div>');
    }

    return parts.join("");
  }

  /** Attach event listeners for the Blocks panel (reset, host checkboxes, copy, enable). */
  function wireBlocksPanel(payload) {
    var hosts = (payload && payload.observedHosts) || [];
    var capOn = payload && payload.captureHostsEnabled;

    var resetBtn = root.querySelector(".boxedin-stats__reset-stats");
    if (resetBtn) {
      resetBtn.addEventListener("click", function () {
        if (pgFlushTimer !== null) {
          clearTimeout(pgFlushTimer);
          pgFlushTimer = null;
        }
        pendingPg.linkedInBlocklist = 0;
        pendingPg.extensionScheme = 0;
        try {
          chrome.runtime.sendMessage({ type: "BOXEDIN_RESET_BLOCK_STATS" }, function () {
            if (chrome.runtime.lastError) return;
            fetchStats();
          });
        } catch (e) { /* ignore */ }
      });
    }

    if (capOn) {
      var hostsResetBtn = root.querySelector(".boxedin-stats__hosts-reset");
      if (hostsResetBtn) {
        hostsResetBtn.addEventListener("click", function () {
          try {
            chrome.runtime.sendMessage({ type: "BOXEDIN_RESET_OBSERVED_HOSTS" }, function () {
              if (chrome.runtime.lastError) return;
              fetchStats();
            });
          } catch (e) { /* ignore */ }
        });
      }

      var checks = root.querySelectorAll(".boxedin-stats__host-check");
      for (var c = 0; c < checks.length; c++) {
        (function (cb) {
          cb.addEventListener("change", function () {
            toggleHostBlock(cb.getAttribute("data-host"), cb.checked);
          });
        })(checks[c]);
      }

      if (hosts.length > 0) {
        var copyBtn = root.querySelector(".boxedin-stats__hosts-copy");
        if (copyBtn) {
          copyBtn.addEventListener("click", function () {
            var text = hosts.join("\n");
            var label = copyBtn.getAttribute("data-label-copy") || "Copy all";
            var labelDone = copyBtn.getAttribute("data-label-copied") || "Copied";
            copyTextToClipboard(text, function () {
              copyBtn.textContent = labelDone;
              setTimeout(function () { copyBtn.textContent = label; }, 1600);
            });
          });
        }

        var osintBtns = root.querySelectorAll(".boxedin-stats__hosts-list .boxedin-rt__osint-btn");
        for (var ob = 0; ob < osintBtns.length; ob++) {
          (function (btn) {
            btn.addEventListener("click", function (ev) {
              ev.preventDefault();
              ev.stopPropagation();
              openCrtShSearch(btn.getAttribute("data-domain"));
            });
          })(osintBtns[ob]);
        }

        var shodanBtns = root.querySelectorAll(".boxedin-stats__hosts-list .boxedin-rt__shodan-btn");
        for (var sb = 0; sb < shodanBtns.length; sb++) {
          (function (btn) {
            btn.addEventListener("click", function (ev) {
              ev.preventDefault();
              ev.stopPropagation();
              openShodanSearch(btn.getAttribute("data-query"));
            });
          })(shodanBtns[sb]);
        }

        var whoisBtns = root.querySelectorAll(".boxedin-stats__hosts-list .boxedin-rt__whois-btn");
        for (var wb = 0; wb < whoisBtns.length; wb++) {
          (function (btn) {
            btn.addEventListener("click", function (ev) {
              ev.preventDefault();
              ev.stopPropagation();
              openWhoisSearch(btn.getAttribute("data-domain"));
            });
          })(whoisBtns[wb]);
        }

        var waybackBtns = root.querySelectorAll(".boxedin-stats__hosts-list .boxedin-rt__wayback-btn");
        for (var wbb = 0; wbb < waybackBtns.length; wbb++) {
          (function (btn) {
            btn.addEventListener("click", function (ev) {
              ev.preventDefault();
              ev.stopPropagation();
              openWaybackSearch(btn.getAttribute("data-domain"));
            });
          })(waybackBtns[wbb]);
        }

        var intelxBtns = root.querySelectorAll(".boxedin-stats__hosts-list .boxedin-rt__intelx-btn");
        for (var ixb = 0; ixb < intelxBtns.length; ixb++) {
          (function (btn) {
            btn.addEventListener("click", function (ev) {
              ev.preventDefault();
              ev.stopPropagation();
              openIntelXSearch(btn.getAttribute("data-query"));
            });
          })(intelxBtns[ixb]);
        }
      }
    } else {
      var enableBtn = root.querySelector(".boxedin-stats__enable-capture");
      if (enableBtn) {
        enableBtn.addEventListener("click", function () { enableCaptureHosts(); });
      }
    }
  }

  /* ── Auth panel ────────────────────────────────────────────────────── */

  /**
   * Build the Auth panel HTML from background audit data + page-guard
   * findings, grouped into Critical / Warning / Info severity sections.
   */
  function buildAuthBody(data) {
    if (!redteamEnabled) {
      return '<p class="boxedin-rt__disabled">Enable red-team tools in the BoxedIn options page.</p>';
    }
    if (!data) return '<p class="boxedin-rt__none">Loading auth audit data\u2026</p>';

    var critical = [];
    var warning = [];
    var info = [];

    function cookieBlockBtn(name, domain, removeUrl) {
      if (!removeUrl) return "";
      return ' <button type="button" class="boxedin-rt__cookie-block-btn" data-cookie-name="' +
        escapeAttr(name) + '" data-cookie-domain="' + escapeAttr(domain || "") +
        '" data-remove-url="' + escapeAttr(removeUrl) +
        '" title="Block this cookie (persistent)">block</button>';
    }

    var reqHeaders = data.reqHeaders || [];
    for (var ri = 0; ri < reqHeaders.length; ri++) {
      var rh = reqHeaders[ri];
      if (rh.authOverHttp) {
        critical.push("Authorization sent over HTTP: " + escapeHtml((rh.url || "").slice(0, 80)));
      }
      if (rh.tokenType) {
        info.push("Token type: <strong>" + escapeHtml(rh.tokenType) + "</strong> on " +
          escapeHtml((rh.url || "").slice(0, 60)));
      }
    }

    var cookies = data.cookies || [];
    for (var ci = 0; ci < cookies.length; ci++) {
      var ck = cookies[ci];
      var blockHtml = cookieBlockBtn(ck.name, ck.domain, ck.removeUrl);
      if (ck.issues && ck.issues.length > 0) {
        for (var ii = 0; ii < ck.issues.length; ii++) {
          var issue = ck.issues[ii];
          if (ck.isSessionLike && issue.indexOf("HttpOnly") !== -1) {
            critical.push("Cookie <strong>" + escapeHtml(ck.name) + "</strong>: " + escapeHtml(issue) + blockHtml);
          } else {
            warning.push("Cookie <strong>" + escapeHtml(ck.name) + "</strong>: " + escapeHtml(issue) + blockHtml);
          }
        }
      } else {
        info.push("Cookie: " + escapeHtml(ck.name) + " (" + escapeHtml(ck.domain) + ")" +
          (ck.httpOnly ? " HttpOnly" : "") + (ck.secure ? " Secure" : "") + blockHtml);
      }
    }

    var setCookieIssues = data.setCookieIssues || [];
    for (var sci = 0; sci < setCookieIssues.length; sci++) {
      var scItem = setCookieIssues[sci];
      warning.push("Set-Cookie <strong>" + escapeHtml(scItem.name) + "</strong>: " +
        escapeHtml(scItem.issues.join(", ")));
    }

    var secH = data.securityHeaders || {};
    if (!secH.hsts) warning.push("Missing <strong>Strict-Transport-Security</strong> header");
    if (!secH.xcto) warning.push("Missing <strong>X-Content-Type-Options</strong> header");
    if (!secH.xfo) warning.push("Missing <strong>X-Frame-Options</strong> header");
    if (!secH.hasCsp) warning.push("Missing <strong>Content-Security-Policy</strong> header");
    if (secH.cspReportOnly) warning.push("CSP is <strong>report-only</strong> (not enforced)");

    for (var pga = 0; pga < cachedPageGuardAuth.length; pga++) {
      var pgData = cachedPageGuardAuth[pga];
      if (pgData.subtype === "storage-sensitive" && pgData.findings) {
        for (var fi = 0; fi < pgData.findings.length; fi++) {
          var f = pgData.findings[fi];
          critical.push(escapeHtml(f.issue) + ": <code>" + escapeHtml(f.key) + "</code> = " +
            escapeHtml(f.preview || ""));
        }
      }
      if (pgData.subtype === "exposed-secret" && pgData.findings) {
        for (var esi = 0; esi < pgData.findings.length; esi++) {
          var es = pgData.findings[esi];
          critical.push("Exposed secret: <strong>" + escapeHtml(es.name) + "</strong> in " +
            escapeHtml(es.location || "page") + " \u2014 <code>" + escapeHtml(es.preview || "") + "</code>");
        }
      }
    }

    if (critical.length === 0 && warning.length === 0 && info.length === 0) {
      return '<p class="boxedin-rt__none">No auth findings yet. Navigate to a site and reload to scan.</p>';
    }

    var parts = [];

    if (critical.length > 0) {
      parts.push(
        '<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">' +
        '<span class="boxedin-rt__badge boxedin-rt__badge--critical">Critical</span> ' +
        critical.length + ' issue' + (critical.length !== 1 ? 's' : '') + '</div>');
      for (var cr = 0; cr < critical.length; cr++) {
        parts.push('<div class="boxedin-rt__item"><span class="boxedin-rt__item-label">' + critical[cr] + '</span></div>');
      }
      parts.push('</div>');
    }

    if (warning.length > 0) {
      parts.push(
        '<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">' +
        '<span class="boxedin-rt__badge boxedin-rt__badge--warning">Warning</span> ' +
        warning.length + ' issue' + (warning.length !== 1 ? 's' : '') + '</div>');
      for (var w = 0; w < warning.length; w++) {
        parts.push('<div class="boxedin-rt__item"><span class="boxedin-rt__item-label">' + warning[w] + '</span></div>');
      }
      parts.push('</div>');
    }

    if (info.length > 0) {
      parts.push(
        '<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">' +
        '<span class="boxedin-rt__badge boxedin-rt__badge--info">Info</span> ' +
        info.length + ' item' + (info.length !== 1 ? 's' : '') + '</div>');
      for (var inf = 0; inf < info.length; inf++) {
        parts.push('<div class="boxedin-rt__item"><span class="boxedin-rt__item-detail">' + info[inf] + '</span></div>');
      }
      parts.push('</div>');
    }

    return parts.join("");
  }

  /** Bind click handlers for cookie block buttons in the Auth panel. */
  function wireAuthPanel() {
    var blockBtns = root.querySelectorAll(".boxedin-rt__cookie-block-btn");
    for (var bi = 0; bi < blockBtns.length; bi++) {
      (function (btn) {
        btn.addEventListener("click", function (ev) {
          ev.preventDefault();
          ev.stopPropagation();
          var cookieName = btn.getAttribute("data-cookie-name");
          var cookieDomain = btn.getAttribute("data-cookie-domain");
          var removeUrl = btn.getAttribute("data-remove-url");
          if (!cookieName || !removeUrl) return;
          btn.disabled = true;
          btn.textContent = "\u2026";
          try {
            chrome.runtime.sendMessage({
              type: "BOXEDIN_REMOVE_COOKIE", name: cookieName, domain: cookieDomain, url: removeUrl
            }, function (resp) {
              if (chrome.runtime.lastError) { /* ignore */ }
              if (resp && resp.removed) {
                btn.textContent = "\u2713";
                btn.classList.add("boxedin-rt__cookie-block-btn--done");
                setTimeout(function () { fetchAuthAndRender(); }, 600);
              } else {
                btn.textContent = "fail";
                btn.disabled = false;
              }
            });
          } catch (e) {
            btn.textContent = "block";
            btn.disabled = false;
          }
        });
      })(blockBtns[bi]);
    }
  }

  /** Fetch auth audit data from the background and render the Auth panel. */
  function fetchAuthAndRender() {
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_GET_AUTH_AUDIT" }, function (response) {
        if (chrome.runtime.lastError) {
          if (activeTab === "auth") renderShell(buildAuthBody(null));
          return;
        }
        if (activeTab === "auth") {
          renderShell(buildAuthBody(response));
          wireAuthPanel();
        }
      });
    } catch (e) {
      if (activeTab === "auth") renderShell(buildAuthBody(null));
    }
  }

  /* ── Exfil panel ───────────────────────────────────────────────────── */

  /**
   * Build the Exfil panel HTML: filter buttons, clear button, and a
   * reverse-chronological event stream with third-party alert highlighting.
   */
  function buildExfilBody() {
    if (!redteamEnabled) {
      return '<p class="boxedin-rt__disabled">Enable red-team tools in the BoxedIn options page.</p>';
    }

    var events = cachedExfilEvents;
    var subtypes = ["fetch", "xhr", "clipboard-write", "clipboard-read", "websocket", "form-submit", "large-request"];
    var parts = [];

    parts.push('<div class="boxedin-rt__exfil-toolbar">');
    parts.push('<div class="boxedin-rt__filters">');
    parts.push('<button type="button" class="boxedin-rt__filter' +
      (exfilFilter === null ? ' boxedin-rt__filter--active' : '') +
      '" data-filter="all">All</button>');
    for (var fi = 0; fi < subtypes.length; fi++) {
      parts.push('<button type="button" class="boxedin-rt__filter' +
        (exfilFilter === subtypes[fi] ? ' boxedin-rt__filter--active' : '') +
        '" data-filter="' + subtypes[fi] + '">' + escapeHtml(subtypes[fi]) + '</button>');
    }
    parts.push('</div>');
    if (events.length > 0) {
      parts.push('<button type="button" class="boxedin-rt__exfil-clear" title="Clear all exfil events for this tab">Clear</button>');
    }
    parts.push('</div>');

    var filtered = [];
    for (var ei = 0; ei < events.length; ei++) {
      if (exfilFilter === null || events[ei].subtype === exfilFilter) {
        filtered.push(events[ei]);
      }
    }

    if (filtered.length === 0) {
      parts.push('<p class="boxedin-rt__none">No exfiltration events captured yet.</p>');
      return parts.join("");
    }

    parts.push('<ul class="boxedin-rt__stream">');
    for (var i = filtered.length - 1; i >= 0; i--) {
      var evt = filtered[i];
      var isThirdParty = false;
      var evtHost = "";
      if (evt.url) {
        try {
          evtHost = new URL(evt.url).hostname;
          var pageHost = window.location.hostname;
          if (evtHost && evtHost !== pageHost && exfilAllowlist.indexOf(evtHost) === -1) {
            isThirdParty = true;
          }
        } catch (e) { /* ignore */ }
      }
      var alertClass = isThirdParty ? " boxedin-rt__event--alert" : "";
      var display = evt.url || evt.preview || evt.action || "\u2014";
      if (evt.bodySize) display += " (" + Math.round(evt.bodySize / 1024) + " KB)";
      var evtMethod = evt.method || "GET";
      var evtUrl = evt.url || "";
      parts.push(
        '<li class="boxedin-rt__event' + alertClass + '" data-rpt-url="' + escapeAttr(evtUrl) +
        '" data-rpt-method="' + escapeAttr(evtMethod) + '">' +
        '<span class="boxedin-rt__event-type">' + escapeHtml(evt.subtype || "?") + '</span>' +
        '<span class="boxedin-rt__event-url">' + escapeHtml(display));
      if (isThirdParty && evtHost) {
        parts.push(' <button type="button" class="boxedin-rt__allow-btn" data-host="' +
          escapeAttr(evtHost) + '" title="Add to exfil allowlist">allow</button>');
        parts.push(' <button type="button" class="boxedin-rt__osint-btn" data-domain="' +
          escapeAttr(evtHost) + '" title="Search crt.sh">\uD83D\uDD0D</button>');
        parts.push(' <button type="button" class="boxedin-rt__shodan-btn" data-query="' +
          escapeAttr(evtHost) + '" title="Search Shodan">\uD83C\uDF10</button>');
      }
      parts.push('</span>' +
        '<span class="boxedin-rt__event-ts">' + escapeHtml(formatTime(evt.ts)) + '</span>' +
        '</li>');
    }
    parts.push('</ul>');

    return parts.join("");
  }

  /**
   * Wire Exfil panel interactivity: clear button, subtype filter buttons,
   * event-row click → open repeater with captured headers, allow-host buttons.
   */
  function wireExfilPanel() {
    var clearBtn = root.querySelector(".boxedin-rt__exfil-clear");
    if (clearBtn) {
      clearBtn.addEventListener("click", function () {
        cachedExfilEvents = [];
        try {
          chrome.runtime.sendMessage({ type: "BOXEDIN_RESET_EXFIL_EVENTS" }, function () {
            if (chrome.runtime.lastError) { /* ignore */ }
          });
        } catch (e) { /* ignore */ }
        if (activeTab === "exfil") renderActivePanel();
      });
    }

    var filters = root.querySelectorAll(".boxedin-rt__filter");
    for (var i = 0; i < filters.length; i++) {
      (function (btn) {
        btn.addEventListener("click", function () {
          var f = btn.getAttribute("data-filter");
          exfilFilter = f === "all" ? null : f;
          if (activeTab === "exfil") renderActivePanel();
        });
      })(filters[i]);
    }

    var eventRows = root.querySelectorAll(".boxedin-rt__event[data-rpt-url]");
    for (var er = 0; er < eventRows.length; er++) {
      (function (row) {
        row.style.cursor = "pointer";
        row.addEventListener("click", function (ev) {
          if (ev.target.classList.contains("boxedin-rt__allow-btn")) return;
          var rptUrl = row.getAttribute("data-rpt-url");
          var rptMethod = row.getAttribute("data-rpt-method") || "GET";
          if (!rptUrl) { openRepeater({}); return; }
          try {
            chrome.runtime.sendMessage({ type: "BOXEDIN_GET_CAPTURED_REQUESTS" }, function (resp) {
              var matched = null;
              if (!chrome.runtime.lastError && resp && resp.requests) {
                for (var mi = resp.requests.length - 1; mi >= 0; mi--) {
                  if (resp.requests[mi].url === rptUrl) { matched = resp.requests[mi]; break; }
                }
              }
              openRepeater({
                url: rptUrl,
                method: matched ? matched.method : rptMethod,
                headers: matched ? matched.headers : {},
                body: matched ? matched.body : ""
              });
            });
          } catch (e) {
            openRepeater({ url: rptUrl, method: rptMethod });
          }
        });
      })(eventRows[er]);
    }

    var allowBtns = root.querySelectorAll(".boxedin-rt__allow-btn");
    for (var a = 0; a < allowBtns.length; a++) {
      (function (btn) {
        btn.addEventListener("click", function () {
          var host = btn.getAttribute("data-host");
          if (!host) return;
          chrome.storage.local.get([STORAGE_EXFIL_ALLOWLIST], function (items) {
            var list = (items[STORAGE_EXFIL_ALLOWLIST] || []).slice();
            if (list.indexOf(host) === -1) list.push(host);
            var patch = {};
            patch[STORAGE_EXFIL_ALLOWLIST] = list;
            chrome.storage.local.set(patch);
            exfilAllowlist = list;
            if (activeTab === "exfil") renderActivePanel();
          });
        });
      })(allowBtns[a]);
    }

    var exfilOsintBtns = root.querySelectorAll(".boxedin-rt__stream .boxedin-rt__osint-btn");
    for (var eo = 0; eo < exfilOsintBtns.length; eo++) {
      (function (btn) {
        btn.addEventListener("click", function (ev) {
          ev.preventDefault();
          ev.stopPropagation();
          openCrtShSearch(btn.getAttribute("data-domain"));
        });
      })(exfilOsintBtns[eo]);
    }

    var exfilShodanBtns = root.querySelectorAll(".boxedin-rt__stream .boxedin-rt__shodan-btn");
    for (var es = 0; es < exfilShodanBtns.length; es++) {
      (function (btn) {
        btn.addEventListener("click", function (ev) {
          ev.preventDefault();
          ev.stopPropagation();
          openShodanSearch(btn.getAttribute("data-query"));
        });
      })(exfilShodanBtns[es]);
    }
  }

  /** Re-render the Exfil panel while preserving .boxedin-rt__stream scroll. */
  function exfilRenderWithScroll() {
    var streamEl = root && root.querySelector(".boxedin-rt__stream");
    var prevScroll = streamEl ? streamEl.scrollTop : 0;
    renderShell(buildExfilBody());
    wireExfilPanel();
    var newStream = root && root.querySelector(".boxedin-rt__stream");
    if (newStream && prevScroll) newStream.scrollTop = prevScroll;
  }

  /** Fetch exfil events from the background, merge with local cache, and render. */
  function fetchExfilAndRender() {
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_GET_EXFIL_EVENTS" }, function (response) {
        if (chrome.runtime.lastError) {
          if (activeTab === "exfil") exfilRenderWithScroll();
          return;
        }
        if (response && response.events && response.events.length > cachedExfilEvents.length) {
          cachedExfilEvents = response.events;
        }
        if (activeTab === "exfil") exfilRenderWithScroll();
      });
    } catch (e) {
      if (activeTab === "exfil") exfilRenderWithScroll();
    }
  }

  /* ── Inject panel ──────────────────────────────────────────────────── */

  /**
   * Build the Inject panel HTML: CSP analysis with directive table,
   * CORS issues, CSRF form gaps, and XSS sink / reflected-param findings.
   */
  function buildInjectBody(data) {
    if (!redteamEnabled) {
      return '<p class="boxedin-rt__disabled">Enable red-team tools in the BoxedIn options page.</p>';
    }
    if (!data) return '<p class="boxedin-rt__none">Loading injection findings\u2026</p>';

    var parts = [];

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">CSP Analysis</div>');
    var csp = data.csp;
    if (csp) {
      if (csp.missing) {
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--critical">Critical</span> ' +
          '<span class="boxedin-rt__item-label">No CSP header present</span></div>');
      } else {
        if (csp.reportOnly) {
          parts.push(
            '<div class="boxedin-rt__item">' +
            '<span class="boxedin-rt__badge boxedin-rt__badge--warning">Warning</span> ' +
            '<span class="boxedin-rt__item-label">CSP is report-only</span></div>');
        }
        if (csp.issues && csp.issues.length > 0) {
          for (var ci = 0; ci < csp.issues.length; ci++) {
            var sev = csp.issues[ci].indexOf("missing") !== -1 ? "warning" : "critical";
            parts.push(
              '<div class="boxedin-rt__item">' +
              '<span class="boxedin-rt__badge boxedin-rt__badge--' + sev + '">' +
              (sev === "critical" ? "Critical" : "Warning") + '</span> ' +
              '<span class="boxedin-rt__item-label">' + escapeHtml(csp.issues[ci]) + '</span></div>');
          }
        }
        if (csp.directives) {
          parts.push('<table class="boxedin-rt__directive-table"><thead><tr><th>Directive</th><th>Value</th></tr></thead><tbody>');
          var dKeys = Object.keys(csp.directives);
          for (var di = 0; di < dKeys.length; di++) {
            parts.push('<tr><td>' + escapeHtml(dKeys[di]) + '</td><td>' +
              escapeHtml(csp.directives[dKeys[di]] || "(empty)") + '</td></tr>');
          }
          parts.push('</tbody></table>');
        }
      }
    } else {
      parts.push('<p class="boxedin-rt__none">No CSP data yet.</p>');
    }
    parts.push('</div>');

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">CORS Analysis</div>');
    var cors = data.cors || [];
    if (cors.length > 0) {
      for (var coi = 0; coi < cors.length; coi++) {
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--warning">Warning</span> ' +
          '<span class="boxedin-rt__item-label">' + escapeHtml(cors[coi]) + '</span></div>');
      }
    } else {
      parts.push('<p class="boxedin-rt__none">No CORS issues detected.</p>');
    }
    parts.push('</div>');

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">CSRF Gaps</div>');
    var csrf = data.csrf || [];
    if (csrf.length > 0) {
      for (var csi = 0; csi < csrf.length; csi++) {
        var csrfItem = csrf[csi];
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--warning">Warning</span> ' +
          '<span class="boxedin-rt__item-label">Form without CSRF token</span>' +
          '<div class="boxedin-rt__item-detail">' + escapeHtml(csrfItem.method || "POST") +
          ' \u2192 ' + escapeHtml((csrfItem.action || "").slice(0, 100)) +
          (csrfItem.id ? ' (id="' + escapeHtml(csrfItem.id) + '")' : '') + '</div></div>');
      }
    } else {
      parts.push('<p class="boxedin-rt__none">No CSRF gaps detected (or no forms scanned yet).</p>');
    }
    parts.push('</div>');

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">XSS Sinks</div>');
    var xss = data.xss || [];
    var reflected = data.reflectedParams || [];
    if (xss.length > 0 || reflected.length > 0) {
      for (var xi = 0; xi < xss.length; xi++) {
        var xssItem = xss[xi];
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--critical">Critical</span> ' +
          '<span class="boxedin-rt__item-label">' + escapeHtml(xssItem.sink || "DOM write") + '</span>' +
          '<div class="boxedin-rt__item-detail">' + escapeHtml(xssItem.preview || "") + '</div></div>');
      }
      for (var rpi = 0; rpi < reflected.length; rpi++) {
        var rp = reflected[rpi];
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--warning">Warning</span> ' +
          '<span class="boxedin-rt__item-label">Reflected ' + escapeHtml(rp.context || "param") +
          ': ' + escapeHtml(rp.param || "") + '</span>' +
          '<div class="boxedin-rt__item-detail">' + escapeHtml((rp.value || "").slice(0, 60)) + '</div></div>');
      }
    } else {
      parts.push('<p class="boxedin-rt__none">No XSS sinks observed yet.</p>');
    }
    parts.push('</div>');

    var openRedirects = data.openRedirects || [];
    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">Open Redirects</div>');
    if (openRedirects.length > 0) {
      for (var ori = 0; ori < openRedirects.length; ori++) {
        var or = openRedirects[ori];
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--warning">Warning</span> ' +
          '<span class="boxedin-rt__item-label">Redirect param: ' + escapeHtml(or.param || "") + '</span>' +
          '<div class="boxedin-rt__item-detail">' + escapeHtml((or.value || "").slice(0, 150)) + '</div></div>');
      }
    } else {
      parts.push('<p class="boxedin-rt__none">No open redirect parameters detected.</p>');
    }
    parts.push('</div>');

    var mixedContent = data.mixedContent || [];
    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">Mixed Content</div>');
    if (mixedContent.length > 0) {
      for (var mci = 0; mci < mixedContent.length; mci++) {
        var mc = mixedContent[mci];
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--warning">Warning</span> ' +
          '<span class="boxedin-rt__item-label">HTTP &lt;' + escapeHtml(mc.tag || "unknown") + '&gt;</span>' +
          '<div class="boxedin-rt__item-detail">' + escapeHtml((mc.url || "").slice(0, 150)) + '</div></div>');
      }
    } else {
      parts.push('<p class="boxedin-rt__none">No mixed content detected' + (window.location.protocol !== "https:" ? ' (page is not HTTPS)' : '') + '.</p>');
    }
    parts.push('</div>');

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">CORS Probe</div>');
    if (cachedCorsProbe) {
      if (cachedCorsProbe.error) {
        parts.push('<p class="boxedin-rt__none">Request failed: ' + escapeHtml(cachedCorsProbe.error) + '</p>');
      } else if (cachedCorsProbe.vulnerable) {
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--critical">Critical</span> ' +
          '<span class="boxedin-rt__item-label">' + escapeHtml(cachedCorsProbe.reason) + '</span>' +
          '<div class="boxedin-rt__item-detail">ACAO: ' + escapeHtml(cachedCorsProbe.acao) +
          (cachedCorsProbe.acac ? ' | ACAC: ' + escapeHtml(cachedCorsProbe.acac) : '') + '</div></div>');
      } else {
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--info">Safe</span> ' +
          '<span class="boxedin-rt__item-label">Origin not reflected</span>' +
          '<div class="boxedin-rt__item-detail">ACAO: ' + escapeHtml(cachedCorsProbe.acao || "(none)") + '</div></div>');
      }
      parts.push('<button type="button" class="boxedin-rt__probe-cors-btn">Re-test CORS</button>');
    } else {
      parts.push(
        '<p class="boxedin-rt__osint-hint">Actively test whether the server reflects arbitrary origins in Access-Control-Allow-Origin.</p>' +
        '<button type="button" class="boxedin-rt__probe-cors-btn">Test CORS</button>');
    }
    parts.push('</div>');

    var formInventory = data.formInventory || {};
    var formForms = formInventory.forms || [];
    var formStandalone = formInventory.standaloneInputs || [];
    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">Form Surface' +
      (formForms.length > 0 ? '<span class="boxedin-rt__recon-count">' + formForms.length + ' forms</span>' : '') +
      '</div>');
    if (formForms.length > 0 || formStandalone.length > 0) {
      for (var ffi = 0; ffi < formForms.length; ffi++) {
        var ff = formForms[ffi];
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--info">Form</span> ' +
          '<span class="boxedin-rt__item-label">' + escapeHtml(ff.method || "GET") +
          ' \u2192 ' + escapeHtml((ff.action || "").slice(0, 100)) + '</span>');
        if (ff.fields && ff.fields.length > 0) {
          parts.push('<div class="boxedin-rt__item-detail">');
          for (var fii = 0; fii < ff.fields.length; fii++) {
            var field = ff.fields[fii];
            parts.push(
              '&lt;' + escapeHtml(field.tag || "input") + '&gt; ' +
              'type=' + escapeHtml(field.type || "text") +
              (field.name ? ' name="' + escapeHtml(field.name) + '"' : '') +
              (field.autocomplete ? ' autocomplete="' + escapeHtml(field.autocomplete) + '"' : '') +
              (field.required ? ' required' : '') + '<br>');
          }
          parts.push('</div>');
        }
        parts.push('</div>');
      }
      if (formStandalone.length > 0) {
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--info">Standalone</span> ' +
          '<span class="boxedin-rt__item-label">' + formStandalone.length + ' input(s) outside any form</span>' +
          '<div class="boxedin-rt__item-detail">');
        for (var fsi = 0; fsi < formStandalone.length; fsi++) {
          var sf = formStandalone[fsi];
          parts.push(
            'type=' + escapeHtml(sf.type || "text") +
            (sf.name ? ' name="' + escapeHtml(sf.name) + '"' : '') +
            (sf.autocomplete ? ' autocomplete="' + escapeHtml(sf.autocomplete) + '"' : '') + '<br>');
        }
        parts.push('</div></div>');
      }
    } else {
      parts.push('<p class="boxedin-rt__none">No forms or input fields found.</p>');
    }
    parts.push('</div>');

    return parts.join("");
  }

  /** Fetch inject findings from the background and render the Inject panel. */
  function fetchInjectAndRender() {
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_GET_INJECT_FINDINGS" }, function (response) {
        if (chrome.runtime.lastError) {
          if (activeTab === "inject") {
            renderShell(buildInjectBody(null));
            wireInjectPanel();
          }
          return;
        }
        if (activeTab === "inject") {
          renderShell(buildInjectBody(response));
          wireInjectPanel();
        }
      });
    } catch (e) {
      if (activeTab === "inject") {
        renderShell(buildInjectBody(null));
        wireInjectPanel();
      }
    }
  }

  function wireInjectPanel() {
    var corsBtn = root.querySelector(".boxedin-rt__probe-cors-btn");
    if (corsBtn) {
      corsBtn.addEventListener("click", function () {
        corsBtn.disabled = true;
        corsBtn.textContent = "Testing\u2026";
        var origin = window.location.origin;
        try {
          chrome.runtime.sendMessage({ type: "BOXEDIN_PROBE_CORS", origin: origin }, function (response) {
            if (chrome.runtime.lastError) {
              corsBtn.textContent = "Error";
              return;
            }
            cachedCorsProbe = (response && response.result) || { error: "No response" };
            if (activeTab === "inject") fetchInjectAndRender();
          });
        } catch (e) {
          corsBtn.textContent = "Error";
        }
      });
    }
  }

  /* ── Recon panel ──────────────────────────────────────────────────── */

  /**
   * Build the Recon panel HTML from tech-stack findings grouped by
   * category (CMS, Frameworks, Analytics, Server).
   */
  function buildReconBody(findings) {
    if (!redteamEnabled) {
      return '<p class="boxedin-rt__disabled">Enable red-team tools in the BoxedIn options page.</p>';
    }

    var parts = [];
    var hasContent = false;

    if (cachedSubdomains.length > 0) {
      hasContent = true;
      parts.push(
        '<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">Subdomains' +
        '<span class="boxedin-rt__recon-count">' + cachedSubdomains.length + '</span></div>');
      parts.push('<p class="boxedin-rt__osint-hint">Subdomains of ' + escapeHtml(cachedBaseDomain) + ' found in page resources.</p>');
      for (var sdi = 0; sdi < cachedSubdomains.length; sdi++) {
        parts.push(
          '<div class="boxedin-rt__item"><span class="boxedin-rt__item-label">' +
          escapeHtml(cachedSubdomains[sdi]) + '</span></div>');
      }
      parts.push('</div>');
    }

    if (cachedSourceMaps.length > 0) {
      hasContent = true;
      parts.push(
        '<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">Source Maps' +
        '<span class="boxedin-rt__recon-count">' + cachedSourceMaps.length + '</span></div>');
      parts.push('<p class="boxedin-rt__osint-hint">Source maps expose original source code in production.</p>');
      for (var smi = 0; smi < cachedSourceMaps.length; smi++) {
        var sm = cachedSourceMaps[smi];
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--warning">Warning</span> ' +
          '<span class="boxedin-rt__item-label">' + escapeHtml(sm.type) + '</span>' +
          '<div class="boxedin-rt__item-detail">' + escapeHtml(sm.url || "") + '</div></div>');
      }
      parts.push('</div>');
    }

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">Sensitive Paths</div>');
    if (cachedProbeResults) {
      var found = cachedProbeResults.filter(function (r) { return r.found; });
      if (found.length === 0) {
        parts.push('<p class="boxedin-rt__none">No sensitive paths found (' + cachedProbeResults.length + ' paths probed).</p>');
      } else {
        for (var pri = 0; pri < found.length; pri++) {
          var pr = found[pri];
          var prSev = pr.risk === "critical" ? "critical" : pr.risk === "high" ? "critical" : pr.risk === "medium" ? "warning" : "info";
          var prSevLabel = pr.risk.charAt(0).toUpperCase() + pr.risk.slice(1);
          parts.push(
            '<div class="boxedin-rt__item">' +
            '<span class="boxedin-rt__badge boxedin-rt__badge--' + prSev + '">' + prSevLabel + '</span> ' +
            '<span class="boxedin-rt__item-label">' + escapeHtml(pr.path) + ' (' + pr.status + ')</span>' +
            '<button type="button" class="boxedin-rt__probe-view-btn" data-path="' + escapeAttr(pr.path) + '" title="Fetch and view contents">\u{1F441}</button>' +
            '<div class="boxedin-rt__item-detail">' + escapeHtml(pr.desc) + '</div>' +
            '<div class="boxedin-rt__probe-content" data-for="' + escapeAttr(pr.path) + '"></div>' +
            '</div>');
        }
      }
      parts.push('<button type="button" class="boxedin-rt__probe-paths-btn">Re-probe</button>');
    } else {
      parts.push(
        '<p class="boxedin-rt__osint-hint">Probe common paths for exposed files and endpoints.</p>' +
        '<button type="button" class="boxedin-rt__probe-paths-btn">Probe Paths</button>');
    }
    parts.push('<div class="boxedin-rt__probe-results"></div></div>');

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">DNS Security Audit</div>');
    if (cachedDnsFindings) {
      var dnsCounts = { critical: 0, high: 0, medium: 0, info: 0 };
      var dnsSummaryParts = [];
      for (var dfi = 0; dfi < cachedDnsFindings.length; dfi++) {
        var df = cachedDnsFindings[dfi];
        dnsCounts[df.risk] = (dnsCounts[df.risk] || 0) + 1;
        var dfBadge = df.risk === "critical" ? "critical" : df.risk === "high" ? "critical" : df.risk === "medium" ? "warning" : "info";
        var dfLabel = df.risk.charAt(0).toUpperCase() + df.risk.slice(1);
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--' + dfBadge + '">' + dfLabel + '</span> ' +
          '<span class="boxedin-rt__dns-check">[' + escapeHtml(df.check) + ']</span> ' +
          '<span class="boxedin-rt__item-label">' + escapeHtml(df.title) + '</span>' +
          '<div class="boxedin-rt__item-detail">' + escapeHtml(df.detail || "") + '</div></div>');
      }
      if (dnsCounts.critical) dnsSummaryParts.push(dnsCounts.critical + " Critical");
      if (dnsCounts.high) dnsSummaryParts.push(dnsCounts.high + " High");
      if (dnsCounts.medium) dnsSummaryParts.push(dnsCounts.medium + " Medium");
      if (dnsCounts.info) dnsSummaryParts.push(dnsCounts.info + " Info");
      parts.push('<p class="boxedin-rt__osint-hint"><strong>' + escapeHtml(cachedDnsDomain) + '</strong> \u2014 ' + dnsSummaryParts.join(", ") + '</p>');
      parts.push('<button type="button" class="boxedin-rt__dns-audit-btn">Re-run DNS Audit</button>');
    } else {
      parts.push(
        '<p class="boxedin-rt__osint-hint">Check SPF, DKIM, DMARC, DNSSEC, CAA, MX, and NS records via DNS-over-HTTPS (dns.google).</p>' +
        '<button type="button" class="boxedin-rt__dns-audit-btn">Run DNS Audit</button>');
    }
    parts.push('<div class="boxedin-rt__dns-results"></div></div>');

    if (findings && findings.length > 0) {
      hasContent = true;
      var groups = { cms: [], framework: [], analytics: [], server: [] };
      for (var i = 0; i < findings.length; i++) {
        var f = findings[i];
        var cat = f.category || "server";
        if (!groups[cat]) groups[cat] = [];
        groups[cat].push(f);
      }

      var groupMeta = [
        { key: "cms", label: "CMS" },
        { key: "framework", label: "Frameworks" },
        { key: "analytics", label: "Analytics" },
        { key: "server", label: "Server" }
      ];

      for (var g = 0; g < groupMeta.length; g++) {
        var gm = groupMeta[g];
        var items = groups[gm.key];
        if (!items || items.length === 0) continue;

        parts.push(
          '<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">' +
          escapeHtml(gm.label) +
          '<span class="boxedin-rt__recon-count">' + items.length + '</span>' +
          '</div>');

        for (var j = 0; j < items.length; j++) {
          var item = items[j];
          var nameStr = escapeHtml(item.name || "Unknown");
          if (item.version) nameStr += ' <span class="boxedin-rt__recon-version">' + escapeHtml(item.version) + '</span>';

          parts.push(
            '<div class="boxedin-rt__item">' +
            '<span class="boxedin-rt__item-label">' + nameStr + '</span>' +
            '<span class="boxedin-rt__recon-evidence">' + escapeHtml(item.evidence || "") + '</span>');

          if (item.attackNotes) {
            parts.push(
              '<div class="boxedin-rt__item-detail">' + escapeHtml(item.attackNotes) + '</div>');
          }
          parts.push('</div>');
        }

        parts.push('</div>');
      }
    }

    if (!hasContent && (!findings || findings.length === 0)) {
      parts.unshift('<p class="boxedin-rt__none">No tech-stack findings yet. Navigate to a site and reload to scan.</p>');
    }

    return parts.join("");
  }

  /** Fetch tech-stack findings from the background and render the Recon panel. */
  function fetchReconAndRender() {
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_GET_TECH_FINDINGS" }, function (response) {
        if (chrome.runtime.lastError) {
          if (activeTab === "recon") {
            renderShell(buildReconBody([]));
            wireReconPanel();
          }
          return;
        }
        var findings = (response && response.findings) || [];
        if (activeTab === "recon") {
          renderShell(buildReconBody(findings));
          wireReconPanel();
        }
      });
    } catch (e) {
      if (activeTab === "recon") {
        renderShell(buildReconBody([]));
        wireReconPanel();
      }
    }
  }

  function wireReconPanel() {
    var probeBtn = root.querySelector(".boxedin-rt__probe-paths-btn");
    if (probeBtn) {
      probeBtn.addEventListener("click", function () {
        probeBtn.disabled = true;
        probeBtn.textContent = "Probing\u2026";
        var origin = window.location.origin;
        try {
          chrome.runtime.sendMessage({ type: "BOXEDIN_PROBE_PATHS", origin: origin }, function (response) {
            if (chrome.runtime.lastError) {
              probeBtn.textContent = "Error";
              return;
            }
            cachedProbeResults = (response && response.results) || [];
            if (activeTab === "recon") fetchReconAndRender();
          });
        } catch (e) {
          probeBtn.textContent = "Error";
        }
      });
    }

    var viewBtns = root.querySelectorAll(".boxedin-rt__probe-view-btn");
    for (var vi = 0; vi < viewBtns.length; vi++) {
      (function (btn) {
        btn.addEventListener("click", function () {
          var path = btn.getAttribute("data-path");
          if (!path) return;
          var contentEl = root.querySelector('.boxedin-rt__probe-content[data-for="' + path.replace(/"/g, '\\"') + '"]');
          if (!contentEl) return;
          if (contentEl.style.display === "block") {
            contentEl.style.display = "none";
            return;
          }
          if (contentEl.getAttribute("data-loaded")) {
            contentEl.style.display = "block";
            return;
          }
          contentEl.innerHTML = '<p class="boxedin-rt__none">Fetching\u2026</p>';
          contentEl.style.display = "block";
          var url = window.location.origin + path;
          try {
            chrome.runtime.sendMessage({ type: "BOXEDIN_FETCH_PATH_CONTENT", url: url }, function (response) {
              if (chrome.runtime.lastError || !response) {
                contentEl.innerHTML = '<p class="boxedin-rt__none">Failed to fetch.</p>';
                return;
              }
              contentEl.setAttribute("data-loaded", "1");
              var ct = response.contentType || "";
              var body = response.body || "";
              var headerHtml = '<div class="boxedin-rt__probe-content-meta">HTTP ' +
                (response.status || "?") + ' | ' + escapeHtml(ct.split(";")[0]) +
                ' | ' + body.length + ' bytes</div>';
              contentEl.innerHTML = headerHtml +
                '<pre class="boxedin-rt__probe-content-body">' + escapeHtml(body) + '</pre>';
            });
          } catch (e) {
            contentEl.innerHTML = '<p class="boxedin-rt__none">Error.</p>';
          }
        });
      })(viewBtns[vi]);
    }

    var dnsBtn = root.querySelector(".boxedin-rt__dns-audit-btn");
    if (dnsBtn) {
      dnsBtn.addEventListener("click", function () {
        dnsBtn.disabled = true;
        dnsBtn.textContent = "Querying DNS\u2026";
        var domain = window.location.hostname;
        try {
          chrome.runtime.sendMessage({ type: "BOXEDIN_DNS_AUDIT", domain: domain }, function (response) {
            if (chrome.runtime.lastError) {
              dnsBtn.textContent = "Error";
              return;
            }
            cachedDnsFindings = (response && response.findings) || [];
            cachedDnsDomain = (response && response.domain) || domain;
            if (activeTab === "recon") fetchReconAndRender();
          });
        } catch (e) {
          dnsBtn.textContent = "Error";
        }
      });
    }
  }

  /* ── APIs panel ──────────────────────────────────────────────────── */

  function buildApisBody(staticFindings, runtimeFindings) {
    if (!redteamEnabled) {
      return '<p class="boxedin-rt__disabled">Enable red-team tools in the BoxedIn options page.</p>';
    }

    staticFindings = staticFindings || [];
    runtimeFindings = runtimeFindings || [];

    if (staticFindings.length === 0 && runtimeFindings.length === 0) {
      return '<p class="boxedin-rt__none">No API endpoints discovered yet. Navigate to a site and reload to scan.</p>';
    }

    var parts = [];

    function methodBadge(m) {
      var cls = "boxedin-rt__method-badge";
      var ml = (m || "?").toUpperCase();
      if (ml === "GET") cls += " boxedin-rt__method--get";
      else if (ml === "POST") cls += " boxedin-rt__method--post";
      else if (ml === "PUT") cls += " boxedin-rt__method--put";
      else if (ml === "DELETE") cls += " boxedin-rt__method--delete";
      else if (ml === "PATCH") cls += " boxedin-rt__method--patch";
      return '<span class="' + cls + '">' + escapeHtml(ml) + '</span>';
    }

    if (staticFindings.length > 0) {
      var originGroups = { inline: [], config: [], dom: [], "script-src": [] };
      for (var si = 0; si < staticFindings.length; si++) {
        var f = staticFindings[si];
        var origin = f.origin || "inline";
        if (!originGroups[origin]) originGroups[origin] = [];
        originGroups[origin].push(f);
      }

      var originMeta = [
        { key: "inline", label: "Inline Scripts" },
        { key: "config", label: "Window Config Objects" },
        { key: "dom", label: "DOM Attributes" },
        { key: "script-src", label: "Script Sources" }
      ];

      parts.push(
        '<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">' +
        'Found in Code' +
        '<span class="boxedin-rt__recon-count">' + staticFindings.length + '</span>' +
        '</div>');

      for (var og = 0; og < originMeta.length; og++) {
        var items = originGroups[originMeta[og].key];
        if (!items || items.length === 0) continue;

        parts.push(
          '<div class="boxedin-rt__api-origin-head">' +
          escapeHtml(originMeta[og].label) +
          ' <span class="boxedin-rt__api-origin-count">(' + items.length + ')</span></div>');

        for (var j = 0; j < items.length; j++) {
          var item = items[j];
          parts.push(
            '<div class="boxedin-rt__api-row">' +
            methodBadge(item.method) +
            '<span class="boxedin-rt__api-url" title="' + escapeAttr(item.url || "") + '">' +
            escapeHtml(item.url || "") + '</span>');
          if (item.context) {
            parts.push(
              '<span class="boxedin-rt__api-context" title="' + escapeAttr(item.context) + '">' +
              escapeHtml(item.context) + '</span>');
          }
          parts.push('</div>');
        }
      }
      parts.push('</div>');
    }

    if (runtimeFindings.length > 0) {
      parts.push(
        '<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">' +
        'Observed at Runtime' +
        '<span class="boxedin-rt__recon-count">' + runtimeFindings.length + '</span>' +
        '</div>');

      for (var ri = 0; ri < runtimeFindings.length; ri++) {
        var rf = runtimeFindings[ri];
        parts.push(
          '<div class="boxedin-rt__api-row">' +
          methodBadge(rf.method) +
          '<span class="boxedin-rt__api-url" title="' + escapeAttr(rf.url || "") + '">' +
          escapeHtml(rf.url || "") + '</span>' +
          '</div>');
      }
      parts.push('</div>');
    }

    return parts.join("");
  }

  function fetchApisAndRender() {
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_GET_API_FINDINGS" }, function (response) {
        if (chrome.runtime.lastError) {
          if (activeTab === "apis") renderShell(buildApisBody([], []));
          return;
        }
        var staticFindings = (response && response.findings) || [];
        var runtimeFindings = (response && response.exfilApis) || [];
        if (activeTab === "apis") renderShell(buildApisBody(staticFindings, runtimeFindings));
      });
    } catch (e) {
      if (activeTab === "apis") renderShell(buildApisBody([], []));
    }
  }

  /* ── Deps panel ──────────────────────────────────────────────────── */

  function buildDepsBody(findings) {
    if (!redteamEnabled) {
      return '<p class="boxedin-rt__disabled">Enable red-team tools in the BoxedIn options page.</p>';
    }
    if (!findings || findings.length === 0) {
      return '<p class="boxedin-rt__none">No dependencies detected yet. Navigate to a site and reload to scan.</p>';
    }

    var thirdParty = [];
    var firstParty = [];
    for (var i = 0; i < findings.length; i++) {
      if (findings[i].thirdParty) thirdParty.push(findings[i]);
      else firstParty.push(findings[i]);
    }

    var noSri = thirdParty.filter(function (d) { return !d.sri; });
    var parts = [];

    if (noSri.length > 0) {
      parts.push(
        '<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">' +
        '<span class="boxedin-rt__badge boxedin-rt__badge--warning">Warning</span> ' +
        'Third-Party Without SRI<span class="boxedin-rt__recon-count">' + noSri.length + '</span></div>');
      parts.push('<p class="boxedin-rt__osint-hint">Third-party scripts/styles loaded without Subresource Integrity. Vulnerable to supply chain attacks if the CDN is compromised.</p>');
      for (var ni = 0; ni < noSri.length; ni++) {
        var ns = noSri[ni];
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--warning">' + escapeHtml(ns.type) + '</span> ' +
          '<span class="boxedin-rt__item-label">' + escapeHtml(ns.host) + '</span>' +
          '<div class="boxedin-rt__item-detail">' + escapeHtml((ns.url || "").slice(0, 150)) + '</div></div>');
      }
      parts.push('</div>');
    }

    if (thirdParty.length > 0) {
      parts.push(
        '<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">' +
        'Third-Party Dependencies<span class="boxedin-rt__recon-count">' + thirdParty.length + '</span></div>');
      for (var ti = 0; ti < thirdParty.length; ti++) {
        var tp = thirdParty[ti];
        var sriLabel = tp.sri ? '<span class="boxedin-rt__badge boxedin-rt__badge--info">SRI</span> ' : '';
        parts.push(
          '<div class="boxedin-rt__item">' + sriLabel +
          '<span class="boxedin-rt__badge boxedin-rt__badge--' + (tp.type === "script" ? "warning" : "info") + '">' +
          escapeHtml(tp.type) + '</span> ' +
          '<span class="boxedin-rt__item-label">' + escapeHtml(tp.host) + '</span>' +
          '<div class="boxedin-rt__item-detail">' + escapeHtml((tp.url || "").slice(0, 150)) +
          (tp.async ? ' async' : '') + (tp.defer ? ' defer' : '') + '</div></div>');
      }
      parts.push('</div>');
    }

    if (firstParty.length > 0) {
      parts.push(
        '<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">' +
        'First-Party Resources<span class="boxedin-rt__recon-count">' + firstParty.length + '</span></div>');
      for (var fpi = 0; fpi < firstParty.length; fpi++) {
        var fp = firstParty[fpi];
        parts.push(
          '<div class="boxedin-rt__item">' +
          '<span class="boxedin-rt__badge boxedin-rt__badge--info">' + escapeHtml(fp.type) + '</span> ' +
          '<span class="boxedin-rt__item-label">' + escapeHtml((fp.url || "").slice(0, 150)) + '</span></div>');
      }
      parts.push('</div>');
    }

    return parts.join("");
  }

  function fetchDepsAndRender() {
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_GET_DEPS_FINDINGS" }, function (response) {
        if (chrome.runtime.lastError) {
          if (activeTab === "deps") renderShell(buildDepsBody([]));
          return;
        }
        var findings = (response && response.findings) || [];
        if (activeTab === "deps") renderShell(buildDepsBody(findings));
      });
    } catch (e) {
      if (activeTab === "deps") renderShell(buildDepsBody([]));
    }
  }

  /* ── Timeline panel ────────────────────────────────────────────────── */

  function buildTimelineBody(events) {
    if (!redteamEnabled) {
      return '<p class="boxedin-rt__disabled">Enable red-team tools in the BoxedIn options page.</p>';
    }
    if (!events || events.length === 0) {
      return '<p class="boxedin-rt__none">No network events recorded yet. Navigate to a site and interact to capture activity.</p>';
    }

    var parts = [];
    parts.push(
      '<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">Request Flow' +
      '<span class="boxedin-rt__recon-count">' + events.length + ' events</span></div>');

    var firstTs = events[0].ts || 0;
    for (var i = 0; i < events.length; i++) {
      var ev = events[i];
      var elapsed = firstTs ? ((ev.ts || 0) - firstTs) : 0;
      var elapsedStr = elapsed >= 0 ? "+" + (elapsed / 1000).toFixed(2) + "s" : "";
      var timeStr = formatTime(ev.ts);
      var typeCls = "info";
      if (ev.type === "fetch" || ev.type === "xhr") typeCls = "warning";
      else if (ev.type === "websocket") typeCls = "critical";
      else if (ev.type === "form-submit") typeCls = "critical";
      else if (ev.type === "clipboard-write" || ev.type === "clipboard-read") typeCls = "critical";

      parts.push(
        '<div class="boxedin-rt__item boxedin-rt__timeline-item">' +
        '<span class="boxedin-rt__timeline-time">' + escapeHtml(timeStr) + '</span>' +
        '<span class="boxedin-rt__timeline-elapsed">' + escapeHtml(elapsedStr) + '</span>' +
        '<span class="boxedin-rt__badge boxedin-rt__badge--' + typeCls + '">' + escapeHtml(ev.type || "?") + '</span> ');

      if (ev.method && ev.method !== "GET") {
        parts.push('<span class="boxedin-rt__method-badge">' + escapeHtml(ev.method) + '</span> ');
      }

      parts.push(
        '<span class="boxedin-rt__item-label">' + escapeHtml((ev.url || "").slice(0, 120)) + '</span>' +
        '</div>');
    }

    parts.push('</div>');
    return parts.join("");
  }

  function fetchTimelineAndRender() {
    try {
      chrome.runtime.sendMessage({ type: "BOXEDIN_GET_TIMELINE" }, function (response) {
        if (chrome.runtime.lastError) {
          if (activeTab === "timeline") renderShell(buildTimelineBody([]));
          return;
        }
        var events = (response && response.events) || [];
        if (activeTab === "timeline") renderShell(buildTimelineBody(events));
      });
    } catch (e) {
      if (activeTab === "timeline") renderShell(buildTimelineBody([]));
    }
  }

  /* ── OSINT panel ─────────────────────────────────────────────────── */

  /** Build and render the OSINT panel with crt.sh search for the current domain. */
  function renderOsintPanel() {
    if (!redteamEnabled) {
      renderShell('<p class="boxedin-rt__disabled">Enable red-team tools in the BoxedIn options page.</p>');
      return;
    }

    var pageDomain = "";
    try { pageDomain = window.location.hostname || ""; } catch (e) { /* ignore */ }

    var parts = [];

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">crt.sh — Certificate Transparency</div>');
    parts.push(
      '<p class="boxedin-rt__osint-hint">' +
      'Search certificate transparency logs for SSL certificates, subdomains, and exposed internal domain names.' +
      '</p>');

    if (pageDomain) {
      parts.push(
        '<div class="boxedin-rt__osint-search">' +
        '<code>' + escapeHtml(pageDomain) + '</code> ' +
        '<button type="button" class="boxedin-rt__osint-search-btn" data-domain="' +
        escapeAttr(pageDomain) + '">Search crt.sh</button>' +
        '</div>');
    } else {
      parts.push('<p class="boxedin-rt__none">No page domain available.</p>');
    }

    parts.push(
      '<div class="boxedin-rt__osint-manual">' +
      '<input type="text" class="boxedin-rt__osint-input" placeholder="example.com" spellcheck="false" />' +
      '<button type="button" class="boxedin-rt__osint-manual-btn">Search</button>' +
      '</div>');

    parts.push('</div>');

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">Shodan — Internet-Wide Scan Data</div>');
    parts.push(
      '<p class="boxedin-rt__osint-hint">' +
      'Search Shodan for open ports, services, banners, SSL info, and known vulnerabilities on a host.' +
      '</p>');

    if (pageDomain) {
      parts.push(
        '<div class="boxedin-rt__osint-search">' +
        '<code>' + escapeHtml(pageDomain) + '</code> ' +
        '<button type="button" class="boxedin-rt__osint-shodan-btn" data-query="' +
        escapeAttr(pageDomain) + '">Search Shodan</button>' +
        '</div>');
    } else {
      parts.push('<p class="boxedin-rt__none">No page domain available.</p>');
    }

    parts.push(
      '<div class="boxedin-rt__osint-manual">' +
      '<input type="text" class="boxedin-rt__osint-shodan-input" placeholder="example.com or 1.2.3.4" spellcheck="false" />' +
      '<button type="button" class="boxedin-rt__osint-shodan-manual-btn">Search</button>' +
      '</div>');

    parts.push('</div>');

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">WHOIS — Domain Registration</div>');
    parts.push(
      '<p class="boxedin-rt__osint-hint">' +
      'Look up domain registration details including registrant, registrar, creation/expiry dates, and name servers.' +
      '</p>');

    if (pageDomain) {
      parts.push(
        '<div class="boxedin-rt__osint-search">' +
        '<code>' + escapeHtml(pageDomain) + '</code> ' +
        '<button type="button" class="boxedin-rt__osint-whois-btn" data-domain="' +
        escapeAttr(pageDomain) + '">WHOIS Lookup</button>' +
        '</div>');
    } else {
      parts.push('<p class="boxedin-rt__none">No page domain available.</p>');
    }

    parts.push(
      '<div class="boxedin-rt__osint-manual">' +
      '<input type="text" class="boxedin-rt__osint-whois-input" placeholder="example.com" spellcheck="false" />' +
      '<button type="button" class="boxedin-rt__osint-whois-manual-btn">Lookup</button>' +
      '</div>');

    parts.push('</div>');

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">Wayback Machine — Web Archive</div>');
    parts.push(
      '<p class="boxedin-rt__osint-hint">' +
      'Browse archived snapshots of a site over time. Useful for finding removed pages, leaked content, old configurations, and historical changes.' +
      '</p>');

    if (pageDomain) {
      parts.push(
        '<div class="boxedin-rt__osint-search">' +
        '<code>' + escapeHtml(pageDomain) + '</code> ' +
        '<button type="button" class="boxedin-rt__osint-wayback-btn" data-domain="' +
        escapeAttr(pageDomain) + '">Search Wayback</button>' +
        '</div>');
    } else {
      parts.push('<p class="boxedin-rt__none">No page domain available.</p>');
    }

    parts.push(
      '<div class="boxedin-rt__osint-manual">' +
      '<input type="text" class="boxedin-rt__osint-wayback-input" placeholder="example.com" spellcheck="false" />' +
      '<button type="button" class="boxedin-rt__osint-wayback-manual-btn">Search</button>' +
      '</div>');

    parts.push('</div>');

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">Intelligence X — Deep Search</div>');
    parts.push(
      '<p class="boxedin-rt__osint-hint">' +
      'Search pastes, darknet, leaks, WHOIS history, DNS records, and more. Free tier allows 50 lookups/day.' +
      '</p>');

    if (pageDomain) {
      parts.push(
        '<div class="boxedin-rt__osint-search">' +
        '<code>' + escapeHtml(pageDomain) + '</code> ' +
        '<button type="button" class="boxedin-rt__osint-intelx-btn" data-query="' +
        escapeAttr(pageDomain) + '">Search IntelX</button>' +
        '</div>');
    } else {
      parts.push('<p class="boxedin-rt__none">No page domain available.</p>');
    }

    parts.push(
      '<div class="boxedin-rt__osint-manual">' +
      '<input type="text" class="boxedin-rt__osint-intelx-input" placeholder="example.com, email, IP, etc." spellcheck="false" />' +
      '<button type="button" class="boxedin-rt__osint-intelx-manual-btn">Search</button>' +
      '</div>');

    parts.push('</div>');

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">urlscan.io — URL &amp; Domain Scanner</div>');
    parts.push(
      '<p class="boxedin-rt__osint-hint">' +
      'Scans and analyses URLs/domains for malicious indicators, HTTP transactions, DOM snapshots, and technology stacks.' +
      '</p>');

    if (pageDomain) {
      parts.push(
        '<div class="boxedin-rt__osint-search">' +
        '<code>' + escapeHtml(pageDomain) + '</code> ' +
        '<button type="button" class="boxedin-rt__osint-urlscan-btn" data-domain="' +
        escapeAttr(pageDomain) + '">Search urlscan</button>' +
        '</div>');
    } else {
      parts.push('<p class="boxedin-rt__none">No page domain available.</p>');
    }

    parts.push(
      '<div class="boxedin-rt__osint-manual">' +
      '<input type="text" class="boxedin-rt__osint-urlscan-input" placeholder="example.com" spellcheck="false" />' +
      '<button type="button" class="boxedin-rt__osint-urlscan-manual-btn">Search</button>' +
      '</div>');

    parts.push('</div>');

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">Censys — Internet-Wide Host Search</div>');
    parts.push(
      '<p class="boxedin-rt__osint-hint">' +
      'Searches internet-wide scan data for hosts, certificates, open ports, and services. Free account allows 250 queries/month.' +
      '</p>');

    if (pageDomain) {
      parts.push(
        '<div class="boxedin-rt__osint-search">' +
        '<code>' + escapeHtml(pageDomain) + '</code> ' +
        '<button type="button" class="boxedin-rt__osint-censys-btn" data-domain="' +
        escapeAttr(pageDomain) + '">Search Censys</button>' +
        '</div>');
    } else {
      parts.push('<p class="boxedin-rt__none">No page domain available.</p>');
    }

    parts.push(
      '<div class="boxedin-rt__osint-manual">' +
      '<input type="text" class="boxedin-rt__osint-censys-input" placeholder="example.com or 1.2.3.4" spellcheck="false" />' +
      '<button type="button" class="boxedin-rt__osint-censys-manual-btn">Search</button>' +
      '</div>');

    parts.push('</div>');

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">Domain Dossier — DNS &amp; WHOIS Report</div>');
    parts.push(
      '<p class="boxedin-rt__osint-hint">' +
      'Runs DNS, WHOIS, and network WHOIS lookups in one combined report via CentralOps.net.' +
      '</p>');

    if (pageDomain) {
      parts.push(
        '<div class="boxedin-rt__osint-search">' +
        '<code>' + escapeHtml(pageDomain) + '</code> ' +
        '<button type="button" class="boxedin-rt__osint-dossier-btn" data-domain="' +
        escapeAttr(pageDomain) + '">Run Dossier</button>' +
        '</div>');
    } else {
      parts.push('<p class="boxedin-rt__none">No page domain available.</p>');
    }

    parts.push(
      '<div class="boxedin-rt__osint-manual">' +
      '<input type="text" class="boxedin-rt__osint-dossier-input" placeholder="example.com or IP" spellcheck="false" />' +
      '<button type="button" class="boxedin-rt__osint-dossier-manual-btn">Search</button>' +
      '</div>');

    parts.push('</div>');

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">PhishTank — Phishing URL Database</div>');
    parts.push(
      '<p class="boxedin-rt__osint-hint">' +
      'Community-driven database of verified phishing URLs. Check whether a domain has been reported for phishing activity.' +
      '</p>');

    if (pageDomain) {
      parts.push(
        '<div class="boxedin-rt__osint-search">' +
        '<code>' + escapeHtml(pageDomain) + '</code> ' +
        '<button type="button" class="boxedin-rt__osint-phishtank-btn" data-domain="' +
        escapeAttr(pageDomain) + '">Search PhishTank</button>' +
        '</div>');
    } else {
      parts.push('<p class="boxedin-rt__none">No page domain available.</p>');
    }

    parts.push(
      '<div class="boxedin-rt__osint-manual">' +
      '<input type="text" class="boxedin-rt__osint-phishtank-input" placeholder="example.com" spellcheck="false" />' +
      '<button type="button" class="boxedin-rt__osint-phishtank-manual-btn">Search</button>' +
      '</div>');

    parts.push('</div>');

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">FOFA — Cyberspace Search Engine</div>');
    parts.push(
      '<p class="boxedin-rt__osint-hint">' +
      'Chinese cyberspace mapping engine (similar to Shodan/Censys). Searches for hosts, ports, protocols, and banners. Free tier available.' +
      '</p>');

    if (pageDomain) {
      parts.push(
        '<div class="boxedin-rt__osint-search">' +
        '<code>' + escapeHtml(pageDomain) + '</code> ' +
        '<button type="button" class="boxedin-rt__osint-fofa-btn" data-domain="' +
        escapeAttr(pageDomain) + '">Search FOFA</button>' +
        '</div>');
    } else {
      parts.push('<p class="boxedin-rt__none">No page domain available.</p>');
    }

    parts.push(
      '<div class="boxedin-rt__osint-manual">' +
      '<input type="text" class="boxedin-rt__osint-fofa-input" placeholder="example.com" spellcheck="false" />' +
      '<button type="button" class="boxedin-rt__osint-fofa-manual-btn">Search</button>' +
      '</div>');

    parts.push('</div>');

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">Companies House — UK Company Registry</div>');
    parts.push(
      '<p class="boxedin-rt__osint-hint">' +
      'Official UK government registry of companies. Search by company name or domain to find registration details, directors, filings, and accounts.' +
      '</p>');

    if (pageDomain) {
      parts.push(
        '<div class="boxedin-rt__osint-search">' +
        '<code>' + escapeHtml(pageDomain) + '</code> ' +
        '<button type="button" class="boxedin-rt__osint-companieshouse-btn" data-query="' +
        escapeAttr(pageDomain) + '">Search Companies House</button>' +
        '</div>');
    } else {
      parts.push('<p class="boxedin-rt__none">No page domain available.</p>');
    }

    parts.push(
      '<div class="boxedin-rt__osint-manual">' +
      '<input type="text" class="boxedin-rt__osint-companieshouse-input" placeholder="company name or domain" spellcheck="false" />' +
      '<button type="button" class="boxedin-rt__osint-companieshouse-manual-btn">Search</button>' +
      '</div>');

    parts.push('</div>');

    parts.push('<div class="boxedin-rt__group"><div class="boxedin-rt__group-head">SecurityTrails — DNS History &amp; Intelligence</div>');
    parts.push(
      '<p class="boxedin-rt__osint-hint">' +
      'Historical DNS records, WHOIS changes, associated domains, subdomains, and hosting history. Free tier available.' +
      '</p>');

    if (pageDomain) {
      parts.push(
        '<div class="boxedin-rt__osint-search">' +
        '<code>' + escapeHtml(pageDomain) + '</code> ' +
        '<button type="button" class="boxedin-rt__osint-securitytrails-btn" data-domain="' +
        escapeAttr(pageDomain) + '">View DNS History</button>' +
        '</div>');
    } else {
      parts.push('<p class="boxedin-rt__none">No page domain available.</p>');
    }

    parts.push(
      '<div class="boxedin-rt__osint-manual">' +
      '<input type="text" class="boxedin-rt__osint-securitytrails-input" placeholder="example.com" spellcheck="false" />' +
      '<button type="button" class="boxedin-rt__osint-securitytrails-manual-btn">Search</button>' +
      '</div>');

    parts.push('</div>');

    renderShell(parts.join(""));
    wireOsintPanel();
  }

  /** Bind click handlers for the OSINT panel search buttons and input. */
  function wireOsintPanel() {
    var searchBtn = root.querySelector(".boxedin-rt__osint-search-btn");
    if (searchBtn) {
      searchBtn.addEventListener("click", function () {
        openCrtShSearch(searchBtn.getAttribute("data-domain"));
      });
    }

    var manualBtn = root.querySelector(".boxedin-rt__osint-manual-btn");
    var manualInput = root.querySelector(".boxedin-rt__osint-input");
    if (manualBtn && manualInput) {
      manualBtn.addEventListener("click", function () {
        var val = manualInput.value.trim();
        if (val) openCrtShSearch(val);
      });
      manualInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          e.preventDefault();
          var val = manualInput.value.trim();
          if (val) openCrtShSearch(val);
        }
      });
    }

    var shodanBtn = root.querySelector(".boxedin-rt__osint-shodan-btn");
    if (shodanBtn) {
      shodanBtn.addEventListener("click", function () {
        openShodanSearch(shodanBtn.getAttribute("data-query"));
      });
    }

    var shodanManualBtn = root.querySelector(".boxedin-rt__osint-shodan-manual-btn");
    var shodanManualInput = root.querySelector(".boxedin-rt__osint-shodan-input");
    if (shodanManualBtn && shodanManualInput) {
      shodanManualBtn.addEventListener("click", function () {
        var val = shodanManualInput.value.trim();
        if (val) openShodanSearch(val);
      });
      shodanManualInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          e.preventDefault();
          var val = shodanManualInput.value.trim();
          if (val) openShodanSearch(val);
        }
      });
    }

    var whoisBtn = root.querySelector(".boxedin-rt__osint-whois-btn");
    if (whoisBtn) {
      whoisBtn.addEventListener("click", function () {
        openWhoisSearch(whoisBtn.getAttribute("data-domain"));
      });
    }

    var whoisManualBtn = root.querySelector(".boxedin-rt__osint-whois-manual-btn");
    var whoisManualInput = root.querySelector(".boxedin-rt__osint-whois-input");
    if (whoisManualBtn && whoisManualInput) {
      whoisManualBtn.addEventListener("click", function () {
        var val = whoisManualInput.value.trim();
        if (val) openWhoisSearch(val);
      });
      whoisManualInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          e.preventDefault();
          var val = whoisManualInput.value.trim();
          if (val) openWhoisSearch(val);
        }
      });
    }

    var waybackBtn = root.querySelector(".boxedin-rt__osint-wayback-btn");
    if (waybackBtn) {
      waybackBtn.addEventListener("click", function () {
        openWaybackSearch(waybackBtn.getAttribute("data-domain"));
      });
    }

    var waybackManualBtn = root.querySelector(".boxedin-rt__osint-wayback-manual-btn");
    var waybackManualInput = root.querySelector(".boxedin-rt__osint-wayback-input");
    if (waybackManualBtn && waybackManualInput) {
      waybackManualBtn.addEventListener("click", function () {
        var val = waybackManualInput.value.trim();
        if (val) openWaybackSearch(val);
      });
      waybackManualInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          e.preventDefault();
          var val = waybackManualInput.value.trim();
          if (val) openWaybackSearch(val);
        }
      });
    }

    var intelxBtn = root.querySelector(".boxedin-rt__osint-intelx-btn");
    if (intelxBtn) {
      intelxBtn.addEventListener("click", function () {
        openIntelXSearch(intelxBtn.getAttribute("data-query"));
      });
    }

    var intelxManualBtn = root.querySelector(".boxedin-rt__osint-intelx-manual-btn");
    var intelxManualInput = root.querySelector(".boxedin-rt__osint-intelx-input");
    if (intelxManualBtn && intelxManualInput) {
      intelxManualBtn.addEventListener("click", function () {
        var val = intelxManualInput.value.trim();
        if (val) openIntelXSearch(val);
      });
      intelxManualInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          e.preventDefault();
          var val = intelxManualInput.value.trim();
          if (val) openIntelXSearch(val);
        }
      });
    }

    var urlscanBtn = root.querySelector(".boxedin-rt__osint-urlscan-btn");
    if (urlscanBtn) {
      urlscanBtn.addEventListener("click", function () {
        openUrlscanSearch(urlscanBtn.getAttribute("data-domain"));
      });
    }

    var urlscanManualBtn = root.querySelector(".boxedin-rt__osint-urlscan-manual-btn");
    var urlscanManualInput = root.querySelector(".boxedin-rt__osint-urlscan-input");
    if (urlscanManualBtn && urlscanManualInput) {
      urlscanManualBtn.addEventListener("click", function () {
        var val = urlscanManualInput.value.trim();
        if (val) openUrlscanSearch(val);
      });
      urlscanManualInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          e.preventDefault();
          var val = urlscanManualInput.value.trim();
          if (val) openUrlscanSearch(val);
        }
      });
    }

    var censysBtn = root.querySelector(".boxedin-rt__osint-censys-btn");
    if (censysBtn) {
      censysBtn.addEventListener("click", function () {
        openCensysSearch(censysBtn.getAttribute("data-domain"));
      });
    }

    var censysManualBtn = root.querySelector(".boxedin-rt__osint-censys-manual-btn");
    var censysManualInput = root.querySelector(".boxedin-rt__osint-censys-input");
    if (censysManualBtn && censysManualInput) {
      censysManualBtn.addEventListener("click", function () {
        var val = censysManualInput.value.trim();
        if (val) openCensysSearch(val);
      });
      censysManualInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          e.preventDefault();
          var val = censysManualInput.value.trim();
          if (val) openCensysSearch(val);
        }
      });
    }

    var dossierBtn = root.querySelector(".boxedin-rt__osint-dossier-btn");
    if (dossierBtn) {
      dossierBtn.addEventListener("click", function () {
        openDomainDossierSearch(dossierBtn.getAttribute("data-domain"));
      });
    }

    var dossierManualBtn = root.querySelector(".boxedin-rt__osint-dossier-manual-btn");
    var dossierManualInput = root.querySelector(".boxedin-rt__osint-dossier-input");
    if (dossierManualBtn && dossierManualInput) {
      dossierManualBtn.addEventListener("click", function () {
        var val = dossierManualInput.value.trim();
        if (val) openDomainDossierSearch(val);
      });
      dossierManualInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          e.preventDefault();
          var val = dossierManualInput.value.trim();
          if (val) openDomainDossierSearch(val);
        }
      });
    }

    var phishtankBtn = root.querySelector(".boxedin-rt__osint-phishtank-btn");
    if (phishtankBtn) {
      phishtankBtn.addEventListener("click", function () {
        openPhishTankSearch(phishtankBtn.getAttribute("data-domain"));
      });
    }

    var phishtankManualBtn = root.querySelector(".boxedin-rt__osint-phishtank-manual-btn");
    var phishtankManualInput = root.querySelector(".boxedin-rt__osint-phishtank-input");
    if (phishtankManualBtn && phishtankManualInput) {
      phishtankManualBtn.addEventListener("click", function () {
        var val = phishtankManualInput.value.trim();
        if (val) openPhishTankSearch(val);
      });
      phishtankManualInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          e.preventDefault();
          var val = phishtankManualInput.value.trim();
          if (val) openPhishTankSearch(val);
        }
      });
    }

    var fofaBtn = root.querySelector(".boxedin-rt__osint-fofa-btn");
    if (fofaBtn) {
      fofaBtn.addEventListener("click", function () {
        openFofaSearch(fofaBtn.getAttribute("data-domain"));
      });
    }

    var fofaManualBtn = root.querySelector(".boxedin-rt__osint-fofa-manual-btn");
    var fofaManualInput = root.querySelector(".boxedin-rt__osint-fofa-input");
    if (fofaManualBtn && fofaManualInput) {
      fofaManualBtn.addEventListener("click", function () {
        var val = fofaManualInput.value.trim();
        if (val) openFofaSearch(val);
      });
      fofaManualInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          e.preventDefault();
          var val = fofaManualInput.value.trim();
          if (val) openFofaSearch(val);
        }
      });
    }

    var chBtn = root.querySelector(".boxedin-rt__osint-companieshouse-btn");
    if (chBtn) {
      chBtn.addEventListener("click", function () {
        openCompaniesHouseSearch(chBtn.getAttribute("data-query"));
      });
    }

    var chManualBtn = root.querySelector(".boxedin-rt__osint-companieshouse-manual-btn");
    var chManualInput = root.querySelector(".boxedin-rt__osint-companieshouse-input");
    if (chManualBtn && chManualInput) {
      chManualBtn.addEventListener("click", function () {
        var val = chManualInput.value.trim();
        if (val) openCompaniesHouseSearch(val);
      });
      chManualInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          e.preventDefault();
          var val = chManualInput.value.trim();
          if (val) openCompaniesHouseSearch(val);
        }
      });
    }

    var stBtn = root.querySelector(".boxedin-rt__osint-securitytrails-btn");
    if (stBtn) {
      stBtn.addEventListener("click", function () {
        openSecurityTrailsSearch(stBtn.getAttribute("data-domain"));
      });
    }

    var stManualBtn = root.querySelector(".boxedin-rt__osint-securitytrails-manual-btn");
    var stManualInput = root.querySelector(".boxedin-rt__osint-securitytrails-input");
    if (stManualBtn && stManualInput) {
      stManualBtn.addEventListener("click", function () {
        var val = stManualInput.value.trim();
        if (val) openSecurityTrailsSearch(val);
      });
      stManualInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          e.preventDefault();
          var val = stManualInput.value.trim();
          if (val) openSecurityTrailsSearch(val);
        }
      });
    }
  }

  /* ── Fetch stats (blocks panel) ────────────────────────────────────── */

  /**
   * Flush any pending page-guard deltas, then fetch DNR + page-guard
   * block stats from the background and render the Blocks panel.
   */
  function fetchStats() {
    if (pgFlushTimer !== null) {
      clearTimeout(pgFlushTimer);
      pgFlushTimer = null;
    }
    function doGet() {
      try {
        chrome.runtime.sendMessage({ type: "BOXEDIN_GET_BLOCK_STATS" }, function (response) {
          if (chrome.runtime.lastError) {
            cachedBlocksPayload = { unavailable: true, reason: chrome.runtime.lastError.message };
            if (activeTab === "blocks") {
              renderShell(buildBlocksBody(cachedBlocksPayload));
              wireBlocksPanel(cachedBlocksPayload);
            }
            return;
          }
          cachedBlocksPayload = response || { rows: [], total: 0 };
          if (cachedBlocksPayload.extensionDisabled) {
            renderShell("", { extensionDisabled: true });
            return;
          }
          if (activeTab === "blocks") {
            renderShell(buildBlocksBody(cachedBlocksPayload));
            wireBlocksPanel(cachedBlocksPayload);
          }
        });
      } catch (e) {
        cachedBlocksPayload = { unavailable: true, reason: String(e && e.message) };
        if (activeTab === "blocks") {
          renderShell(buildBlocksBody(cachedBlocksPayload));
          wireBlocksPanel(cachedBlocksPayload);
        }
      }
    }
    var li = pendingPg.linkedInBlocklist;
    var es = pendingPg.extensionScheme;
    pendingPg.linkedInBlocklist = 0;
    pendingPg.extensionScheme = 0;
    if (li > 0 || es > 0) {
      var payload = { type: "BOXEDIN_PAGE_GUARD_STAT" };
      if (li > 0) payload.linkedInBlocklist = li;
      if (es > 0) payload.extensionScheme = es;
      try {
        chrome.runtime.sendMessage(payload, function () {
          if (chrome.runtime.lastError) { /* ignore */ }
          doGet();
        });
      } catch (e2) {
        pendingPg.linkedInBlocklist += li;
        pendingPg.extensionScheme += es;
        doGet();
      }
    } else {
      doGet();
    }
  }

  /* ── Repeater overlay ────────────────────────────────────────────── */

  /**
   * Show the repeater panel, optionally pre-filled with request data.
   * @param {Object} [prefill]  { url, method, headers, body } to pre-populate.
   */
  function openRepeater(prefill) {
    if (!repeaterRoot) return;
    repeaterRoot.style.display = "";
    renderRepeater(prefill);
  }

  /** Hide the repeater panel. */
  function closeRepeater() {
    if (repeaterRoot) repeaterRoot.style.display = "none";
  }

  /**
   * Render the repeater form: method selector, URL input, headers/body
   * textareas, send button, and response viewer. Strips browser-managed
   * headers (Cookie, Sec-*, etc.) from the pre-filled header object.
   */
  function renderRepeater(prefill) {
    if (!repeaterRoot) return;
    prefill = prefill || {};
    var method = prefill.method || "GET";
    var url = prefill.url || "";
    var headers = prefill.headers || "";
    var body = prefill.body || "";

    if (typeof headers === "object" && !Array.isArray(headers)) {
      var skipH = { "cookie": 1, "host": 1, "connection": 1, "content-length": 1,
                    "accept-encoding": 1, "sec-fetch-site": 1, "sec-fetch-mode": 1,
                    "sec-fetch-dest": 1, "sec-ch-ua": 1, "sec-ch-ua-mobile": 1,
                    "sec-ch-ua-platform": 1, "sec-ch-prefers-color-scheme": 1 };
      var hParts = [];
      var hKeys = Object.keys(headers);
      for (var hi = 0; hi < hKeys.length; hi++) {
        if (!skipH[hKeys[hi].toLowerCase()]) {
          hParts.push(hKeys[hi] + ": " + headers[hKeys[hi]]);
        }
      }
      headers = hParts.join("\n");
    }

    repeaterRoot.innerHTML =
      '<div class="boxedin-rpt__header">' +
        '<span class="boxedin-rpt__title">Request Repeater</span>' +
        '<button type="button" class="boxedin-rpt__close" title="Close">\u2715</button>' +
      '</div>' +
      '<div class="boxedin-rpt__body">' +
        '<div class="boxedin-rpt__row boxedin-rpt__row--method-url">' +
          '<select class="boxedin-rpt__method">' +
            '<option' + (method === "GET" ? " selected" : "") + '>GET</option>' +
            '<option' + (method === "POST" ? " selected" : "") + '>POST</option>' +
            '<option' + (method === "PUT" ? " selected" : "") + '>PUT</option>' +
            '<option' + (method === "PATCH" ? " selected" : "") + '>PATCH</option>' +
            '<option' + (method === "DELETE" ? " selected" : "") + '>DELETE</option>' +
            '<option' + (method === "HEAD" ? " selected" : "") + '>HEAD</option>' +
            '<option' + (method === "OPTIONS" ? " selected" : "") + '>OPTIONS</option>' +
          '</select>' +
          '<input type="text" class="boxedin-rpt__url" placeholder="https://example.com/api/..." value="' + escapeAttr(url) + '" />' +
        '</div>' +
        '<label class="boxedin-rpt__label">Headers <span class="boxedin-rpt__label-hint">(one per line: Name: Value)</span></label>' +
        '<textarea class="boxedin-rpt__headers" rows="4" spellcheck="false">' + escapeHtml(headers) + '</textarea>' +
        '<label class="boxedin-rpt__label">Body</label>' +
        '<textarea class="boxedin-rpt__bodyinput" rows="3" spellcheck="false">' + escapeHtml(body) + '</textarea>' +
        '<div class="boxedin-rpt__actions">' +
          '<button type="button" class="boxedin-rpt__send">Send</button>' +
          '<span class="boxedin-rpt__status"></span>' +
        '</div>' +
        '<div class="boxedin-rpt__response">' +
          '<div class="boxedin-rpt__resp-head"></div>' +
          '<pre class="boxedin-rpt__resp-body"></pre>' +
        '</div>' +
      '</div>';

    wireRepeater();
  }

  /**
   * Bind repeater close and send buttons. Send parses the header textarea,
   * dispatches BOXEDIN_REPLAY_REQUEST, and renders the response inline.
   */
  function wireRepeater() {
    if (!repeaterRoot) return;

    var closeBtn = repeaterRoot.querySelector(".boxedin-rpt__close");
    if (closeBtn) closeBtn.addEventListener("click", closeRepeater);

    var sendBtn = repeaterRoot.querySelector(".boxedin-rpt__send");
    if (sendBtn) {
      sendBtn.addEventListener("click", function () {
        var methodEl = repeaterRoot.querySelector(".boxedin-rpt__method");
        var urlEl = repeaterRoot.querySelector(".boxedin-rpt__url");
        var headersEl = repeaterRoot.querySelector(".boxedin-rpt__headers");
        var bodyEl = repeaterRoot.querySelector(".boxedin-rpt__bodyinput");
        var statusEl = repeaterRoot.querySelector(".boxedin-rpt__status");
        var respHead = repeaterRoot.querySelector(".boxedin-rpt__resp-head");
        var respBody = repeaterRoot.querySelector(".boxedin-rpt__resp-body");

        var reqUrl = urlEl ? urlEl.value.trim() : "";
        var reqMethod = methodEl ? methodEl.value : "GET";
        if (!reqUrl) {
          if (statusEl) statusEl.textContent = "URL is required";
          return;
        }

        var parsedHeaders = {};
        if (headersEl) {
          var lines = headersEl.value.split("\n");
          for (var li = 0; li < lines.length; li++) {
            var line = lines[li].trim();
            if (!line) continue;
            var colon = line.indexOf(":");
            if (colon > 0) {
              parsedHeaders[line.substring(0, colon).trim()] = line.substring(colon + 1).trim();
            }
          }
        }

        var reqBody = bodyEl ? bodyEl.value : "";

        if (sendBtn) sendBtn.disabled = true;
        if (statusEl) statusEl.textContent = "Sending\u2026";
        if (respHead) respHead.innerHTML = "";
        if (respBody) respBody.textContent = "";

        try {
          chrome.runtime.sendMessage({
            type: "BOXEDIN_REPLAY_REQUEST",
            url: reqUrl,
            method: reqMethod,
            headers: parsedHeaders,
            body: reqBody
          }, function (response) {
            if (sendBtn) sendBtn.disabled = false;
            if (chrome.runtime.lastError) {
              if (statusEl) statusEl.textContent = "Error: " + chrome.runtime.lastError.message;
              return;
            }
            if (!response) {
              if (statusEl) statusEl.textContent = "No response";
              return;
            }
            if (!response.ok && response.error) {
              if (statusEl) statusEl.textContent = "Error";
              if (respHead) respHead.innerHTML = '<span class="boxedin-rpt__resp-error">' + escapeHtml(response.error) + '</span>';
              if (respBody) respBody.textContent = "";
              return;
            }

            var badgeClass = response.status < 300 ? "boxedin-rpt__resp-status--ok" :
                             response.status < 400 ? "boxedin-rpt__resp-status--redirect" :
                             "boxedin-rpt__resp-status--error";
            if (statusEl) statusEl.textContent = response.elapsedMs + " ms";

            var headParts = [];
            headParts.push('<span class="boxedin-rpt__resp-status ' + badgeClass + '">' +
              response.status + ' ' + escapeHtml(response.statusText || "") + '</span>');
            if (response.headers) {
              headParts.push('<details class="boxedin-rpt__resp-headers-details"><summary>Response headers</summary><pre class="boxedin-rpt__resp-headers-pre">');
              var rKeys = Object.keys(response.headers);
              for (var rk = 0; rk < rKeys.length; rk++) {
                headParts.push(escapeHtml(rKeys[rk]) + ": " + escapeHtml(response.headers[rKeys[rk]]) + "\n");
              }
              headParts.push('</pre></details>');
            }
            if (respHead) respHead.innerHTML = headParts.join("");
            if (respBody) respBody.textContent = response.body || "";
          });
        } catch (e) {
          if (sendBtn) sendBtn.disabled = false;
          if (statusEl) statusEl.textContent = "Error: " + (e.message || e);
        }
      });
    }
  }

  /* ── Mount ─────────────────────────────────────────────────────────── */

  /**
   * Create the overlay and repeater root elements, wire storage listeners
   * for live preference updates, restore persisted state, and start polling.
   */
  function mount() {
    if (document.getElementById("boxedin-block-stats-root")) return;
    root = document.createElement("div");
    root.id = "boxedin-block-stats-root";
    root.setAttribute("role", "complementary");
    root.setAttribute("aria-label", "BoxedIn network block statistics");
    (document.body || document.documentElement).appendChild(root);

    repeaterRoot = document.createElement("div");
    repeaterRoot.id = "boxedin-repeater-root";
    repeaterRoot.setAttribute("role", "dialog");
    repeaterRoot.setAttribute("aria-label", "BoxedIn request repeater");
    repeaterRoot.style.display = "none";
    (document.body || document.documentElement).appendChild(repeaterRoot);

    chrome.storage.onChanged.addListener(function (changes, areaName) {
      if (areaName !== "local") return;
      if (changes.extensionEnabled) {
        if (changes.extensionEnabled.newValue === false) {
          root.style.display = "none";
        } else {
          renderActivePanel();
        }
      }
      if (changes.pageGuardBlockStats || changes.blockStatsByRuleId ||
          changes.captureRequestHostsEnabled || changes.blockedHosts) {
        if (activeTab === "blocks") fetchStats();
      }
      if (changes[STORAGE_REDTEAM_ENABLED]) {
        redteamEnabled = !!changes[STORAGE_REDTEAM_ENABLED].newValue;
        if (redteamEnabled) {
          enablePageGuardRedteam();
        } else {
          activeTab = "blocks";
        }
        renderActivePanel();
      }
      if (changes[STORAGE_EXFIL_ALLOWLIST]) {
        exfilAllowlist = changes[STORAGE_EXFIL_ALLOWLIST].newValue || [];
      }
    });

    var storageKeys = {};
    storageKeys[STORAGE_VIEW_STATE] = "normal";
    storageKeys[STORAGE_ACTIVE_TAB] = "blocks";
    storageKeys[STORAGE_REDTEAM_ENABLED] = false;
    storageKeys[STORAGE_EXFIL_ALLOWLIST] = [];
    chrome.storage.local.get(storageKeys, function (items) {
      var saved = items[STORAGE_VIEW_STATE];
      if (saved === "collapsed" || saved === "maximized") viewState = saved;

      redteamEnabled = !!items[STORAGE_REDTEAM_ENABLED];
      exfilAllowlist = items[STORAGE_EXFIL_ALLOWLIST] || [];

      if (redteamEnabled) {
        var savedTab = items[STORAGE_ACTIVE_TAB];
        if (savedTab === "auth" || savedTab === "exfil" || savedTab === "inject" || savedTab === "recon" || savedTab === "apis" || savedTab === "deps" || savedTab === "timeline" || savedTab === "osint") {
          activeTab = savedTab;
        }
        enablePageGuardRedteam();
      }

      applyViewState();
      renderActivePanel();
    });

    window.setInterval(function () { renderActivePanel(); }, POLL_MS);
  }

  if (document.body) {
    mount();
  } else {
    document.addEventListener("DOMContentLoaded", mount);
  }
})();
