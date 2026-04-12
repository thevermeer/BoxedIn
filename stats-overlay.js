/**
 * Overlay (isolated world): DNR + page-guard block stats, hostname list with
 * per-host blocking checkboxes, reset/copy. Listens for page-guard postMessage
 * (same tab, inc. iframes). Injected on all sites.
 */
(function () {
  "use strict";

  var POLL_MS = 4000;
  var STORAGE_VIEW_STATE = "overlayViewState";
  var root;
  var viewState = "normal";
  var pendingPg = { linkedInBlocklist: 0, extensionScheme: 0 };
  var pgFlushTimer = null;

  /** Flush coalesced page-guard deltas to storage (debounced 200ms). */
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
        if (chrome.runtime.lastError) {
          /* ignore */
        }
      });
    } catch (e) {
      /* ignore */
    }
  }

  /**
   * Page-guard runs in MAIN (all frames) and posts to window.top. Relying on
   * ev.source === window breaks when Window references differ across frames.
   * Same page origin + our payload shape is enough for this overlay.
   */
  function onPageGuardMessage(ev) {
    try {
      if (ev.origin !== window.location.origin) return;
    } catch (e) {
      return;
    }
    var data = ev.data;
    if (
      !data ||
      data.source !== "boxedin-page-guard" ||
      data.type !== "stat"
    ) {
      return;
    }
    if (data.key === "linkedInBlocklist") {
      var d1 =
        typeof data.delta === "number" && data.delta > 0 ? data.delta : 1;
      pendingPg.linkedInBlocklist += d1;
    } else if (data.key === "extensionScheme") {
      var d2 =
        typeof data.delta === "number" && data.delta > 0 ? data.delta : 1;
      pendingPg.extensionScheme += d2;
    } else {
      return;
    }
    if (pgFlushTimer !== null) {
      clearTimeout(pgFlushTimer);
    }
    pgFlushTimer = setTimeout(flushPendingPageGuard, 200);
  }

  window.addEventListener("message", onPageGuardMessage);

  function isDarkUi() {
    try {
      if (document.documentElement) {
        if (document.documentElement.classList.contains("theme--dark")) {
          return true;
        }
        if (document.documentElement.getAttribute("data-theme") === "dark") {
          return true;
        }
      }
      if (
        window.matchMedia &&
        window.matchMedia("(prefers-color-scheme: dark)").matches
      ) {
        return true;
      }
    } catch (e) {
      /* ignore */
    }
    return false;
  }

  function saveViewState(state) {
    viewState = state;
    try {
      var patch = {};
      patch[STORAGE_VIEW_STATE] = state;
      chrome.storage.local.set(patch);
    } catch (e) {
      /* ignore */
    }
  }

  function applyViewState() {
    root.classList.remove("boxedin-stats--collapsed", "boxedin-stats--maximized");
    if (viewState === "collapsed") {
      root.classList.add("boxedin-stats--collapsed");
    } else if (viewState === "maximized") {
      root.classList.add("boxedin-stats--maximized");
    }
  }

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

  function copyTextToClipboard(text, onDone) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(onDone).catch(function () {
        fallbackCopyText(text, onDone);
      });
      return;
    }
    fallbackCopyText(text, onDone);
  }

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
    } catch (e) {
      /* ignore */
    }
  }

  function wireHostsCopy(hosts) {
    var btn = root.querySelector(".boxedin-stats__hosts-copy");
    if (!btn || !hosts || hosts.length === 0) return;
    btn.addEventListener("click", function () {
      var text = hosts.join("\n");
      var label = btn.getAttribute("data-label-copy") || "Copy all";
      var labelDone = btn.getAttribute("data-label-copied") || "Copied";
      copyTextToClipboard(text, function () {
        btn.textContent = labelDone;
        window.setTimeout(function () {
          btn.textContent = label;
        }, 1600);
      });
    });
  }

  function toggleHostBlock(host, block) {
    try {
      chrome.runtime.sendMessage(
        { type: "BOXEDIN_TOGGLE_HOST_BLOCK", host: host, block: block },
        function () {
          if (chrome.runtime.lastError) {
            return;
          }
          fetchStats();
        }
      );
    } catch (e) {
      /* ignore */
    }
  }

  function enableCaptureHosts() {
    try {
      chrome.runtime.sendMessage(
        { type: "BOXEDIN_SET_CAPTURE_HOSTS", enabled: true },
        function () {
          if (chrome.runtime.lastError) {
            return;
          }
          fetchStats();
        }
      );
    } catch (e) {
      /* ignore */
    }
  }

  function wireHostsReset() {
    var btn = root.querySelector(".boxedin-stats__hosts-reset");
    if (!btn) return;
    btn.addEventListener("click", function () {
      try {
        chrome.runtime.sendMessage(
          { type: "BOXEDIN_RESET_OBSERVED_HOSTS" },
          function () {
            if (chrome.runtime.lastError) {
              return;
            }
            fetchStats();
          }
        );
      } catch (e) {
        /* ignore */
      }
    });
  }

  function wireResetStats() {
    var btn = root.querySelector(".boxedin-stats__reset-stats");
    if (!btn) return;
    btn.addEventListener("click", function () {
      if (pgFlushTimer !== null) {
        clearTimeout(pgFlushTimer);
        pgFlushTimer = null;
      }
      pendingPg.linkedInBlocklist = 0;
      pendingPg.extensionScheme = 0;
      try {
        chrome.runtime.sendMessage(
          { type: "BOXEDIN_RESET_BLOCK_STATS" },
          function () {
            if (chrome.runtime.lastError) {
              return;
            }
            fetchStats();
          }
        );
      } catch (e) {
        /* ignore */
      }
    });
  }

  function wireHostCheckboxes() {
    var checks = root.querySelectorAll(".boxedin-stats__host-check");
    var c = 0;
    for (; c < checks.length; c++) {
      (function (cb) {
        cb.addEventListener("change", function () {
          toggleHostBlock(cb.getAttribute("data-host"), cb.checked);
        });
      })(checks[c]);
    }
  }

  function wireEnableCapture() {
    var btn = root.querySelector(".boxedin-stats__enable-capture");
    if (!btn) return;
    btn.addEventListener("click", function () {
      enableCaptureHosts();
    });
  }

  function partitionBlockRows(rows) {
    var network = [];
    var sniff = [];
    var i = 0;
    for (; i < rows.length; i++) {
      var r = rows[i];
      if (r && r.kind === "extensionSniff") {
        sniff.push(r);
      } else {
        network.push(r);
      }
    }
    return { network: network, sniff: sniff };
  }

  function sumRowCounts(arr) {
    var s = 0;
    var j = 0;
    for (; j < arr.length; j++) {
      var c = arr[j] && arr[j].count;
      if (typeof c === "number" && c > 0) s += c;
    }
    return s;
  }

  function appendBlockRowParts(parts, r) {
    parts.push(
      '<div class="boxedin-stats__row"><span class="boxedin-stats__label" title="' +
        escapeAttr(r.detail || "") +
        '">' +
        escapeHtml(r.label) +
        '</span><span class="boxedin-stats__count">' +
        r.count +
        "</span></div>"
    );
  }

  function render(payload) {
    if (!root) return;
    if (payload && payload.extensionDisabled) {
      root.style.display = "none";
      return;
    }
    root.style.display = "";
    var collapsed = viewState === "collapsed";
    var maximized = viewState === "maximized";
    var prevBodyScroll = 0;
    var prevHostsScroll = 0;
    var bodyEl = root.querySelector(".boxedin-stats__body");
    var hostsEl = root.querySelector(".boxedin-stats__hosts-list");
    if (bodyEl) prevBodyScroll = bodyEl.scrollTop;
    if (hostsEl) prevHostsScroll = hostsEl.scrollTop;

    root.className = "";
    if (isDarkUi()) root.classList.add("boxedin-stats--dark");
    applyViewState();

    if (payload && payload.unavailable) {
      root.innerHTML =
        '<div class="boxedin-stats__header"><span>BoxedIn blocks</span></div>' +
        '<div class="boxedin-stats__body"><p class="boxedin-stats__hint">' +
        escapeHtml(
          payload.reason ||
            "Block stats need declarativeNetRequestFeedback in a recent Chrome."
        ) +
        "</p></div>";
      return;
    }

    var rows = (payload && payload.rows) || [];
    var total = (payload && payload.total) || 0;
    collapsed = root.classList.contains("boxedin-stats--collapsed");

    var parts = [];
    if (rows.length === 0) {
      parts.push(
        '<p class="boxedin-stats__empty">No requests blocked yet on this profile.</p>'
      );
    } else {
      parts.push(
        '<div class="boxedin-stats__total">Total blocked: <strong>' +
          total +
          "</strong></div>"
      );
      var split = partitionBlockRows(rows);
      var netRows = split.network;
      var sniffRows = split.sniff;
      parts.push(
        '<div class="boxedin-stats__section">' +
          '<div class="boxedin-stats__section-head">' +
          '<span class="boxedin-stats__section-title">Network &amp; API traffic</span>' +
          '<span class="boxedin-stats__section-sub">' +
          sumRowCounts(netRows) +
          "</span>" +
          "</div>"
      );
      if (netRows.length > 0) {
        var i = 0;
        for (; i < netRows.length; i++) {
          appendBlockRowParts(parts, netRows[i]);
        }
      } else {
        parts.push(
          '<p class="boxedin-stats__section-empty">None in this category yet.</p>'
        );
      }
      parts.push("</div>");
      parts.push(
        '<div class="boxedin-stats__section">' +
          '<div class="boxedin-stats__section-head">' +
          '<span class="boxedin-stats__section-title">Extension sniffing</span>' +
          '<span class="boxedin-stats__section-sub">' +
          sumRowCounts(sniffRows) +
          "</span>" +
          "</div>"
      );
      if (sniffRows.length > 0) {
        var s = 0;
        for (; s < sniffRows.length; s++) {
          appendBlockRowParts(parts, sniffRows[s]);
        }
      } else {
        parts.push(
          '<p class="boxedin-stats__section-empty">' +
            "None yet \u2014 counts DNR rule 2 (chrome-extension://\u2026) and page-guard JS blocks of extension URLs." +
            "</p>"
        );
      }
      parts.push("</div>");
    }
    var hosts = (payload && payload.observedHosts) || [];
    var blockedHosts = (payload && payload.blockedHosts) || [];
    var blockedSet = {};
    var bh = 0;
    for (; bh < blockedHosts.length; bh++) {
      blockedSet[blockedHosts[bh]] = true;
    }
    var capOn = payload && payload.captureHostsEnabled;
    if (capOn) {
      parts.push(
        '<div class="boxedin-stats__hosts"><div class="boxedin-stats__hosts-head">' +
          '<span class="boxedin-stats__hosts-title">Hostnames (this tab)</span>' +
          '<div class="boxedin-stats__hosts-actions">'
      );
      if (hosts.length > 0) {
        parts.push(
          '<button type="button" class="boxedin-stats__hosts-copy boxedin-stats__hosts-btn" title="Copy all hostnames (one per line)" data-label-copy="Copy all" data-label-copied="Copied">Copy all</button>'
        );
      }
      parts.push(
        '<button type="button" class="boxedin-stats__hosts-reset boxedin-stats__hosts-btn" title="Clear the hostname list for this tab">Reset list</button>' +
          "</div></div>"
      );
      if (hosts.length > 0) {
        parts.push(
          '<p class="boxedin-stats__hosts-hint">Check a hostname to block all sub-resource requests to it.</p>'
        );
        parts.push('<ul class="boxedin-stats__hosts-list">');
        var h = 0;
        for (; h < hosts.length; h++) {
          var isBlocked = !!blockedSet[hosts[h]];
          parts.push(
            '<li class="boxedin-stats__host-item' +
              (isBlocked ? " boxedin-stats__host-item--blocked" : "") +
              '">' +
              '<label class="boxedin-stats__host-label">' +
              '<input type="checkbox" class="boxedin-stats__host-check" data-host="' +
              escapeAttr(hosts[h]) +
              '"' +
              (isBlocked ? " checked" : "") +
              " />" +
              "<code>" +
              escapeHtml(hosts[h]) +
              "</code></label></li>"
          );
        }
        parts.push("</ul>");
      } else {
        parts.push(
          '<p class="boxedin-stats__hosts-empty">Host capture on \u2014 no hostnames recorded yet in this tab.</p>'
        );
      }
      parts.push("</div>");
    } else {
      parts.push(
        '<div class="boxedin-stats__hosts-off">' +
          '<p class="boxedin-stats__hosts-empty">Hostname capture is off.</p>' +
          '<button type="button" class="boxedin-stats__enable-capture boxedin-stats__hosts-btn">Enable host capture</button>' +
          "</div>"
      );
    }
    var bodyHtml = parts.join("");

    root.innerHTML =
      '<div class="boxedin-stats__header">' +
      '<span class="boxedin-stats__title">BoxedIn blocks</span>' +
      '<div class="boxedin-stats__header-actions">' +
      '<button type="button" class="boxedin-stats__reset-stats" title="Clear cumulative DNR and page-guard block counts (this browser)">Reset stats</button>' +
      '<button type="button" class="boxedin-stats__maximize" title="' +
      (maximized ? "Restore" : "Maximize") +
      '">' +
      (maximized ? "\u25A3" : "\u25A1") +
      "</button>" +
      '<button type="button" class="boxedin-stats__toggle" title="' +
      (collapsed ? "Expand" : "Collapse") +
      '" aria-expanded="' +
      (collapsed ? "false" : "true") +
      '">' +
      (collapsed ? "\u25B2" : "\u25BC") +
      "</button></div></div>" +
      '<div class="boxedin-stats__body">' +
      bodyHtml +
      "</div>";

    wireToggle();
    wireMaximize();
    wireResetStats();
    if (capOn) {
      wireHostsReset();
      wireHostCheckboxes();
      if (hosts.length > 0) {
        wireHostsCopy(hosts);
      }
    } else {
      wireEnableCapture();
    }

    var newBody = root.querySelector(".boxedin-stats__body");
    var newHosts = root.querySelector(".boxedin-stats__hosts-list");
    if (newBody && prevBodyScroll) newBody.scrollTop = prevBodyScroll;
    if (newHosts && prevHostsScroll) newHosts.scrollTop = prevHostsScroll;
  }

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function escapeAttr(s) {
    return escapeHtml(s).replace(/'/g, "&#39;");
  }

  function fetchStats() {
    if (pgFlushTimer !== null) {
      clearTimeout(pgFlushTimer);
      pgFlushTimer = null;
    }
    function doGet() {
      try {
        chrome.runtime.sendMessage(
          { type: "BOXEDIN_GET_BLOCK_STATS" },
          function (response) {
            if (chrome.runtime.lastError) {
              render({
                unavailable: true,
                reason: chrome.runtime.lastError.message,
              });
              return;
            }
            render(response || { rows: [], total: 0 });
          }
        );
      } catch (e) {
        render({ unavailable: true, reason: String(e && e.message) });
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
          if (chrome.runtime.lastError) {
            /* ignore */
          }
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

  function mount() {
    if (document.getElementById("boxedin-block-stats-root")) return;
    root = document.createElement("div");
    root.id = "boxedin-block-stats-root";
    root.setAttribute("role", "complementary");
    root.setAttribute("aria-label", "BoxedIn network block statistics");
    (document.body || document.documentElement).appendChild(root);
    chrome.storage.onChanged.addListener(function (changes, areaName) {
      if (areaName !== "local") return;
      if (
        changes.pageGuardBlockStats ||
        changes.blockStatsByRuleId ||
        changes.captureRequestHostsEnabled ||
        changes.extensionEnabled ||
        changes.blockedHosts
      ) {
        fetchStats();
      }
    });
    chrome.storage.local.get(
      (function () {
        var d = {};
        d[STORAGE_VIEW_STATE] = "normal";
        return d;
      })(),
      function (items) {
        var saved = items[STORAGE_VIEW_STATE];
        if (saved === "collapsed" || saved === "maximized") {
          viewState = saved;
        }
        applyViewState();
        fetchStats();
      }
    );
    window.setInterval(fetchStats, POLL_MS);
  }

  if (document.body) {
    mount();
  } else {
    document.addEventListener("DOMContentLoaded", mount);
  }
})();
