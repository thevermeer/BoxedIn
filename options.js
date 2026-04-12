/**
 * Options page: user DNR urlFilters, apply status, hostname-capture toggle.
 * Validation mirrors Chrome urlFilter limits; background applies rules.
 */
(function () {
  "use strict";

  var KEY_USER_DNR = "userDnrUrlFilters";
  var MAX_USER_DNR = 50;
  var KEY_LAST_ERROR = "userDnrLastApplyError";
  var KEY_LAST_AT = "userDnrLastApplyAt";
  var KEY_CAPTURE_HOSTS = "captureRequestHostsEnabled";
  var KEY_BLOCKED_HOSTS = "blockedHosts";
  var KEY_REDTEAM_ENABLED = "redteamEnabled";
  var KEY_EXFIL_ALLOWLIST = "redteamExfilAllowlist";
  /** Chrome urlFilter practical upper bound; rules that exceed fail to apply. */
  var MAX_URL_FILTER_LEN = 4096;

  var dnrListEl;
  var newDnrFilterEl;
  var dnrApplyStatusEl;
  var dnrValidationHintEl;
  var blockedHostsListEl;
  var blockedHostsActionsEl;

  function normalizeUserDnrFilters(arr) {
    if (!Array.isArray(arr)) return [];
    var out = [];
    var seen = {};
    var i = 0;
    for (; i < arr.length && out.length < MAX_USER_DNR; i++) {
      var s = String(arr[i] == null ? "" : arr[i]).trim();
      if (!s) continue;
      if (seen[s]) continue;
      seen[s] = true;
      out.push(s);
    }
    return out;
  }

  /**
   * Client-side checks before storage; Chrome may still reject malformed patterns.
   */
  function validateUrlFilter(raw) {
    var t = String(raw == null ? "" : raw).trim();
    if (!t) {
      return { ok: false, message: "Pattern cannot be empty." };
    }
    if (t.length > MAX_URL_FILTER_LEN) {
      return {
        ok: false,
        message:
          "Pattern is too long (max " + MAX_URL_FILTER_LEN + " characters).",
      };
    }
    if (/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(t)) {
      return {
        ok: false,
        message: "Pattern contains invalid control characters.",
      };
    }
    if (/\n|\r/.test(t)) {
      return { ok: false, message: "Pattern cannot contain line breaks." };
    }
    if (/^\*+$/.test(t)) {
      return {
        ok: false,
        message: "Pattern cannot be only asterisks (too broad / invalid).",
      };
    }
    return { ok: true, value: t };
  }

  function setValidationHint(text) {
    if (!dnrValidationHintEl) return;
    dnrValidationHintEl.textContent = text || "";
    dnrValidationHintEl.style.display = text ? "block" : "none";
  }

  function renderApplyStatus(lastError, lastAt) {
    if (!dnrApplyStatusEl) return;
    var err = lastError == null ? "" : String(lastError);
    var at = typeof lastAt === "number" && !isNaN(lastAt) ? lastAt : null;
    var timeStr =
      at != null
        ? " — " + new Date(at).toLocaleString(undefined, { hour12: true })
        : "";
    if (err) {
      dnrApplyStatusEl.textContent =
        "Last apply failed" + timeStr + ": " + err;
      dnrApplyStatusEl.className = "dnr-apply-status dnr-apply-status--error";
    } else if (at != null) {
      dnrApplyStatusEl.textContent =
        "Last apply to Chrome succeeded" + timeStr + ".";
      dnrApplyStatusEl.className = "dnr-apply-status dnr-apply-status--ok";
    } else {
      dnrApplyStatusEl.textContent =
        "Apply status will appear here after custom rules are saved.";
      dnrApplyStatusEl.className = "dnr-apply-status";
    }
  }

  function saveUserDnrFilters(filters) {
    var patch = {};
    patch[KEY_USER_DNR] = normalizeUserDnrFilters(filters);
    chrome.storage.local.set(patch);
  }

  function renderUserDnr(filters) {
    if (!dnrListEl) return;
    dnrListEl.innerHTML = "";
    var list = normalizeUserDnrFilters(filters);
    var i = 0;
    for (; i < list.length; i++) {
      (function (index) {
        var li = document.createElement("li");
        var input = document.createElement("input");
        input.type = "text";
        input.className = "phrase-input";
        input.value = list[index];
        input.setAttribute("spellcheck", "false");
        input.addEventListener("change", function () {
          var v = validateUrlFilter(input.value);
          if (!v.ok) {
            setValidationHint(v.message);
            input.value = list[index];
            return;
          }
          setValidationHint("");
          var next = normalizeUserDnrFilters(list.slice());
          next[index] = v.value;
          saveUserDnrFilters(next);
          renderUserDnr(next);
        });
        var rm = document.createElement("button");
        rm.type = "button";
        rm.className = "btn btn-remove";
        rm.textContent = "Remove";
        rm.addEventListener("click", function () {
          setValidationHint("");
          var next = normalizeUserDnrFilters(list.slice());
          next.splice(index, 1);
          saveUserDnrFilters(next);
          renderUserDnr(next);
        });
        li.appendChild(input);
        li.appendChild(rm);
        dnrListEl.appendChild(li);
      })(i);
    }
    if (list.length === 0) {
      var empty = document.createElement("p");
      empty.className = "empty-hint";
      empty.textContent =
        "No custom rules—add a urlFilter pattern above (max " +
        MAX_USER_DNR +
        ").";
      dnrListEl.appendChild(empty);
    }
  }

  function renderExfilAllowlist(hosts) {
    var el = document.getElementById("exfilAllowlist");
    if (!el) return;
    el.innerHTML = "";
    var list = Array.isArray(hosts) ? hosts : [];
    if (list.length === 0) {
      var empty = document.createElement("p");
      empty.className = "empty-hint";
      empty.textContent = "No allowlisted hosts. The page origin is always allowed.";
      el.appendChild(empty);
      return;
    }
    for (var i = 0; i < list.length; i++) {
      (function (index) {
        var li = document.createElement("li");
        var code = document.createElement("code");
        code.className = "blocked-host-name";
        code.textContent = list[index];
        var rm = document.createElement("button");
        rm.type = "button";
        rm.className = "btn btn-remove";
        rm.textContent = "Remove";
        rm.addEventListener("click", function () {
          var next = list.slice();
          next.splice(index, 1);
          var patch = {};
          patch[KEY_EXFIL_ALLOWLIST] = next;
          chrome.storage.local.set(patch);
        });
        li.appendChild(code);
        li.appendChild(rm);
        el.appendChild(li);
      })(i);
    }
  }

  function renderBlockedHosts(hosts) {
    if (!blockedHostsListEl) return;
    blockedHostsListEl.innerHTML = "";
    var list = Array.isArray(hosts) ? hosts : [];
    if (blockedHostsActionsEl) {
      blockedHostsActionsEl.style.display = list.length > 0 ? "" : "none";
    }
    if (list.length === 0) {
      var empty = document.createElement("p");
      empty.className = "empty-hint";
      empty.textContent = "No hostnames blocked from the overlay yet.";
      blockedHostsListEl.appendChild(empty);
      return;
    }
    var i = 0;
    for (; i < list.length; i++) {
      (function (index) {
        var li = document.createElement("li");
        var code = document.createElement("code");
        code.className = "blocked-host-name";
        code.textContent = list[index];
        var rm = document.createElement("button");
        rm.type = "button";
        rm.className = "btn btn-remove";
        rm.textContent = "Remove";
        rm.addEventListener("click", function () {
          var next = list.slice();
          next.splice(index, 1);
          var patch = {};
          patch[KEY_BLOCKED_HOSTS] = next;
          chrome.storage.local.set(patch);
        });
        li.appendChild(code);
        li.appendChild(rm);
        blockedHostsListEl.appendChild(li);
      })(i);
    }
  }

  function load() {
    chrome.storage.local.get(
      [KEY_USER_DNR, KEY_LAST_ERROR, KEY_LAST_AT, KEY_CAPTURE_HOSTS, KEY_BLOCKED_HOSTS, KEY_REDTEAM_ENABLED, KEY_EXFIL_ALLOWLIST],
      function (localItems) {
        renderUserDnr((localItems && localItems[KEY_USER_DNR]) || []);
        renderApplyStatus(
          localItems && localItems[KEY_LAST_ERROR],
          localItems && localItems[KEY_LAST_AT]
        );
        renderBlockedHosts((localItems && localItems[KEY_BLOCKED_HOSTS]) || []);
        var capEl = document.getElementById("captureRequestHostsEnabled");
        if (capEl) {
          capEl.checked = !!localItems[KEY_CAPTURE_HOSTS];
        }
        var rtEl = document.getElementById("redteamEnabled");
        if (rtEl) {
          rtEl.checked = !!localItems[KEY_REDTEAM_ENABLED];
        }
        renderExfilAllowlist((localItems && localItems[KEY_EXFIL_ALLOWLIST]) || []);
      }
    );
  }

  function addDnrFromInput() {
    if (!newDnrFilterEl) return;
    var raw = newDnrFilterEl.value;
    var v = validateUrlFilter(raw);
    if (!v.ok) {
      setValidationHint(v.message);
      return;
    }
    setValidationHint("");
    chrome.storage.local.get(
      (function () {
        var d = {};
        d[KEY_USER_DNR] = [];
        return d;
      })(),
      function (items) {
        var next = normalizeUserDnrFilters(
          (items[KEY_USER_DNR] || []).concat([v.value])
        );
        newDnrFilterEl.value = "";
        saveUserDnrFilters(next);
        renderUserDnr(next);
      }
    );
  }

  function init() {
    dnrListEl = document.getElementById("dnrList");
    newDnrFilterEl = document.getElementById("newDnrFilter");
    dnrApplyStatusEl = document.getElementById("dnrApplyStatus");
    dnrValidationHintEl = document.getElementById("dnrValidationHint");
    blockedHostsListEl = document.getElementById("blockedHostsList");
    blockedHostsActionsEl = document.getElementById("blockedHostsActions");
    var addDnrBtn = document.getElementById("addDnrFilter");
    var captureHostsEl = document.getElementById("captureRequestHostsEnabled");
    var clearBlockedBtn = document.getElementById("clearBlockedHosts");
    var redteamEl = document.getElementById("redteamEnabled");
    var exfilAllowlistEl = document.getElementById("exfilAllowlist");
    var newExfilHostEl = document.getElementById("newExfilHost");
    var addExfilHostBtn = document.getElementById("addExfilHost");
    var exportFindingsBtn = document.getElementById("exportFindings");

    if (!dnrListEl) return;

    load();

    if (clearBlockedBtn) {
      clearBlockedBtn.addEventListener("click", function () {
        var patch = {};
        patch[KEY_BLOCKED_HOSTS] = [];
        chrome.storage.local.set(patch);
      });
    }

    if (captureHostsEl) {
      captureHostsEl.addEventListener("change", function () {
        var patch = {};
        patch[KEY_CAPTURE_HOSTS] = !!captureHostsEl.checked;
        chrome.storage.local.set(patch);
      });
    }

    if (addDnrBtn && newDnrFilterEl) {
      addDnrBtn.addEventListener("click", addDnrFromInput);
      newDnrFilterEl.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          e.preventDefault();
          addDnrFromInput();
        }
      });
      newDnrFilterEl.addEventListener("input", function () {
        if (dnrValidationHintEl && dnrValidationHintEl.textContent) {
          setValidationHint("");
        }
      });
    }

    if (redteamEl) {
      redteamEl.addEventListener("change", function () {
        var patch = {};
        patch[KEY_REDTEAM_ENABLED] = !!redteamEl.checked;
        chrome.storage.local.set(patch);
      });
    }

    if (addExfilHostBtn && newExfilHostEl) {
      function addExfilFromInput() {
        var val = (newExfilHostEl.value || "").trim().toLowerCase();
        if (!val) return;
        chrome.storage.local.get([KEY_EXFIL_ALLOWLIST], function (items) {
          var list = (items[KEY_EXFIL_ALLOWLIST] || []).slice();
          if (list.indexOf(val) === -1) list.push(val);
          newExfilHostEl.value = "";
          var patch = {};
          patch[KEY_EXFIL_ALLOWLIST] = list;
          chrome.storage.local.set(patch);
          renderExfilAllowlist(list);
        });
      }
      addExfilHostBtn.addEventListener("click", addExfilFromInput);
      newExfilHostEl.addEventListener("keydown", function (e) {
        if (e.key === "Enter") { e.preventDefault(); addExfilFromInput(); }
      });
    }

    if (exportFindingsBtn) {
      exportFindingsBtn.addEventListener("click", function () {
        chrome.storage.local.get(null, function (all) {
          var blob = new Blob([JSON.stringify(all, null, 2)], { type: "application/json" });
          var url = URL.createObjectURL(blob);
          var a = document.createElement("a");
          a.href = url;
          a.download = "boxedin-findings-" + new Date().toISOString().slice(0, 10) + ".json";
          a.click();
          URL.revokeObjectURL(url);
        });
      });
    }

    chrome.storage.onChanged.addListener(function (changes, areaName) {
      if (areaName !== "local") return;
      if (changes[KEY_USER_DNR]) {
        renderUserDnr(changes[KEY_USER_DNR].newValue || []);
      }
      if (changes[KEY_LAST_ERROR] || changes[KEY_LAST_AT]) {
        chrome.storage.local.get([KEY_LAST_ERROR, KEY_LAST_AT], function (i) {
          renderApplyStatus(i && i[KEY_LAST_ERROR], i && i[KEY_LAST_AT]);
        });
      }
      if (changes[KEY_BLOCKED_HOSTS]) {
        renderBlockedHosts(changes[KEY_BLOCKED_HOSTS].newValue || []);
      }
      if (changes[KEY_CAPTURE_HOSTS]) {
        var capEl = document.getElementById("captureRequestHostsEnabled");
        if (capEl) {
          capEl.checked = !!changes[KEY_CAPTURE_HOSTS].newValue;
        }
      }
      if (changes[KEY_REDTEAM_ENABLED]) {
        var rtEl = document.getElementById("redteamEnabled");
        if (rtEl) rtEl.checked = !!changes[KEY_REDTEAM_ENABLED].newValue;
      }
      if (changes[KEY_EXFIL_ALLOWLIST]) {
        renderExfilAllowlist(changes[KEY_EXFIL_ALLOWLIST].newValue || []);
      }
    });
  }

  document.addEventListener("DOMContentLoaded", init);
})();
