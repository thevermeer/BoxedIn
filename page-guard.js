/**
 * MAIN world, document_start: block extension-URL probes and LinkedIn
 * telemetry (fetch/XHR/beacon, src/href, DOM). Registered dynamically when
 * the extension is enabled (not static content_scripts).
 *
 * /voyager/api/graphql is not blocked. Parser-inserted scripts may run before
 * hooks; API patches are the main defense. Memory: bundles may still load;
 * telemetry requests fail fast. Wrong DNR redirect patterns break the site.
 *
 * Console: set __extensionProbeGuard.verboseExtensionBlocking for URL logs.
 * Stats: extensionSchemeBlocked, linkedInBlocklistBlocked (all APIs),
 * linkedInBlocklistFetchBlocked (fetch-only subset).
 */
(function () {
  "use strict";

  var LOG_PREFIX = "[extension-probe-guard]";

  /**
   * Returns `window.__extensionProbeGuard`, creating it with defaults for
   * `verboseExtensionBlocking` and `stats.extensionSchemeBlocked` when absent.
   */
  function ensureGuard() {
    try {
      var g = window.__extensionProbeGuard;
      if (!g || typeof g !== "object") {
        g = {};
        window.__extensionProbeGuard = g;
      }
      if (typeof g.verboseExtensionBlocking !== "boolean") {
        g.verboseExtensionBlocking = false;
      }
      if (!g.stats || typeof g.stats !== "object") {
        g.stats = {};
      }
      if (typeof g.stats.extensionSchemeBlocked !== "number") {
        g.stats.extensionSchemeBlocked = 0;
      }
      if (typeof g.stats.linkedInBlocklistBlocked !== "number") {
        g.stats.linkedInBlocklistBlocked = 0;
      }
      if (typeof g.stats.linkedInBlocklistFetchBlocked !== "number") {
        g.stats.linkedInBlocklistFetchBlocked = 0;
      }
      return g;
    } catch (_) {
      return {
        verboseExtensionBlocking: false,
        stats: {
          extensionSchemeBlocked: 0,
          linkedInBlocklistBlocked: 0,
          linkedInBlocklistFetchBlocked: 0,
        },
      };
    }
  }

  ensureGuard();

  /**
   * Notifies the isolated-world overlay (injected in the top frame). Page-guard
   * runs in all frames; subframes must post to window.top or the top listener
   * never sees the event.
   */
  function postStatToOverlay(msg) {
    try {
      var target = window;
      try {
        if (window.top) {
          target = window.top;
        }
      } catch (eTop) {
        /* cross-origin top reference — use window */
      }
      if (typeof target.postMessage === "function") {
        target.postMessage(msg, "*");
      }
    } catch (e1) {
      try {
        if (typeof window.postMessage === "function") {
          window.postMessage(msg, "*");
        }
      } catch (e2) {
        /* ignore */
      }
    }
  }

  /**
   * Increments LinkedIn blocklist stats and notifies the extension overlay
   * (isolated world) via postMessage.
   */
  function bumpLinkedInBlocklistStat() {
    var g = ensureGuard();
    g.stats.linkedInBlocklistBlocked += 1;
    try {
      postStatToOverlay({
        source: "boxedin-page-guard",
        type: "stat",
        key: "linkedInBlocklist",
        delta: 1,
      });
    } catch (e1) {
      /* ignore */
    }
  }

  /**
   * Increments only the fetch()-path LinkedIn blocklist counter (independent of
   * XHR/beacon); also included in linkedInBlocklistBlocked.
   */
  function bumpLinkedInBlocklistFetchStat() {
    var g = ensureGuard();
    g.stats.linkedInBlocklistFetchBlocked += 1;
  }

  /**
   * Increments extension-scheme block stats; logs only when
   * `verboseExtensionBlocking` is true (avoids console spam when pages probe
   * many chrome-extension:// URLs).
   */
  function logExtensionSchemeBlock(action, detail) {
    var g = ensureGuard();
    g.stats.extensionSchemeBlocked += 1;
    try {
      postStatToOverlay({
        source: "boxedin-page-guard",
        type: "stat",
        key: "extensionScheme",
        delta: 1,
      });
    } catch (ePg) {
      /* ignore */
    }
    if (g.verboseExtensionBlocking) {
      log(action, detail);
    }
  }

  /**
   * Emits one `console.info` line with LOG_PREFIX; optional second argument
   * is logged as a separate detail value.
   */
  function log(action, detail) {
    if (typeof console === "undefined" || !console.info) return;
    if (detail !== undefined && detail !== null && detail !== "") {
      console.info(LOG_PREFIX + " " + action, detail);
    } else {
      console.info(LOG_PREFIX + " " + action);
    }
  }

  /**
   * Truncates a string for log output (default max length 120), appending
   * an ellipsis when shortened.
   */
  function truncate(s, max) {
    max = max || 120;
    if (s == null) return "";
    s = String(s);
    if (s.length <= max) return s;
    return s.slice(0, max) + "…";
  }

  var PREFIXES = [
    "chrome-extension://",
    "moz-extension://",
    "safari-web-extension://",
    "edge-extension://",
  ];

  /**
   * Regex for many distinct chrome-extension:// plus 32 hex id paths in one
   * source (bundled extension-ID list probes).
   */
  var EXT_SCHEME_IN_SOURCE = /chrome-extension:\/\/[a-f0-9]{32}\//gi;
  /**
   * Regex for moz-extension:// paths in script text (Firefox extension
   * probes).
   */
  var MOZ_SCHEME_IN_SOURCE = /moz-extension:\/\/[a-f0-9-]+\//gi;
  var MIN_INLINE_LEN = 400;
  var MIN_SCHEME_HITS = 3;

  /**
   * True if `url` starts with a known extension scheme (chrome-extension,
   * moz-extension, safari-web-extension, edge-extension).
   */
  function isExtensionSchemeUrl(url) {
    if (url == null) return false;
    var s = typeof url === "string" ? url : String(url);
    for (var i = 0; i < PREFIXES.length; i++) {
      if (s.indexOf(PREFIXES[i]) === 0) return true;
    }
    return false;
  }

  /**
   * Resolves a URL string against `document.baseURI` to an absolute href.
   * On parse failure, returns `String(url)`.
   */
  function resolveUrlAbsolute(url) {
    if (url == null || url === "") return "";
    try {
      return new URL(
        String(url),
        typeof document !== "undefined" ? document.baseURI : undefined
      ).href;
    } catch (_) {
      return String(url);
    }
  }

  /**
   * Lowercase segment names allowed to bypass the opaque-token heuristic
   * (single path segment, length ≥10, both letter and digit). Add here if a
   * legitimate LinkedIn path is wrongly blocked.
   */
  var LINKEDIN_ALLOWED_OPAQUE_SEGMENTS = new Set([]);

  /**
   * True for single-segment paths that look like opaque tracking tokens
   * (e.g. /q5WiqtMRlw): length 10–96, [A-Za-z0-9_-]+, at least one digit and
   * one letter. Not expressible safely in declarativeNetRequest RE2; JS only.
   */
  function isLinkedInOpaqueTokenPath(pathname) {
    var m = pathname.match(/^\/([^/?#]+)\/?$/);
    if (!m) return false;
    var seg = m[1];
    if (seg.length < 10 || seg.length > 96) return false;
    if (!/^[A-Za-z0-9_-]+$/.test(seg)) return false;
    if (!/[0-9]/.test(seg) || !/[a-zA-Z]/.test(seg)) return false;
    if (LINKEDIN_ALLOWED_OPAQUE_SEGMENTS.has(seg.toLowerCase())) return false;
    return true;
  }

  /**
   * True when the URL host is `cs.ns1p.net` (third-party; blocks all paths).
   */
  function isNs1pBlockedUrl(url) {
    if (!url) return false;
    try {
      var u = new URL(
        String(url),
        typeof document !== "undefined" ? document.baseURI : undefined
      );
      return u.hostname.toLowerCase() === "cs.ns1p.net";
    } catch (_) {
      return false;
    }
  }

  /**
   * True for LinkedIn `POST` to `/li/tscp/sct` (TSCP session/telemetry).
   * Other methods are not blocked here so declarativeNetRequest can own
   * path-level rules without double-counting GET (if any).
   */
  function isLinkedInLiTscpSctPost(url, method) {
    if (!url) return false;
    try {
      var u = new URL(
        String(url),
        typeof document !== "undefined" ? document.baseURI : undefined
      );
      var h = u.hostname.toLowerCase();
      var onLinkedIn =
        h === "linkedin.com" || h.slice(-13) === ".linkedin.com";
      if (!onLinkedIn) return false;
      var p = u.pathname;
      if (p.indexOf("/li/tscp/sct") !== 0) return false;
      var m = method == null ? "GET" : String(method);
      return m.toUpperCase() === "POST";
    } catch (_) {
      return false;
    }
  }

  /**
   * True for LinkedIn hostnames and blocklisted path prefixes (sensorCollect,
   * li/track, realtime connectivity tracking, tscp-serving) or opaque token
   * paths matched by `isLinkedInOpaqueTokenPath`.
   */
  function isLinkedInBlocklistedUrl(url) {
    if (!url) return false;
    try {
      var u = new URL(
        String(url),
        typeof document !== "undefined" ? document.baseURI : undefined
      );
      var h = u.hostname.toLowerCase();
      var onLinkedIn =
        h === "linkedin.com" || h.slice(-13) === ".linkedin.com";
      if (!onLinkedIn) return false;
      var p = u.pathname;
      if (p.indexOf("/sensorCollect") !== -1) return true;
      if (p.indexOf("/li/track") !== -1) return true;
      if (
        p.indexOf("/realtime/realtimeFrontendClientConnectivityTracking") !==
        -1
      )
        return true;
      if (p.indexOf("/tscp-serving") !== -1) return true;
      if (isLinkedInOpaqueTokenPath(p)) return true;
      return false;
    } catch (_) {
      return false;
    }
  }

  /**
   * True when the URL host is the PerimeterX protechts collector
   * (collector-pxdojv695v.protechts.net); blocks all paths on that host.
   */
  function isProtechtsCollectorUrl(url) {
    if (!url) return false;
    try {
      var u = new URL(
        String(url),
        typeof document !== "undefined" ? document.baseURI : undefined
      );
      return (
        u.hostname.toLowerCase() === "collector-pxdojv695v.protechts.net"
      );
    } catch (_) {
      return false;
    }
  }

  /**
   * Reads the URL from `fetch()` input: plain string, `URL`, `Request`, or
   * falls back to `String(input)`.
   */
  function requestUrlFromFetchInput(input) {
    if (input == null) return "";
    if (typeof input === "string") return input;
    if (typeof URL !== "undefined" && input instanceof URL) return input.href;
    if (typeof Request !== "undefined" && input instanceof Request)
      return input.url;
    return String(input);
  }

  /**
   * Counts how many times the global regex `re` matches in string `s`
   * (restarts lastIndex before counting).
   */
  function countMatches(re, s) {
    if (!s) return 0;
    re.lastIndex = 0;
    var n = 0;
    while (re.exec(s)) n++;
    return n;
  }

  /**
   * Heuristic for inline script text: long enough and many
   * chrome-extension://… or other extension-scheme substrings (bundled
   * extension-ID probe lists).
   */
  function looksLikeExtensionProbeSource(text) {
    if (!text || text.length < MIN_INLINE_LEN) return false;
    var c = countMatches(EXT_SCHEME_IN_SOURCE, text);
    var m = countMatches(MOZ_SCHEME_IN_SOURCE, text);
    if (c >= MIN_SCHEME_HITS || m >= MIN_SCHEME_HITS) return true;
    var raw = 0;
    var i = 0;
    while (i < PREFIXES.length) {
      var p = PREFIXES[i++];
      var pos = 0;
      while ((pos = text.indexOf(p, pos)) !== -1) {
        raw++;
        pos += p.length;
      }
    }
    return raw >= MIN_SCHEME_HITS;
  }

  /**
   * If `node` is a `<script>` that should not be attached, returns a short
   * human-readable reason; otherwise null. Used by DOM insertion hooks.
   */
  function scriptDropReason(node) {
    if (!node || node.nodeType !== 1) return null;
    if (String(node.tagName).toUpperCase() !== "SCRIPT") return null;
    var src = node.src || "";
    if (src && isExtensionSchemeUrl(src)) {
      return "blocked script (extension-scheme src): " + truncate(src);
    }
    if (src) return null;
    var text = node.textContent || "";
    if (looksLikeExtensionProbeSource(text)) {
      return (
        "blocked inline script (extension-probe heuristic, " +
        text.length +
        " chars)"
      );
    }
    return null;
  }

  /**
   * True when `scriptDropReason` is non-null for this node.
   */
  function shouldDropScriptElement(node) {
    return scriptDropReason(node) != null;
  }

  /**
   * Wraps `appendChild`, `insertBefore`, `replaceChild`, and when present
   * `Element.append` / `prepend` so dynamically inserted probe `<script>`s
   * matching `scriptDropReason` are never attached (parser-inserted scripts
   * are not affected).
   */
  function patchDomInsertion() {
    var np = typeof Node !== "undefined" ? Node.prototype : null;
    var ep = typeof Element !== "undefined" ? Element.prototype : null;
    if (!np) return;

    /**
     * Intercepts `appendChild` / `insertBefore` so blocked `<script>` nodes
     * are never inserted into the tree.
     */
    function wrapTwo(name) {
      var orig = np[name];
      if (typeof orig !== "function") return;
      np[name] = function (node, ref) {
        var why = scriptDropReason(node);
        if (why) {
          log("DOM " + name + " — dropped <script>", why);
          return node;
        }
        return orig.apply(this, arguments);
      };
    }

    /**
     * Patches `replaceChild` so dropped scripts return the old child per DOM
     * semantics when the new child is blocked.
     */
    function wrapReplaceChild() {
      var orig = np.replaceChild;
      if (typeof orig !== "function") return;
      np.replaceChild = function (node, child) {
        var why = scriptDropReason(node);
        if (why) {
          log("DOM replaceChild — dropped <script>", why);
          return child;
        }
        return orig.apply(this, arguments);
      };
    }

    wrapTwo("appendChild");
    wrapTwo("insertBefore");
    wrapReplaceChild();

    if (ep) {
      var append = ep.append;
      if (typeof append === "function") {
        ep.append = function () {
          var args = [];
          var i = 0;
          for (; i < arguments.length; i++) {
            var n = arguments[i];
            var why = scriptDropReason(n);
            if (why) {
              log("Element.append — dropped <script>", why);
              continue;
            }
            args.push(n);
          }
          return append.apply(this, args);
        };
      }
      var prepend = ep.prepend;
      if (typeof prepend === "function") {
        ep.prepend = function () {
          var args = [];
          var i = 0;
          for (; i < arguments.length; i++) {
            var n = arguments[i];
            var why = scriptDropReason(n);
            if (why) {
              log("Element.prepend — dropped <script>", why);
              continue;
            }
            args.push(n);
          }
          return prepend.apply(this, args);
        };
      }
    }
  }

  /**
   * Invalid minimal PNG data URL used to replace blocked `src` on images when
   * a real load must fail without hitting an extension URL.
   */
  var BROKEN_DATA_IMG =
    "data:image/png;base64,";

  /**
   * Resolves blocked fetch() with a 502 Response (response.ok false) so callers
   * that omit .catch() do not surface uncaught rejections; check response.ok.
   */
  function blockedFetchResponse() {
    return new Response(null, {
      status: 502,
      statusText: "Bad Gateway",
    });
  }

  /**
   * Wraps `window.fetch` to short-circuit blocked extension-scheme, LinkedIn
   * blocklist, and protechts collector URLs before the request runs.
   */
  function patchFetch() {
    if (typeof window.fetch !== "function") return;
    var orig = window.fetch;
    window.fetch = function (input, init) {
      var raw = requestUrlFromFetchInput(input);
      var abs = resolveUrlAbsolute(raw);
      var fetchMethod =
        init && init.method ? String(init.method) : "GET";
      if (isExtensionSchemeUrl(abs)) {
        logExtensionSchemeBlock(
          "fetch blocked (extension scheme)",
          truncate(abs, 200)
        );
        return Promise.resolve(blockedFetchResponse());
      }
      if (isNs1pBlockedUrl(abs)) {
        log("fetch blocked (cs.ns1p.net)", truncate(abs, 200));
        return Promise.resolve(blockedFetchResponse());
      }
      if (isLinkedInLiTscpSctPost(abs, fetchMethod)) {
        log("fetch blocked (LinkedIn li/tscp/sct POST)", truncate(abs, 200));
        return Promise.resolve(blockedFetchResponse());
      }
      if (isLinkedInBlocklistedUrl(abs)) {
        log("fetch blocked (LinkedIn blocklist)", truncate(abs, 200));
        bumpLinkedInBlocklistFetchStat();
        bumpLinkedInBlocklistStat();
        return Promise.resolve(blockedFetchResponse());
      }
      if (isProtechtsCollectorUrl(abs)) {
        log("fetch blocked (protechts collector)", truncate(abs, 200));
        return Promise.resolve(blockedFetchResponse());
      }
      var g2 = ensureGuard();
      if (g2.redteamEnabled) {
        try {
          var obsUrl = abs || raw;
          postRedteamToOverlay({
            source: "boxedin-page-guard",
            type: "exfil",
            subtype: "fetch",
            url: String(obsUrl).slice(0, 200),
            method: fetchMethod,
            ts: Date.now()
          });
        } catch (eObs) { /* ignore */ }
      }
      return orig.apply(this, arguments);
    };
  }

  /**
   * Wraps `XMLHttpRequest.prototype.open` to throw on the same blocked URL
   * classes as `patchFetch`.
   */
  function patchXHR() {
    var XHR = window.XMLHttpRequest;
    if (!XHR || !XHR.prototype) return;
    var origOpen = XHR.prototype.open;
    XHR.prototype.open = function (method, url) {
      var abs = resolveUrlAbsolute(url);
      if (isExtensionSchemeUrl(abs)) {
        logExtensionSchemeBlock(
          "XMLHttpRequest.open blocked (extension scheme)",
          truncate(abs, 200)
        );
        throw new TypeError("Blocked extension-URL XHR");
      }
      if (isNs1pBlockedUrl(abs)) {
        log(
          "XMLHttpRequest.open blocked (cs.ns1p.net)",
          truncate(abs, 200)
        );
        throw new TypeError("Blocked ns1p XHR");
      }
      if (isLinkedInLiTscpSctPost(abs, method)) {
        log(
          "XMLHttpRequest.open blocked (LinkedIn li/tscp/sct POST)",
          truncate(abs, 200)
        );
        throw new TypeError("Blocked LinkedIn li/tscp/sct POST XHR");
      }
      if (isLinkedInBlocklistedUrl(abs)) {
        log(
          "XMLHttpRequest.open blocked (LinkedIn blocklist)",
          truncate(abs, 200)
        );
        bumpLinkedInBlocklistStat();
        throw new TypeError("Blocked LinkedIn telemetry XHR");
      }
      if (isProtechtsCollectorUrl(abs)) {
        log(
          "XMLHttpRequest.open blocked (protechts collector)",
          truncate(abs, 200)
        );
        throw new TypeError("Blocked protechts collector XHR");
      }
      var g2 = ensureGuard();
      if (g2.redteamEnabled) {
        try {
          postRedteamToOverlay({
            source: "boxedin-page-guard",
            type: "exfil",
            subtype: "xhr",
            url: String(abs).slice(0, 200),
            method: String(method),
            ts: Date.now()
          });
        } catch (eObs) { /* ignore */ }
      }
      return origOpen.apply(this, arguments);
    };
  }

  /**
   * Wraps `navigator.sendBeacon` to return false for blocked URLs (same
   * policy as fetch/XHR).
   */
  function patchSendBeacon() {
    if (
      typeof navigator === "undefined" ||
      typeof navigator.sendBeacon !== "function"
    ) {
      return;
    }
    var orig = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) {
      var abs = resolveUrlAbsolute(url);
      if (isExtensionSchemeUrl(abs)) {
        logExtensionSchemeBlock(
          "sendBeacon blocked (extension scheme)",
          truncate(abs, 200)
        );
        return false;
      }
      if (isNs1pBlockedUrl(abs)) {
        log("sendBeacon blocked (cs.ns1p.net)", truncate(abs, 200));
        return false;
      }
      if (isLinkedInLiTscpSctPost(abs, "POST")) {
        log(
          "sendBeacon blocked (LinkedIn li/tscp/sct POST)",
          truncate(abs, 200)
        );
        return false;
      }
      if (isLinkedInBlocklistedUrl(abs)) {
        log("sendBeacon blocked (LinkedIn blocklist)", truncate(abs, 200));
        bumpLinkedInBlocklistStat();
        return false;
      }
      if (isProtechtsCollectorUrl(abs)) {
        log("sendBeacon blocked (protechts collector)", truncate(abs, 200));
        return false;
      }
      return orig(url, data);
    };
  }

  /**
   * Replaces `src` setter on `ctor.prototype` (image, iframe, script) to
   * neutralize extension-scheme and protechts collector URLs. `label` is used
   * only for logging and choosing `about:blank` vs broken image data.
   *
   * @param {Function|null} ctor - e.g. HTMLImageElement
   * @param {string} propName - always "src" here
   * @param {string} label - constructor name for logs
   */
  function patchSrcProperty(ctor, propName, label) {
    if (!ctor || !ctor.prototype) return;
    try {
      var proto = ctor.prototype;
      var desc = Object.getOwnPropertyDescriptor(proto, propName);
      if (!desc || !desc.set) return;
      var origSet = desc.set;
      Object.defineProperty(proto, propName, {
        configurable: true,
        enumerable: desc.enumerable,
        get: desc.get,
        set: function (v) {
          var abs = resolveUrlAbsolute(v);
          if (isExtensionSchemeUrl(abs)) {
            logExtensionSchemeBlock(
              (label || propName) + "." + propName + " neutralized",
              truncate(v, 200)
            );
            return origSet.call(this, BROKEN_DATA_IMG);
          }
          if (isNs1pBlockedUrl(abs)) {
            log(
              (label || propName) + "." + propName + " neutralized (ns1p)",
              truncate(v, 200)
            );
            if (
              label === "HTMLIFrameElement" ||
              label === "HTMLScriptElement"
            ) {
              return origSet.call(this, "about:blank");
            }
            return origSet.call(this, BROKEN_DATA_IMG);
          }
          if (isProtechtsCollectorUrl(abs)) {
            log(
              (label || propName) + "." + propName + " neutralized (protechts)",
              truncate(v, 200)
            );
            if (
              label === "HTMLIFrameElement" ||
              label === "HTMLScriptElement"
            ) {
              return origSet.call(this, "about:blank");
            }
            return origSet.call(this, BROKEN_DATA_IMG);
          }
          return origSet.call(this, v);
        },
      });
    } catch (_) {
      /* ignore */
    }
  }

  /**
   * Replaces `href` setter on anchors or links to `about:blank` for blocked
   * extension-scheme or protechts URLs.
   *
   * @param {Function|null} ctor - HTMLAnchorElement or HTMLLinkElement
   * @param {string} label - name for log lines
   */
  function patchHrefProperty(ctor, label) {
    if (!ctor || !ctor.prototype) return;
    try {
      var proto = ctor.prototype;
      var desc = Object.getOwnPropertyDescriptor(proto, "href");
      if (!desc || !desc.set) return;
      var origSet = desc.set;
      Object.defineProperty(proto, "href", {
        configurable: true,
        enumerable: desc.enumerable,
        get: desc.get,
        set: function (v) {
          var abs = resolveUrlAbsolute(v);
          if (isExtensionSchemeUrl(abs)) {
            logExtensionSchemeBlock(
              (label || "element") + ".href neutralized",
              truncate(v, 200)
            );
            return origSet.call(this, "about:blank");
          }
          if (isNs1pBlockedUrl(abs)) {
            log(
              (label || "element") + ".href neutralized (ns1p)",
              truncate(v, 200)
            );
            return origSet.call(this, "about:blank");
          }
          if (isProtechtsCollectorUrl(abs)) {
            log(
              (label || "element") + ".href neutralized (protechts)",
              truncate(v, 200)
            );
            return origSet.call(this, "about:blank");
          }
          return origSet.call(this, v);
        },
      });
    } catch (_) {
      /* ignore */
    }
  }

  /**
   * Wraps `Element.prototype.setAttribute` for `src` and `href` so attribute
   * assignment cannot bypass the same URL rules as property setters.
   */
  function patchSetAttribute() {
    var el = typeof Element !== "undefined" ? Element.prototype : null;
    if (!el || !el.setAttribute) return;
    var orig = el.setAttribute;
    el.setAttribute = function (name, value) {
      var n = String(name).toLowerCase();
      if ((n === "src" || n === "href") && typeof value === "string") {
        var abs = resolveUrlAbsolute(value);
        if (isExtensionSchemeUrl(abs)) {
          logExtensionSchemeBlock(
            "setAttribute(" + n + ") neutralized",
            truncate(value, 200)
          );
          if (n === "src") return orig.call(this, "src", BROKEN_DATA_IMG);
          return orig.call(this, "href", "about:blank");
        }
        if (isNs1pBlockedUrl(abs)) {
          log(
            "setAttribute(" + n + ") neutralized (ns1p)",
            truncate(value, 200)
          );
          if (n === "src") {
            var tagN = String(this.tagName || "").toUpperCase();
            if (tagN === "IFRAME" || tagN === "SCRIPT") {
              return orig.call(this, "src", "about:blank");
            }
            return orig.call(this, "src", BROKEN_DATA_IMG);
          }
          return orig.call(this, "href", "about:blank");
        }
        if (isProtechtsCollectorUrl(abs)) {
          log(
            "setAttribute(" + n + ") neutralized (protechts)",
            truncate(value, 200)
          );
          if (n === "src") {
            var tag = String(this.tagName || "").toUpperCase();
            if (tag === "IFRAME" || tag === "SCRIPT") {
              return orig.call(this, "src", "about:blank");
            }
            return orig.call(this, "src", BROKEN_DATA_IMG);
          }
          return orig.call(this, "href", "about:blank");
        }
      }
      return orig.apply(this, arguments);
    };
  }

  patchFetch();
  patchXHR();
  patchSendBeacon();
  patchSrcProperty(
    typeof HTMLImageElement !== "undefined" ? HTMLImageElement : null,
    "src",
    "HTMLImageElement"
  );
  patchSrcProperty(
    typeof HTMLIFrameElement !== "undefined" ? HTMLIFrameElement : null,
    "src",
    "HTMLIFrameElement"
  );
  patchSrcProperty(
    typeof HTMLScriptElement !== "undefined" ? HTMLScriptElement : null,
    "src",
    "HTMLScriptElement"
  );
  patchHrefProperty(
    typeof HTMLAnchorElement !== "undefined" ? HTMLAnchorElement : null,
    "HTMLAnchorElement"
  );
  patchHrefProperty(
    typeof HTMLLinkElement !== "undefined" ? HTMLLinkElement : null,
    "HTMLLinkElement"
  );
  patchSetAttribute();
  patchDomInsertion();

  try {
    var g = ensureGuard();
    g.version = "1.1.0";
    g.loadedAt = Date.now();
    g.logPrefix = LOG_PREFIX;
    /**
     * Returns a fixed string so callers can verify the guard is present in
     * this frame.
     */
    g.check = function () {
      return "extension-probe-guard is injected in this frame";
    };
    /**
     * Adds a lowercase path segment to `LINKEDIN_ALLOWED_OPAQUE_SEGMENTS` at
     * runtime if an opaque-token path is wrongly blocked.
     */
    g.allowLinkedInOpaqueSegment = function (seg) {
      if (!seg) return;
      LINKEDIN_ALLOWED_OPAQUE_SEGMENTS.add(String(seg).toLowerCase());
    };
    g.redteamEnabled = false;
    g.enableRedteam = function () {
      g.redteamEnabled = true;
      runRedteamScans();
    };
  } catch (_) {
    /* ignore */
  }

  window.addEventListener("message", function (ev) {
    try {
      if (ev.data && ev.data.source === "boxedin-overlay" && ev.data.type === "enable-redteam") {
        var g = ensureGuard();
        if (!g.redteamEnabled) {
          g.redteamEnabled = true;
          runRedteamScans();
        }
      }
    } catch (e) { /* ignore */ }
  });

  function postRedteamToOverlay(msg) {
    try {
      var target = window;
      try { if (window.top) target = window.top; } catch (e) { /* cross-origin */ }
      if (typeof target.postMessage === "function") {
        target.postMessage(msg, "*");
      }
    } catch (e) { /* ignore */ }
  }

  var redteamScansActive = false;

  function scanTechStack() {
    try {
      var found = {};

      var ATTACK_NOTES = {
        "WordPress": "XML-RPC, wp-login brute force, plugin/theme CVEs",
        "Drupal": "Drupalgeddon RCE history, module CVEs",
        "Joomla": "Admin panel brute force, extension CVEs",
        "Shopify": "Liquid template injection, API token leakage",
        "Squarespace": "Limited attack surface; check third-party integrations",
        "Wix": "Client-side data exposure via Wix APIs",
        "Ghost": "Admin panel exposure, API key leakage",
        "Webflow": "Exposed site data in client JS",
        "Hugo": "Static site; check for exposed config or draft content",
        "Jekyll": "Static site; check for exposed _config.yml or draft pages",
        "Contentful": "CDN-delivered; check API keys in client JS",
        "Strapi": "REST/GraphQL API; check for open endpoints and default admin",
        "Sanity": "Check for exposed project ID and dataset in client JS",
        "Prismic": "Check for exposed API endpoint and repository name",
        "React": "Client-side state in DevTools, check for dangerouslySetInnerHTML",
        "Preact": "Lightweight React alt; same dangerouslySetInnerHTML risks",
        "Vue": "Vue DevTools state inspection, v-html XSS risk",
        "Angular": "Template injection if user input in templates, zone.js overhead",
        "AngularJS": "EOL framework; known prototype pollution and sandbox escapes",
        "jQuery": "DOM XSS via $.html(), check version for known CVEs",
        "jQuery UI": "Check version for known XSS CVEs in dialog/autocomplete",
        "Lodash": "Prototype pollution in older versions (< 4.17.12)",
        "Underscore": "Template injection if user input in _.template()",
        "Next.js": "API routes may leak server config, check _next/data exposure",
        "Nuxt": "Server-side config leakage, __NUXT__ state exposure",
        "Gatsby": "GraphQL data layer may expose internal schema at /__graphql",
        "Remix": "Loader data exposed in __remixContext, check for sensitive data",
        "Astro": "Partial hydration; check for exposed island props",
        "Svelte": "Minimal attack surface; check {@html} usage",
        "SvelteKit": "Server routes may leak config; check +page.server data",
        "Ember": "Prototype pollution history, check for triple-stash {{{",
        "Backbone": "Underscore template injection if user input in templates",
        "Alpine.js": "x-data expressions evaluated as JS; XSS via user input in attributes",
        "HTMX": "Server-driven; hx-* attributes can trigger requests to attacker-controlled URLs",
        "Turbo": "Hotwire Turbo; frame injection if src attributes are user-controlled",
        "Stimulus": "Hotwire Stimulus; data-controller values map to JS classes",
        "Lit": "Web components; check for unsanitized HTML in render()",
        "Stencil": "Web components; check for innerHTML usage in JSX",
        "Bootstrap": "Check version for XSS in tooltip/popover (< 3.4.0, < 4.3.1)",
        "Tailwind CSS": "Utility framework; low direct risk but check for purge misconfig",
        "Foundation": "Check version for known XSS in JS components",
        "Material UI": "React component library; check for injection in dynamic props",
        "Vite": "Dev server may be exposed; check for /@vite/client in production",
        "Webpack": "Check for exposed source maps (.map files) and devServer",
        "Google Analytics": "PII leakage via query strings and custom dimensions",
        "Google Tag Manager": "Tag injection if GTM container is misconfigured",
        "Facebook Pixel": "Custom event data may leak PII to third party",
        "Hotjar": "Session recordings may capture sensitive form data",
        "Mixpanel": "User property tracking may expose PII",
        "Segment": "Data routing to multiple third-party destinations",
        "Heap": "Auto-capture may record sensitive input fields",
        "Amplitude": "User properties and event data may leak PII",
        "Plausible": "Privacy-focused; minimal attack surface",
        "Matomo": "Self-hosted analytics; check for exposed admin panel",
        "Clarity": "Microsoft Clarity; session replay may capture sensitive fields",
        "PHP": "Version disclosure, check for known CVEs",
        "Express": "Default error pages leak stack traces",
        "Nginx": "Version disclosure, misconfiguration checks",
        "Apache": "Version disclosure, mod_status/mod_info exposure",
        "ASP.NET": "ViewState deserialization, debug mode exposure",
        "Cloudflare": "CDN — origin IP may still be discoverable",
        "Java Servlet": "Check for exposed stack traces and JSESSIONID fixation",
        "Laravel": "Check for APP_DEBUG=true, exposed .env, debug bar",
        "Django": "Check for DEBUG=True, exposed admin panel at /admin/",
        "Ruby on Rails": "Check for exposed routes, mass assignment, debug mode"
      };

      function emit(category, name, version, evidence) {
        if (found[name]) return;
        found[name] = true;
        postRedteamToOverlay({
          source: "boxedin-page-guard",
          type: "tech",
          category: category,
          name: name,
          version: version || null,
          evidence: evidence,
          attackNotes: ATTACK_NOTES[name] || ""
        });
      }

      /* ── Meta tags ────────────────────────────────────────────── */

      var metas = document.querySelectorAll('meta[name="generator"], meta[name="application-name"], meta[content]');
      for (var mi = 0; mi < metas.length; mi++) {
        var metaName = (metas[mi].getAttribute("name") || "").toLowerCase();
        var metaContent = metas[mi].getAttribute("content") || "";
        if (metaName === "generator" || metaName === "application-name") {
          var mc = metaContent.toLowerCase();
          if (mc.indexOf("wordpress") !== -1) emit("cms", "WordPress", metaContent.replace(/WordPress\s*/i, ""), "meta generator");
          else if (mc.indexOf("drupal") !== -1) emit("cms", "Drupal", (metaContent.match(/Drupal\s+([\d.]+)/i) || [])[1] || null, "meta generator");
          else if (mc.indexOf("joomla") !== -1) emit("cms", "Joomla", (metaContent.match(/Joomla[!]?\s*([\d.]+)/i) || [])[1] || null, "meta generator");
          else if (mc.indexOf("ghost") !== -1) emit("cms", "Ghost", null, "meta generator");
          else if (mc.indexOf("webflow") !== -1) emit("cms", "Webflow", null, "meta generator");
          else if (mc.indexOf("squarespace") !== -1) emit("cms", "Squarespace", null, "meta generator");
          else if (mc.indexOf("wix") !== -1) emit("cms", "Wix", null, "meta generator");
          else if (mc.indexOf("shopify") !== -1) emit("cms", "Shopify", null, "meta generator");
          else if (mc.indexOf("hugo") !== -1) emit("cms", "Hugo", (metaContent.match(/Hugo\s+([\d.]+)/i) || [])[1] || null, "meta generator");
          else if (mc.indexOf("jekyll") !== -1) emit("cms", "Jekyll", (metaContent.match(/Jekyll\s+v?([\d.]+)/i) || [])[1] || null, "meta generator");
          else if (mc.indexOf("gatsby") !== -1) emit("framework", "Gatsby", null, "meta generator");
          else if (mc.indexOf("next.js") !== -1) emit("framework", "Next.js", null, "meta generator");
          else if (mc.indexOf("nuxt") !== -1) emit("framework", "Nuxt", null, "meta generator");
        }
      }

      /* ── Window globals ───────────────────────────────────────── */

      var globalProbes = [
        { test: "wp", category: "cms", name: "WordPress" },
        { test: "Drupal", category: "cms", name: "Drupal" },
        { test: "Joomla", category: "cms", name: "Joomla" },
        { test: "Shopify", category: "cms", name: "Shopify" },
        { test: "__NEXT_DATA__", category: "framework", name: "Next.js" },
        { test: "__NUXT__", category: "framework", name: "Nuxt" },
        { test: "__SVELTE__", category: "framework", name: "Svelte" },
        { test: "__sveltekit", category: "framework", name: "SvelteKit" },
        { test: "__remixContext", category: "framework", name: "Remix" },
        { test: "__GATSBY", category: "framework", name: "Gatsby" },
        { test: "__astro_tag_component__", category: "framework", name: "Astro" },
        { test: "Ember", category: "framework", name: "Ember" },
        { test: "Backbone", category: "framework", name: "Backbone" },
        { test: "htmx", category: "framework", name: "HTMX", check: function () { try { return window.htmx && typeof window.htmx.process === "function"; } catch (e) { return false; } } },
        { test: "Alpine", category: "framework", name: "Alpine.js", check: function () { try { return window.Alpine && typeof window.Alpine.start === "function"; } catch (e) { return false; } } },
        { test: "Turbo", category: "framework", name: "Turbo", check: function () { try { return window.Turbo && typeof window.Turbo.visit === "function"; } catch (e) { return false; } } },
        { test: "Stimulus", category: "framework", name: "Stimulus", check: function () { try { return window.Stimulus && typeof window.Stimulus.register === "function"; } catch (e) { return false; } } },
        { test: "preact", category: "framework", name: "Preact", check: function () { try { return window.preact && typeof window.preact.h === "function"; } catch (e) { return false; } } },
        { test: "ga", category: "analytics", name: "Google Analytics" },
        { test: "gtag", category: "analytics", name: "Google Analytics", check: function () { try { return typeof window.gtag === "function"; } catch (e) { return false; } } },
        { test: "google_tag_manager", category: "analytics", name: "Google Tag Manager" },
        { test: "dataLayer", category: "analytics", name: "Google Tag Manager", check: function () { try { return Array.isArray(window.dataLayer) && window.dataLayer.length > 0; } catch (e) { return false; } } },
        { test: "fbq", category: "analytics", name: "Facebook Pixel" },
        { test: "hj", category: "analytics", name: "Hotjar" },
        { test: "mixpanel", category: "analytics", name: "Mixpanel" },
        { test: "analytics", category: "analytics", name: "Segment", check: function () { try { return window.analytics && typeof window.analytics.identify === "function"; } catch (e) { return false; } } },
        { test: "heap", category: "analytics", name: "Heap", check: function () { try { return window.heap && typeof window.heap.track === "function"; } catch (e) { return false; } } },
        { test: "amplitude", category: "analytics", name: "Amplitude", check: function () { try { return window.amplitude && typeof window.amplitude.getInstance === "function"; } catch (e) { return false; } } },
        { test: "plausible", category: "analytics", name: "Plausible", check: function () { try { return typeof window.plausible === "function"; } catch (e) { return false; } } },
        { test: "_paq", category: "analytics", name: "Matomo", check: function () { try { return Array.isArray(window._paq); } catch (e) { return false; } } },
        { test: "clarity", category: "analytics", name: "Clarity", check: function () { try { return typeof window.clarity === "function"; } catch (e) { return false; } } },
        { test: "_", category: "framework", name: "Lodash", check: function () { try { return window._ && window._.VERSION && typeof window._.map === "function"; } catch (e) { return false; } } }
      ];
      for (var gi = 0; gi < globalProbes.length; gi++) {
        var gp = globalProbes[gi];
        try {
          if (gp.check) {
            if (gp.check()) emit(gp.category, gp.name, null, "window global");
          } else if (window[gp.test] != null) {
            emit(gp.category, gp.name, null, "window global");
          }
        } catch (eG) { /* ignore */ }
      }

      try {
        if (window.React || (window.__REACT_DEVTOOLS_GLOBAL_HOOK__ && window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers && window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers.size > 0)) {
          var rv = null;
          try { rv = window.React && window.React.version ? window.React.version : null; } catch (e) {}
          emit("framework", "React", rv, "window global");
        }
      } catch (eR) { /* ignore */ }
      try {
        if (window.Vue) emit("framework", "Vue", window.Vue.version || null, "window global");
      } catch (eV) { /* ignore */ }
      try {
        if (window.angular || document.querySelector("[ng-app], [ng-controller], [data-ng-app]")) {
          var angV = null;
          try { angV = window.angular && window.angular.version ? window.angular.version.full : null; } catch (e) {}
          if (angV) emit("framework", "AngularJS", angV, "window global");
          else emit("framework", "Angular", null, "window global");
        }
      } catch (eA) { /* ignore */ }
      try {
        if (window.jQuery || window.$) {
          var jqv = null;
          try { jqv = window.jQuery ? window.jQuery.fn.jquery : (window.$ && window.$.fn ? window.$.fn.jquery : null); } catch (e) {}
          emit("framework", "jQuery", jqv, "window global");
        }
      } catch (eJ) { /* ignore */ }
      try {
        if (window.jQuery && window.jQuery.ui) {
          emit("framework", "jQuery UI", window.jQuery.ui.version || null, "window global");
        }
      } catch (eJU) { /* ignore */ }
      try {
        if (window._ && window._.VERSION) {
          emit("framework", "Lodash", window._.VERSION, "window global");
        } else if (window._ && typeof window._.template === "function" && !window._.VERSION) {
          emit("framework", "Underscore", null, "window global");
        }
      } catch (eL) { /* ignore */ }

      /* ── DOM attribute probes ─────────────────────────────────── */

      try {
        if (document.querySelector("[data-reactroot], [data-reactid]")) emit("framework", "React", null, "DOM attribute");
        if (document.querySelector("[data-react-helmet]")) emit("framework", "React", null, "DOM attribute");
      } catch (eD1) { /* ignore */ }
      try {
        var ngVer = document.querySelector("[ng-version]");
        if (ngVer) emit("framework", "Angular", ngVer.getAttribute("ng-version"), "DOM attribute");
      } catch (eD2) { /* ignore */ }
      try {
        if (document.querySelector("[data-v-], [data-vue-app]") || document.querySelector("#__nuxt") || document.querySelector("#__vue_app__")) emit("framework", "Vue", null, "DOM attribute");
      } catch (eD3) { /* ignore */ }
      try {
        if (document.querySelector("[data-svelte], .s-")) emit("framework", "Svelte", null, "DOM attribute");
      } catch (eD4) { /* ignore */ }
      try {
        if (document.getElementById("__next")) emit("framework", "Next.js", null, "DOM element");
        if (document.getElementById("__nuxt") || document.getElementById("__layout")) emit("framework", "Nuxt", null, "DOM element");
        if (document.getElementById("___gatsby")) emit("framework", "Gatsby", null, "DOM element");
      } catch (eD5) { /* ignore */ }
      try {
        if (document.querySelector("[data-turbo], [data-turbo-frame]")) emit("framework", "Turbo", null, "DOM attribute");
        if (document.querySelector("[data-controller]")) emit("framework", "Stimulus", null, "DOM attribute");
      } catch (eD6) { /* ignore */ }
      try {
        if (document.querySelector("[x-data], [x-init], [x-bind]")) emit("framework", "Alpine.js", null, "DOM attribute");
      } catch (eD7) { /* ignore */ }
      try {
        if (document.querySelector("[hx-get], [hx-post], [hx-trigger], [data-hx-get]")) emit("framework", "HTMX", null, "DOM attribute");
      } catch (eD8) { /* ignore */ }
      try {
        if (document.querySelector("astro-island, astro-slot")) emit("framework", "Astro", null, "DOM element");
      } catch (eD9) { /* ignore */ }

      /* ── HTML comment probes ──────────────────────────────────── */

      try {
        var html = document.documentElement.outerHTML.slice(0, 8000);
        if (/<!--\s*This is a WordPress/.test(html) || /wp-content/i.test(html)) emit("cms", "WordPress", null, "HTML content");
        if (/Powered by Drupal/i.test(html)) emit("cms", "Drupal", null, "HTML comment");
        if (/generator" content="Hugo/i.test(html)) emit("cms", "Hugo", null, "HTML content");
        if (/Vite|@vite\/client/i.test(html)) emit("framework", "Vite", null, "HTML content");
      } catch (eHC) { /* ignore */ }

      /* ── Script/link URL patterns (precise) ───────────────────── */

      var scriptPatterns = [
        { pattern: "wp-content/", category: "cms", name: "WordPress" },
        { pattern: "wp-includes/", category: "cms", name: "WordPress" },
        { pattern: "wp-json/", category: "cms", name: "WordPress" },
        { pattern: "cdn.shopify.com", category: "cms", name: "Shopify" },
        { pattern: "sdks.shopifycdn.com", category: "cms", name: "Shopify" },
        { pattern: "squarespace.com", category: "cms", name: "Squarespace" },
        { pattern: "squarespace-cdn.com", category: "cms", name: "Squarespace" },
        { pattern: "static.wixstatic.com", category: "cms", name: "Wix" },
        { pattern: "parastorage.com", category: "cms", name: "Wix" },
        { pattern: "ghost.io", category: "cms", name: "Ghost" },
        { pattern: "webflow.com", category: "cms", name: "Webflow" },
        { pattern: "assets.contentful.com", category: "cms", name: "Contentful" },
        { pattern: "cdn.contentful.com", category: "cms", name: "Contentful" },
        { pattern: "cdn.sanity.io", category: "cms", name: "Sanity" },
        { pattern: "prismic.io", category: "cms", name: "Prismic" },
        { pattern: "/react.", category: "framework", name: "React" },
        { pattern: "/react-dom.", category: "framework", name: "React" },
        { pattern: "unpkg.com/react", category: "framework", name: "React" },
        { pattern: "cdnjs.cloudflare.com/ajax/libs/react", category: "framework", name: "React" },
        { pattern: "/preact.", category: "framework", name: "Preact" },
        { pattern: "unpkg.com/preact", category: "framework", name: "Preact" },
        { pattern: "/vue.", category: "framework", name: "Vue" },
        { pattern: "/vue@", category: "framework", name: "Vue" },
        { pattern: "unpkg.com/vue", category: "framework", name: "Vue" },
        { pattern: "cdn.jsdelivr.net/npm/vue", category: "framework", name: "Vue" },
        { pattern: "/angular.", category: "framework", name: "Angular" },
        { pattern: "/angular@", category: "framework", name: "Angular" },
        { pattern: "ajax.googleapis.com/ajax/libs/angularjs", category: "framework", name: "AngularJS" },
        { pattern: "/jquery.", category: "framework", name: "jQuery" },
        { pattern: "/jquery-", category: "framework", name: "jQuery" },
        { pattern: "/jquery@", category: "framework", name: "jQuery" },
        { pattern: "code.jquery.com", category: "framework", name: "jQuery" },
        { pattern: "ajax.googleapis.com/ajax/libs/jquery", category: "framework", name: "jQuery" },
        { pattern: "/jquery-ui.", category: "framework", name: "jQuery UI" },
        { pattern: "/jquery.ui.", category: "framework", name: "jQuery UI" },
        { pattern: "/ember.", category: "framework", name: "Ember" },
        { pattern: "/backbone.", category: "framework", name: "Backbone" },
        { pattern: "/backbone-", category: "framework", name: "Backbone" },
        { pattern: "/svelte", category: "framework", name: "Svelte" },
        { pattern: "/alpine.", category: "framework", name: "Alpine.js" },
        { pattern: "unpkg.com/alpinejs", category: "framework", name: "Alpine.js" },
        { pattern: "cdn.jsdelivr.net/npm/alpinejs", category: "framework", name: "Alpine.js" },
        { pattern: "/htmx.", category: "framework", name: "HTMX" },
        { pattern: "unpkg.com/htmx.org", category: "framework", name: "HTMX" },
        { pattern: "/turbo.", category: "framework", name: "Turbo" },
        { pattern: "unpkg.com/@hotwired/turbo", category: "framework", name: "Turbo" },
        { pattern: "/stimulus.", category: "framework", name: "Stimulus" },
        { pattern: "unpkg.com/@hotwired/stimulus", category: "framework", name: "Stimulus" },
        { pattern: "/lit-html", category: "framework", name: "Lit" },
        { pattern: "/lit-element", category: "framework", name: "Lit" },
        { pattern: "/lit@", category: "framework", name: "Lit" },
        { pattern: "/stencil.", category: "framework", name: "Stencil" },
        { pattern: "/lodash.", category: "framework", name: "Lodash" },
        { pattern: "/lodash@", category: "framework", name: "Lodash" },
        { pattern: "/underscore.", category: "framework", name: "Underscore" },
        { pattern: "/_next/", category: "framework", name: "Next.js" },
        { pattern: "/_nuxt/", category: "framework", name: "Nuxt" },
        { pattern: "/@vite/client", category: "framework", name: "Vite" },
        { pattern: "/vite.", category: "framework", name: "Vite" },
        { pattern: "bootstrap.min.js", category: "framework", name: "Bootstrap" },
        { pattern: "bootstrap.bundle.", category: "framework", name: "Bootstrap" },
        { pattern: "cdn.jsdelivr.net/npm/bootstrap", category: "framework", name: "Bootstrap" },
        { pattern: "stackpath.bootstrapcdn.com", category: "framework", name: "Bootstrap" },
        { pattern: "foundation.min.js", category: "framework", name: "Foundation" },
        { pattern: "cdn.jsdelivr.net/npm/foundation-sites", category: "framework", name: "Foundation" },
        { pattern: "material-ui", category: "framework", name: "Material UI" },
        { pattern: "@mui/material", category: "framework", name: "Material UI" },
        { pattern: "googletagmanager.com", category: "analytics", name: "Google Tag Manager" },
        { pattern: "google-analytics.com", category: "analytics", name: "Google Analytics" },
        { pattern: "gtag/js", category: "analytics", name: "Google Analytics" },
        { pattern: "googletagservices.com", category: "analytics", name: "Google Analytics" },
        { pattern: "connect.facebook.net", category: "analytics", name: "Facebook Pixel" },
        { pattern: "hotjar.com", category: "analytics", name: "Hotjar" },
        { pattern: "cdn.mxpnl.com", category: "analytics", name: "Mixpanel" },
        { pattern: "cdn.segment.com", category: "analytics", name: "Segment" },
        { pattern: "cdn.heapanalytics.com", category: "analytics", name: "Heap" },
        { pattern: "cdn.amplitude.com", category: "analytics", name: "Amplitude" },
        { pattern: "plausible.io", category: "analytics", name: "Plausible" },
        { pattern: "matomo.", category: "analytics", name: "Matomo" },
        { pattern: "clarity.ms", category: "analytics", name: "Clarity" }
      ];
      var scripts = document.scripts || [];
      for (var si = 0; si < scripts.length; si++) {
        var sSrc = (scripts[si].src || "").toLowerCase();
        if (!sSrc) continue;
        for (var sp = 0; sp < scriptPatterns.length; sp++) {
          if (sSrc.indexOf(scriptPatterns[sp].pattern) !== -1) {
            emit(scriptPatterns[sp].category, scriptPatterns[sp].name, null, "script src");
          }
        }
      }

      /* ── Stylesheet URL patterns ──────────────────────────────── */

      var cssPatterns = [
        { pattern: "wp-content/", category: "cms", name: "WordPress" },
        { pattern: "wp-includes/", category: "cms", name: "WordPress" },
        { pattern: "cdn.shopify.com", category: "cms", name: "Shopify" },
        { pattern: "squarespace.com", category: "cms", name: "Squarespace" },
        { pattern: "static.wixstatic.com", category: "cms", name: "Wix" },
        { pattern: "webflow.com", category: "cms", name: "Webflow" },
        { pattern: "bootstrap.min.css", category: "framework", name: "Bootstrap" },
        { pattern: "stackpath.bootstrapcdn.com", category: "framework", name: "Bootstrap" },
        { pattern: "cdn.jsdelivr.net/npm/bootstrap", category: "framework", name: "Bootstrap" },
        { pattern: "foundation.min.css", category: "framework", name: "Foundation" },
        { pattern: "tailwindcss", category: "framework", name: "Tailwind CSS" }
      ];
      var links = document.querySelectorAll('link[rel="stylesheet"]');
      for (var li = 0; li < links.length; li++) {
        var lHref = (links[li].href || "").toLowerCase();
        if (!lHref) continue;
        for (var lp = 0; lp < cssPatterns.length; lp++) {
          if (lHref.indexOf(cssPatterns[lp].pattern) !== -1) {
            emit(cssPatterns[lp].category, cssPatterns[lp].name, null, "link href");
          }
        }
      }

      /* ── Tailwind detection via class heuristic ───────────────── */

      try {
        var twClasses = document.querySelectorAll("[class*='flex '], [class*='grid '], [class*='text-'], [class*='bg-'], [class*='px-'], [class*='py-'], [class*='mt-'], [class*='mb-']");
        if (twClasses.length >= 5) emit("framework", "Tailwind CSS", null, "DOM classes heuristic");
      } catch (eTW) { /* ignore */ }

      /* ── Webpack detection via chunk comments/globals ──────────── */

      try {
        if (window.webpackJsonp || window.__webpack_require__ || window.webpackChunk) emit("framework", "Webpack", null, "window global");
      } catch (eWP) { /* ignore */ }

      /* ── Version extraction from script URLs ──────────────────── */

      try {
        var versionRe = /[\/\-@]([\d]+\.[\d]+\.[\d]+(?:[.\-][\w]+)?)\b/;
        var versionTargets = {
          "jquery": "jQuery", "vue": "Vue", "angular": "Angular", "angularjs": "AngularJS",
          "react": "React", "preact": "Preact", "ember": "Ember", "backbone": "Backbone",
          "lodash": "Lodash", "underscore": "Underscore", "bootstrap": "Bootstrap",
          "alpine": "Alpine.js", "htmx": "HTMX", "lit": "Lit", "svelte": "Svelte"
        };
        for (var vi = 0; vi < scripts.length; vi++) {
          var vSrc = (scripts[vi].src || "").toLowerCase();
          if (!vSrc) continue;
          var vtKeys = Object.keys(versionTargets);
          for (var vk = 0; vk < vtKeys.length; vk++) {
            if (vSrc.indexOf(vtKeys[vk]) !== -1) {
              var vMatch = vSrc.match(versionRe);
              if (vMatch && vMatch[1] && found[versionTargets[vtKeys[vk]]]) {
                postRedteamToOverlay({
                  source: "boxedin-page-guard",
                  type: "tech-version",
                  name: versionTargets[vtKeys[vk]],
                  version: vMatch[1]
                });
              }
            }
          }
        }
      } catch (eVE) { /* ignore */ }

    } catch (e) { /* ignore */ }
  }

  function scanApiEndpoints() {
    try {
      var found = {};
      var API_PATH_RE = /\/api\/|\/v[0-9]+\/|\/graphql|\/rest\/|\/webhook/i;

      function emit(method, url, origin, context) {
        var key = (method || "?") + " " + url;
        if (found[key]) return;
        found[key] = true;
        postRedteamToOverlay({
          source: "boxedin-page-guard",
          type: "api",
          method: method || "unknown",
          url: url,
          origin: origin,
          context: context || ""
        });
      }

      /* Layer 1 — Inline script body regex */

      var scripts = document.scripts || [];
      var fetchRe = /fetch\s*\(\s*["'`]([^"'`\s]{4,200})["'`]/g;
      var axiosRe = /axios\s*\.\s*(get|post|put|delete|patch)\s*\(\s*["'`]([^"'`\s]{4,200})["'`]/gi;
      var ajaxUrlRe = /\$\s*\.\s*ajax\s*\(\s*\{[^}]*url\s*:\s*["'`]([^"'`\s]{4,200})["'`]/g;
      var jqShortRe = /\$\s*\.\s*(get|post)\s*\(\s*["'`]([^"'`\s]{4,200})["'`]/gi;
      var xhrOpenRe = /\.open\s*\(\s*["'`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["'`]\s*,\s*["'`]([^"'`\s]{4,200})["'`]/gi;
      var restLiteralRe = /["'`]((?:https?:\/\/[^\s"'`]{4,180})?\/(?:api|v[0-9]+|graphql|rest|webhook)[^\s"'`]{0,180})["'`]/gi;

      for (var si = 0; si < scripts.length; si++) {
        if (scripts[si].src) continue;
        var text = scripts[si].textContent || "";
        if (text.length < 20) continue;
        var m;

        fetchRe.lastIndex = 0;
        while ((m = fetchRe.exec(text)) !== null) {
          emit("GET", m[1], "inline", "fetch(\"" + m[1].slice(0, 60) + "\")");
        }
        axiosRe.lastIndex = 0;
        while ((m = axiosRe.exec(text)) !== null) {
          emit(m[1].toUpperCase(), m[2], "inline", "axios." + m[1] + "(\"" + m[2].slice(0, 60) + "\")");
        }
        ajaxUrlRe.lastIndex = 0;
        while ((m = ajaxUrlRe.exec(text)) !== null) {
          emit("unknown", m[1], "inline", "$.ajax({url: \"" + m[1].slice(0, 60) + "\"})");
        }
        jqShortRe.lastIndex = 0;
        while ((m = jqShortRe.exec(text)) !== null) {
          emit(m[1].toUpperCase(), m[2], "inline", "$." + m[1] + "(\"" + m[2].slice(0, 60) + "\")");
        }
        xhrOpenRe.lastIndex = 0;
        while ((m = xhrOpenRe.exec(text)) !== null) {
          emit(m[1].toUpperCase(), m[2], "inline", ".open(\"" + m[1] + "\", \"" + m[2].slice(0, 60) + "\")");
        }
        restLiteralRe.lastIndex = 0;
        while ((m = restLiteralRe.exec(text)) !== null) {
          emit("unknown", m[1], "inline", "string literal");
        }
      }

      /* Layer 2 — Window config object probing */

      var configKeys = [
        "__CONFIG__", "__APP_CONFIG__", "__SETTINGS__", "ENV", "__ENV__",
        "config", "appConfig", "settings"
      ];
      var configUrlRe = /^https?:\/\//;

      function scanConfigValue(val, source) {
        if (typeof val === "string" && val.length > 3 && val.length < 500) {
          if (configUrlRe.test(val) || API_PATH_RE.test(val)) {
            emit("unknown", val, "config", source);
          }
        }
      }

      function scanConfigObj(obj, source) {
        if (!obj || typeof obj !== "object") return;
        try {
          var keys = Object.keys(obj);
          for (var ki = 0; ki < keys.length && ki < 100; ki++) {
            try { scanConfigValue(obj[keys[ki]], source + "." + keys[ki]); } catch (eV) { /* ignore */ }
          }
        } catch (eK) { /* ignore */ }
      }

      for (var ci = 0; ci < configKeys.length; ci++) {
        try {
          var cObj = window[configKeys[ci]];
          if (cObj && typeof cObj === "object") scanConfigObj(cObj, "window." + configKeys[ci]);
          else if (typeof cObj === "string") scanConfigValue(cObj, "window." + configKeys[ci]);
        } catch (eC) { /* ignore */ }
      }
      try {
        if (window.__NEXT_DATA__ && window.__NEXT_DATA__.props) {
          scanConfigObj(window.__NEXT_DATA__.props, "window.__NEXT_DATA__.props");
        }
      } catch (eNext) { /* ignore */ }
      try {
        if (window.__NUXT__ && typeof window.__NUXT__ === "object") {
          scanConfigObj(window.__NUXT__, "window.__NUXT__");
        }
      } catch (eNuxt) { /* ignore */ }
      try {
        if (window.__remixContext && typeof window.__remixContext === "object") {
          scanConfigObj(window.__remixContext, "window.__remixContext");
        }
      } catch (eRemix) { /* ignore */ }

      /* Layer 3 — DOM attribute scan */

      try {
        var forms = document.querySelectorAll("form[action]");
        for (var fi = 0; fi < forms.length; fi++) {
          var action = forms[fi].getAttribute("action") || "";
          if (action && API_PATH_RE.test(action)) {
            var fMethod = (forms[fi].method || "GET").toUpperCase();
            emit(fMethod, action, "dom", "<form action=\"" + action.slice(0, 60) + "\">");
          }
        }
      } catch (eF) { /* ignore */ }
      try {
        var apiAttrs = document.querySelectorAll("[data-api-url], [data-api-endpoint], [data-url], [data-endpoint]");
        for (var ai = 0; ai < apiAttrs.length; ai++) {
          var el = apiAttrs[ai];
          var attrNames = ["data-api-url", "data-api-endpoint", "data-url", "data-endpoint"];
          for (var ati = 0; ati < attrNames.length; ati++) {
            var av = el.getAttribute(attrNames[ati]);
            if (av && (API_PATH_RE.test(av) || configUrlRe.test(av))) {
              emit("unknown", av, "dom", attrNames[ati] + "=\"" + av.slice(0, 60) + "\"");
            }
          }
        }
      } catch (eA) { /* ignore */ }
      try {
        var anchors = document.querySelectorAll("a[href]");
        for (var ali = 0; ali < anchors.length; ali++) {
          var href = anchors[ali].getAttribute("href") || "";
          if (href && API_PATH_RE.test(href)) {
            emit("GET", href, "dom", "<a href=\"" + href.slice(0, 60) + "\">");
          }
        }
      } catch (eL) { /* ignore */ }

      /* Layer 5 — Script src path patterns */

      for (var ssi = 0; ssi < scripts.length; ssi++) {
        var sSrc = scripts[ssi].src || "";
        if (sSrc && API_PATH_RE.test(sSrc)) {
          emit("GET", sSrc, "script-src", "<script src=\"" + sSrc.slice(0, 60) + "\">");
        }
      }

    } catch (e) { /* ignore */ }
  }

  function scanSubdomains() {
    try {
      var pageDomain = window.location.hostname.toLowerCase();
      if (!pageDomain) return;
      var parts = pageDomain.split(".");
      var baseDomain = parts.length >= 2 ? parts.slice(-2).join(".") : pageDomain;
      var seen = {};
      seen[pageDomain] = true;
      var subdomains = [];
      var selectors = "a[href],link[href],script[src],img[src],iframe[src],video[src],source[src],object[data]";
      var els = document.querySelectorAll(selectors);
      for (var i = 0; i < els.length; i++) {
        var attr = els[i].src || els[i].href || els[i].getAttribute("data") || "";
        if (!attr) continue;
        try {
          var u = new URL(attr, window.location.href);
          var h = u.hostname.toLowerCase();
          if (h && h !== pageDomain && h.endsWith("." + baseDomain) && !seen[h]) {
            seen[h] = true;
            subdomains.push(h);
          }
        } catch (eU) { /* ignore */ }
      }
      var scripts = document.querySelectorAll("script:not([src])");
      var urlRe = /https?:\/\/([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*)/gi;
      for (var si = 0; si < scripts.length; si++) {
        var text = scripts[si].textContent || "";
        if (text.length > 200000) text = text.slice(0, 200000);
        var m;
        urlRe.lastIndex = 0;
        while ((m = urlRe.exec(text)) !== null) {
          var host = m[1].toLowerCase();
          if (host !== pageDomain && host.endsWith("." + baseDomain) && !seen[host]) {
            seen[host] = true;
            subdomains.push(host);
          }
        }
      }
      if (subdomains.length > 0) {
        postRedteamToOverlay({
          source: "boxedin-page-guard",
          type: "recon",
          subtype: "subdomains",
          subdomains: subdomains,
          baseDomain: baseDomain
        });
      }
    } catch (e) { /* ignore */ }
  }

  function scanSourceMaps() {
    try {
      var findings = [];
      var scripts = document.querySelectorAll("script[src]");
      for (var i = 0; i < scripts.length; i++) {
        var src = scripts[i].src || "";
        if (src.endsWith(".map") || src.indexOf(".map?") !== -1) {
          findings.push({ type: "external-map-file", url: src.slice(0, 200) });
        }
      }
      var inlineScripts = document.querySelectorAll("script:not([src])");
      var mapRe = /\/[\/\*][#@]\s*sourceMappingURL\s*=\s*(\S+)/g;
      for (var si = 0; si < inlineScripts.length; si++) {
        var text = inlineScripts[si].textContent || "";
        if (text.length > 200000) text = text.slice(0, 200000);
        var m;
        mapRe.lastIndex = 0;
        while ((m = mapRe.exec(text)) !== null) {
          findings.push({ type: "inline-sourcemap-url", url: m[1].slice(0, 200) });
        }
      }
      var linkEls = document.querySelectorAll("link[rel='sourcemap'], link[rel='x-sourcemap']");
      for (var li = 0; li < linkEls.length; li++) {
        var href = linkEls[li].href || "";
        if (href) findings.push({ type: "link-sourcemap", url: href.slice(0, 200) });
      }
      if (findings.length > 0) {
        postRedteamToOverlay({
          source: "boxedin-page-guard",
          type: "recon",
          subtype: "sourcemaps",
          findings: findings
        });
      }
    } catch (e) { /* ignore */ }
  }

  function scanOpenRedirects() {
    try {
      var params = new URLSearchParams(window.location.search);
      var redirectNames = /^(redirect|next|url|return|returnUrl|returnTo|goto|destination|target|continue|redir|forward|out|link|to)$/i;
      var findings = [];
      params.forEach(function (val, key) {
        if (redirectNames.test(key) && val.length > 1) {
          if (/^https?:\/\//i.test(val) || /^\/\//.test(val) || /^\/[^\/]/.test(val)) {
            findings.push({ param: key, value: val.slice(0, 200) });
          }
        }
      });
      if (findings.length > 0) {
        postRedteamToOverlay({
          source: "boxedin-page-guard",
          type: "inject",
          subtype: "open-redirect",
          findings: findings
        });
      }
    } catch (e) { /* ignore */ }
  }

  function scanMixedContent() {
    try {
      if (window.location.protocol !== "https:") return;
      var findings = [];
      var seen = {};
      var selectors = "script[src],img[src],link[href],iframe[src],video[src],source[src],audio[src],object[data],embed[src]";
      var els = document.querySelectorAll(selectors);
      for (var i = 0; i < els.length; i++) {
        var attr = els[i].src || els[i].href || els[i].getAttribute("data") || "";
        if (!attr) continue;
        if (/^http:\/\//i.test(attr) && !seen[attr]) {
          seen[attr] = true;
          findings.push({
            tag: els[i].tagName.toLowerCase(),
            url: attr.slice(0, 200)
          });
        }
      }
      if (findings.length > 0) {
        postRedteamToOverlay({
          source: "boxedin-page-guard",
          type: "inject",
          subtype: "mixed-content",
          findings: findings
        });
      }
    } catch (e) { /* ignore */ }
  }

  function scanExposedSecrets() {
    try {
      var patterns = [
        { name: "AWS Access Key", re: /AKIA[0-9A-Z]{16}/g },
        { name: "AWS Secret Key", re: /(?:aws.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]/g, refine: /[0-9a-zA-Z\/+]{40}/ },
        { name: "Google API Key", re: /AIza[0-9A-Za-z_-]{35}/g },
        { name: "Google OAuth", re: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g },
        { name: "Stripe Secret Key", re: /sk_live_[0-9a-zA-Z]{24,}/g },
        { name: "Stripe Publishable Key", re: /pk_live_[0-9a-zA-Z]{24,}/g },
        { name: "Slack Token", re: /xox[bpsa]-[0-9]{10,}-[0-9a-zA-Z-]+/g },
        { name: "Slack Webhook", re: /hooks\.slack\.com\/services\/T[0-9A-Z]{8,}\/B[0-9A-Z]{8,}\/[0-9a-zA-Z]{20,}/g },
        { name: "GitHub Token", re: /gh[ps]_[A-Za-z0-9_]{36,}/g },
        { name: "GitHub PAT", re: /github_pat_[A-Za-z0-9_]{20,}/g },
        { name: "Private Key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
        { name: "Mailgun API Key", re: /key-[0-9a-zA-Z]{32}/g },
        { name: "Twilio API Key", re: /SK[0-9a-fA-F]{32}/g },
        { name: "SendGrid API Key", re: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/g },
        { name: "Firebase API Key", re: /AIza[0-9A-Za-z_-]{35}/g },
        { name: "Heroku API Key", re: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g, context: "heroku" },
        { name: "Generic Bearer Token", re: /bearer\s+[A-Za-z0-9_\-.~+\/]{20,}/gi }
      ];
      var findings = [];
      var seen = {};
      var scripts = document.querySelectorAll("script:not([src])");
      var texts = [];
      for (var si = 0; si < scripts.length; si++) {
        var t = scripts[si].textContent || "";
        if (t.length > 300000) t = t.slice(0, 300000);
        texts.push(t);
      }
      var metaTags = document.querySelectorAll("meta[content]");
      for (var mi = 0; mi < metaTags.length; mi++) {
        texts.push(metaTags[mi].getAttribute("content") || "");
      }
      for (var ti = 0; ti < texts.length; ti++) {
        for (var pi = 0; pi < patterns.length; pi++) {
          var pat = patterns[pi];
          pat.re.lastIndex = 0;
          var m;
          while ((m = pat.re.exec(texts[ti])) !== null) {
            var match = m[0];
            if (pat.context === "heroku" && !/heroku/i.test(texts[ti].slice(Math.max(0, m.index - 40), m.index))) continue;
            var key = pat.name + ":" + match.slice(0, 30);
            if (!seen[key]) {
              seen[key] = true;
              findings.push({
                name: pat.name,
                preview: match.slice(0, 30) + (match.length > 30 ? "..." : ""),
                location: "inline-script"
              });
            }
            if (findings.length >= 50) break;
          }
          if (findings.length >= 50) break;
        }
        if (findings.length >= 50) break;
      }
      if (findings.length > 0) {
        postRedteamToOverlay({
          source: "boxedin-page-guard",
          type: "auth",
          subtype: "exposed-secret",
          findings: findings
        });
      }
    } catch (e) { /* ignore */ }
  }

  function scanFormFields() {
    try {
      var forms = document.querySelectorAll("form");
      var findings = [];
      for (var fi = 0; fi < forms.length; fi++) {
        var form = forms[fi];
        var formInfo = {
          action: (form.action || window.location.href).slice(0, 200),
          method: (form.method || "GET").toUpperCase(),
          id: form.id || null,
          name: form.name || null,
          fields: []
        };
        var inputs = form.querySelectorAll("input, select, textarea");
        for (var ii = 0; ii < inputs.length; ii++) {
          var inp = inputs[ii];
          var fieldType = inp.type || inp.tagName.toLowerCase();
          if (fieldType === "hidden" || fieldType === "submit" || fieldType === "button") continue;
          formInfo.fields.push({
            tag: inp.tagName.toLowerCase(),
            type: fieldType,
            name: inp.name || null,
            id: inp.id || null,
            autocomplete: inp.getAttribute("autocomplete") || null,
            required: inp.required || false,
            pattern: inp.getAttribute("pattern") || null
          });
        }
        if (formInfo.fields.length > 0) {
          findings.push(formInfo);
        }
      }
      var standaloneInputs = [];
      var allInputs = document.querySelectorAll("input:not(form input), textarea:not(form textarea)");
      for (var si = 0; si < allInputs.length; si++) {
        var sInp = allInputs[si];
        if (sInp.closest("form")) continue;
        var sType = sInp.type || sInp.tagName.toLowerCase();
        if (sType === "hidden" || sType === "submit" || sType === "button") continue;
        standaloneInputs.push({
          tag: sInp.tagName.toLowerCase(),
          type: sType,
          name: sInp.name || null,
          id: sInp.id || null,
          autocomplete: sInp.getAttribute("autocomplete") || null
        });
      }
      if (findings.length > 0 || standaloneInputs.length > 0) {
        postRedteamToOverlay({
          source: "boxedin-page-guard",
          type: "inject",
          subtype: "form-inventory",
          forms: findings,
          standaloneInputs: standaloneInputs
        });
      }
    } catch (e) { /* ignore */ }
  }

  function scanDependencies() {
    try {
      var pageDomain = window.location.hostname.toLowerCase();
      var findings = [];
      var seen = {};
      var scripts = document.querySelectorAll("script[src]");
      for (var i = 0; i < scripts.length; i++) {
        var src = scripts[i].src || "";
        if (!src || seen[src]) continue;
        seen[src] = true;
        try {
          var u = new URL(src, window.location.href);
          var host = u.hostname.toLowerCase();
          var isThirdParty = host !== pageDomain;
          findings.push({
            type: "script",
            url: src.slice(0, 300),
            host: host,
            thirdParty: isThirdParty,
            sri: scripts[i].getAttribute("integrity") || null,
            crossorigin: scripts[i].getAttribute("crossorigin") || null,
            async: scripts[i].async || false,
            defer: scripts[i].defer || false
          });
        } catch (eU) { /* ignore */ }
      }
      var links = document.querySelectorAll("link[rel='stylesheet'][href]");
      for (var li = 0; li < links.length; li++) {
        var href = links[li].href || "";
        if (!href || seen[href]) continue;
        seen[href] = true;
        try {
          var lu = new URL(href, window.location.href);
          var lHost = lu.hostname.toLowerCase();
          findings.push({
            type: "stylesheet",
            url: href.slice(0, 300),
            host: lHost,
            thirdParty: lHost !== pageDomain,
            sri: links[li].getAttribute("integrity") || null,
            crossorigin: links[li].getAttribute("crossorigin") || null
          });
        } catch (eL) { /* ignore */ }
      }
      if (findings.length > 0) {
        postRedteamToOverlay({
          source: "boxedin-page-guard",
          type: "deps",
          findings: findings
        });
      }
    } catch (e) { /* ignore */ }
  }

  function runRedteamScans() {
    if (redteamScansActive) return;
    var g = ensureGuard();
    if (!g.redteamEnabled) return;
    redteamScansActive = true;
    scanStorage();
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", function () {
        scanReflectedParams();
        scanCsrfTokens();
        scanTechStack();
        scanApiEndpoints();
        scanSubdomains();
        scanSourceMaps();
        scanOpenRedirects();
        scanMixedContent();
        scanExposedSecrets();
        scanFormFields();
        scanDependencies();
      });
    } else {
      scanReflectedParams();
      scanCsrfTokens();
      scanTechStack();
      scanApiEndpoints();
      scanSubdomains();
      scanSourceMaps();
      scanOpenRedirects();
      scanMixedContent();
      scanExposedSecrets();
      scanFormFields();
      scanDependencies();
    }
    hookExfilApis();
    observeXssSinks();
  }

  function scanStorage() {
    try {
      var findings = [];
      var jwtRe = /^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/;
      var apiKeyRe = /^(sk-|pk-|AKIA|ghp_|gho_|github_pat_)[A-Za-z0-9_-]{10,}/;
      var stores = [];
      try { if (window.localStorage) stores.push({ name: "localStorage", s: window.localStorage }); } catch (e) {}
      try { if (window.sessionStorage) stores.push({ name: "sessionStorage", s: window.sessionStorage }); } catch (e) {}
      for (var si = 0; si < stores.length; si++) {
        var store = stores[si];
        try {
          for (var ki = 0; ki < store.s.length; ki++) {
            var key = store.s.key(ki);
            var val = store.s.getItem(key) || "";
            if (jwtRe.test(val)) {
              findings.push({ store: store.name, key: key, issue: "JWT token in " + store.name, preview: val.slice(0, 40) + "..." });
            } else if (apiKeyRe.test(val)) {
              findings.push({ store: store.name, key: key, issue: "API key pattern in " + store.name, preview: val.slice(0, 20) + "..." });
            }
          }
        } catch (eS) { /* ignore */ }
      }
      if (findings.length > 0) {
        postRedteamToOverlay({
          source: "boxedin-page-guard",
          type: "auth",
          subtype: "storage-sensitive",
          findings: findings
        });
      }
    } catch (e) { /* ignore */ }
  }

  function scanReflectedParams() {
    try {
      var params = new URLSearchParams(window.location.search);
      var frag = window.location.hash.slice(1);
      var body = document.body ? document.body.innerHTML : "";
      if (!body) return;
      var findings = [];
      params.forEach(function (val, key) {
        if (val.length >= 4 && body.indexOf(val) !== -1) {
          findings.push({ param: key, value: val.slice(0, 60), context: "query" });
        }
      });
      if (frag.length >= 4 && body.indexOf(frag) !== -1) {
        findings.push({ param: "#fragment", value: frag.slice(0, 60), context: "fragment" });
      }
      if (findings.length > 0) {
        postRedteamToOverlay({
          source: "boxedin-page-guard",
          type: "inject",
          subtype: "reflected-param",
          findings: findings
        });
      }
    } catch (e) { /* ignore */ }
  }

  function scanCsrfTokens() {
    try {
      var forms = document.querySelectorAll("form");
      var findings = [];
      var csrfNames = /csrf|_token|authenticity_token|__RequestVerificationToken|antiforgery/i;
      for (var fi = 0; fi < forms.length; fi++) {
        var form = forms[fi];
        var method = (form.method || "GET").toUpperCase();
        if (method === "GET") continue;
        var hasToken = false;
        var inputs = form.querySelectorAll("input[type=hidden]");
        for (var ii = 0; ii < inputs.length; ii++) {
          if (csrfNames.test(inputs[ii].name || "")) { hasToken = true; break; }
        }
        if (!hasToken) {
          findings.push({
            action: form.action || window.location.href,
            method: method,
            id: form.id || null
          });
        }
      }
      if (findings.length > 0) {
        postRedteamToOverlay({
          source: "boxedin-page-guard",
          type: "inject",
          subtype: "csrf-missing",
          findings: findings
        });
      }
    } catch (e) { /* ignore */ }
  }

  function hookExfilApis() {
    try {
      if (navigator.clipboard) {
        var origWrite = navigator.clipboard.writeText;
        if (typeof origWrite === "function") {
          navigator.clipboard.writeText = function (text) {
            postRedteamToOverlay({
              source: "boxedin-page-guard",
              type: "exfil",
              subtype: "clipboard-write",
              size: text ? text.length : 0,
              preview: text ? text.slice(0, 80) : "",
              ts: Date.now()
            });
            return origWrite.apply(this, arguments);
          };
        }
        var origRead = navigator.clipboard.readText;
        if (typeof origRead === "function") {
          navigator.clipboard.readText = function () {
            postRedteamToOverlay({
              source: "boxedin-page-guard",
              type: "exfil",
              subtype: "clipboard-read",
              ts: Date.now()
            });
            return origRead.apply(this, arguments);
          };
        }
      }
    } catch (e) { /* ignore */ }

    try {
      var OrigWS = window.WebSocket;
      if (typeof OrigWS === "function") {
        window.WebSocket = function (url, protocols) {
          postRedteamToOverlay({
            source: "boxedin-page-guard",
            type: "exfil",
            subtype: "websocket",
            url: String(url).slice(0, 200),
            ts: Date.now()
          });
          if (protocols !== undefined) return new OrigWS(url, protocols);
          return new OrigWS(url);
        };
        window.WebSocket.prototype = OrigWS.prototype;
        window.WebSocket.CONNECTING = OrigWS.CONNECTING;
        window.WebSocket.OPEN = OrigWS.OPEN;
        window.WebSocket.CLOSING = OrigWS.CLOSING;
        window.WebSocket.CLOSED = OrigWS.CLOSED;
      }
    } catch (e) { /* ignore */ }

    try {
      var origSubmit = HTMLFormElement.prototype.submit;
      HTMLFormElement.prototype.submit = function () {
        postRedteamToOverlay({
          source: "boxedin-page-guard",
          type: "exfil",
          subtype: "form-submit",
          action: (this.action || "").slice(0, 200),
          method: this.method || "GET",
          ts: Date.now()
        });
        return origSubmit.apply(this, arguments);
      };
    } catch (e) { /* ignore */ }
  }

  function observeXssSinks() {
    try {
      var origDocWrite = document.write;
      document.write = function () {
        var content = arguments.length > 0 ? String(arguments[0]) : "";
        if (/<script|on\w+\s*=/i.test(content)) {
          postRedteamToOverlay({
            source: "boxedin-page-guard",
            type: "inject",
            subtype: "xss-sink",
            sink: "document.write",
            preview: content.slice(0, 120),
            ts: Date.now()
          });
        }
        return origDocWrite.apply(this, arguments);
      };
    } catch (e) { /* ignore */ }

    try {
      var origEval = window.eval;
      window.eval = function (code) {
        postRedteamToOverlay({
          source: "boxedin-page-guard",
          type: "inject",
          subtype: "xss-sink",
          sink: "eval",
          preview: String(code || "").slice(0, 120),
          ts: Date.now()
        });
        return origEval.apply(this, arguments);
      };
    } catch (e) { /* ignore */ }
  }

  window.addEventListener("message", function (ev) {
    try {
      var data = ev.data;
      if (!data || data.source !== "boxedin-overlay") return;
      if (data.type === "enable-redteam") {
        var g2 = ensureGuard();
        g2.redteamEnabled = true;
        runRedteamScans();
      }
    } catch (e) { /* ignore */ }
  });

  log(
    "active — " +
      LOG_PREFIX +
      "; extension-scheme blocks silent (stats in " +
      "__extensionProbeGuard.stats; set verboseExtensionBlocking = true " +
      "for per-URL logs)"
  );
})();
