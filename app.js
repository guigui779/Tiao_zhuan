(function () {
  "use strict";

  /* ===== 配置 ===== */
  var CFG = {
    configUrl: "/api/config",
    probeTimeout: 2000,
    graceMs: 300,
    cacheKey: "_jc_v4",
    cacheTTL: 300000,
    countdown: 3,
    maxRetry: 3
  };

  var DEFAULTS = {
    wildcard: { enabled: true, baseDomain: "", candidateCount: 6, labelLength: 3 },
    probeAssets: [],
    probeAssetThreshold: 2,
    domains: [],
    siteName: ""
  };

  /* ===== DOM ===== */
  var $ = function (id) { return document.getElementById(id); };

  /* ===== 工具 ===== */
  function deepCopy(o) { return JSON.parse(JSON.stringify(o)); }

  function randomLabel(len) {
    var c = "abcdefghijklmnopqrstuvwxyz0123456789", r = "";
    for (var i = 0; i < len; i++) r += c.charAt(Math.floor(Math.random() * c.length));
    return r;
  }

  function normalizeConfig(src) {
    var r = deepCopy(DEFAULTS);
    if (!src) return r;
    if (src.wildcard) {
      r.wildcard.enabled = src.wildcard.enabled !== false;
      r.wildcard.baseDomain = src.wildcard.baseDomain || "";
      r.wildcard.candidateCount = parseInt(src.wildcard.candidateCount, 10) || 6;
      r.wildcard.labelLength = parseInt(src.wildcard.labelLength, 10) || 3;
    }
    if (src.domains && src.domains.length) r.domains = src.domains.slice();
    if (src.probeAssets && src.probeAssets.length) r.probeAssets = src.probeAssets.slice();
    if (src.probeAssetThreshold) r.probeAssetThreshold = parseInt(src.probeAssetThreshold, 10) || 2;
    if (src.siteName) r.siteName = src.siteName;
    return r;
  }

  /* ===== 缓存 ===== */
  function getCache() {
    try {
      var raw = localStorage.getItem(CFG.cacheKey);
      if (!raw) return null;
      var o = JSON.parse(raw);
      if (o && o.url && o.ts && (Date.now() - o.ts < CFG.cacheTTL)) return o;
    } catch (e) {}
    return null;
  }

  function setCache(url) {
    try { localStorage.setItem(CFG.cacheKey, JSON.stringify({ url: url, ts: Date.now() })); } catch (e) {}
  }

  /* ===== DNS 预解析 ===== */
  function dnsPrefetch(host) {
    var link = document.createElement("link");
    link.rel = "dns-prefetch";
    link.href = "//" + host;
    document.head.appendChild(link);
  }

  /* ===== 候选域名生成 ===== */
  function buildWildcardDomains(cfg) {
    var wc = cfg.wildcard || {};
    var base = wc.baseDomain || "";
    if (!base) return [];
    var count = parseInt(wc.candidateCount, 10) || 6;
    var len = parseInt(wc.labelLength, 10) || 3;
    var domains = [], used = {}, attempts = 0;
    while (domains.length < count && attempts < count * 8) {
      attempts++;
      var label = randomLabel(len);
      var url = "https://" + label + "." + base;
      if (used[url]) continue;
      used[url] = true;
      domains.push({ url: url, name: "线路" + (domains.length + 1), src: "wildcard" });
    }
    return domains;
  }

  function resolveDomains(cfg) {
    if (cfg.domains && cfg.domains.length) return cfg.domains;
    if (cfg.wildcard && cfg.wildcard.enabled) return buildWildcardDomains(cfg);
    return [];
  }

  /* ===== 探测 ===== */
  function probeAsset(url, timeout, cb) {
    var img = new Image(), done = false;
    var timer = setTimeout(function () { if (!done) { done = true; img.src = ""; cb(false); } }, timeout);
    function fin(ok) { if (done) return; done = true; clearTimeout(timer); cb(ok); }
    img.onload = function () { fin(true); };
    img.onerror = function () { fin(false); };
    img.src = url;
  }

  function checkDomain(domain, cfg, cb) {
    var start = Date.now();
    var base = domain.url.replace(/\/+$/, "");
    var assets = (cfg.probeAssets && cfg.probeAssets.length) ? cfg.probeAssets : [];
    var threshold = parseInt(cfg.probeAssetThreshold, 10) || 2;
    if (!assets.length) { cb(false, 0); return; }

    var state = { done: false, okCount: 0, total: 0 };
    var timer = setTimeout(function () { finish(false, 0); }, CFG.probeTimeout);

    function finish(ok, lat) {
      if (state.done) return;
      state.done = true;
      clearTimeout(timer);
      cb(ok, lat || 0);
    }

    function evaluate() {
      if (state.done) return;
      if (state.okCount >= threshold) { finish(true, Date.now() - start); return; }
      if (state.total === assets.length && state.okCount < threshold) finish(false, 0);
    }

    assets.forEach(function (path) {
      probeAsset(base + path + "?_=" + Date.now(), CFG.probeTimeout - 500, function (ok) {
        state.total++;
        if (ok) state.okCount++;
        evaluate();
      });
    });
  }

  /* ===== UI 辅助 ===== */
  function setStatus(text) { $("statusText").textContent = text; }
  function showSpinner(v) { $("spinnerWrap").style.display = v ? "" : "none"; }

  function renderLines(domains) {
    var ul = $("lineList");
    ul.innerHTML = "";
    domains.forEach(function (d, i) {
      var li = document.createElement("li");
      li.id = "l-" + i;
      li.innerHTML = '<span class="line-name">' + d.name + '</span><span class="line-status checking" id="s-' + i + '">检测中</span>';
      ul.appendChild(li);
    });
  }

  function updateLine(i, ok, lat) {
    var s = $("s-" + i);
    if (!s) return;
    s.className = "line-status " + (ok ? "ok" : "fail");
    s.textContent = ok ? (lat + "ms") : "超时";
    var li = $("l-" + i);
    if (li) li.className = ok ? "ok" : "fail";
  }

  function markBest(i) {
    var li = $("l-" + i);
    if (li) li.className = "ok best";
  }

  function bindClick(i, url) {
    var li = $("l-" + i);
    if (li) li.onclick = function () { jumpTo(url); };
  }

  function showFallback(cfg) {
    $("mainContent").className = "hide";
    $("fallbackContent").className = "";
  }

  /* ===== 跳转 ===== */
  function jumpTo(url) {
    setCache(url);
    setStatus("正在获取访问凭证...");
    var xhr = new XMLHttpRequest();
    xhr.open("GET", "/api/gate-token", true);
    xhr.timeout = 2000;
    xhr.onload = function () {
      var tk = "";
      try { var d = JSON.parse(xhr.responseText); tk = d.token || ""; } catch (e) {}
      var sep = url.indexOf("?") >= 0 ? "&" : "?";
      window.location.replace(url + sep + "_gate=" + encodeURIComponent(tk));
    };
    xhr.onerror = function () { window.location.replace(url); };
    xhr.ontimeout = xhr.onerror;
    xhr.send();
  }

  /* ===== 倒计时 ===== */
  function startCountdown(results, cfg) {
    var best = results[0];
    var rem = CFG.countdown;
    var cancelled = false;

    showSpinner(false);
    setStatus(rem + " 秒后跳转到最快线路...");
    $("mainActions").className = "actions";
    markBest(best.i);
    results.forEach(function (r) { bindClick(r.i, r.url); });

    $("cancelBtn").onclick = function () {
      cancelled = true;
      clearInterval(iv);
      setStatus("已取消，请手动选择线路");
      $("mainActions").className = "actions hide";
    };

    var iv = setInterval(function () {
      if (cancelled) return;
      rem--;
      if (rem <= 0) { clearInterval(iv); jumpTo(best.url); }
      else setStatus(rem + " 秒后跳转到最快线路...");
    }, 1000);
  }

  /* ===== 全量探测 ===== */
  function startProbe(cfg, retry) {
    retry = retry || 0;
    var domains = resolveDomains(cfg);
    if (!domains.length) { showFallback(cfg); return; }

    showSpinner(true);
    setStatus("正在检测最快线路...");
    renderLines(domains);

    var results = [], done = 0, finished = false, grace = null;

    function doFinish() {
      if (finished) return;
      finished = true;
      if (grace) clearTimeout(grace);
      if (results.length) {
        results.sort(function (a, b) { return a.lat - b.lat; });
        startCountdown(results, cfg);
      }
    }

    domains.forEach(function (d, i) {
      checkDomain(d, cfg, function (ok, lat) {
        done++;
        updateLine(i, ok, lat);
        if (ok) {
          results.push({ url: d.url, name: d.name, lat: lat, i: i });
          bindClick(i, d.url);
          if (!grace) grace = setTimeout(doFinish, CFG.graceMs);
        }
        if (done === domains.length) {
          if (results.length) { doFinish(); }
          else if (retry < CFG.maxRetry) {
            setStatus("重试中 (" + (retry + 1) + "/" + CFG.maxRetry + ")...");
            setTimeout(function () { startProbe(cfg, retry + 1); }, 800);
          } else { showFallback(cfg); }
        }
      });
    });
  }

  /* ===== 配置加载 ===== */
  function loadConfig(cb) {
    var xhr = new XMLHttpRequest();
    xhr.open("GET", CFG.configUrl + "?_=" + Date.now(), true);
    xhr.timeout = 3000;
    xhr.onload = function () {
      if (xhr.status === 200) {
        try { cb(normalizeConfig(JSON.parse(xhr.responseText))); return; } catch (e) {}
      }
      cb(normalizeConfig(null));
    };
    xhr.onerror = function () { cb(normalizeConfig(null)); };
    xhr.ontimeout = xhr.onerror;
    xhr.send();
  }

  /* ===== Token 验证 ===== */
  function getToken() {
    var m = location.search.match(/[?&]token=([^&]+)/);
    return m ? decodeURIComponent(m[1]) : "";
  }

  function verifyToken(token, cb) {
    var xhr = new XMLHttpRequest();
    xhr.open("GET", "/api/verify-token?token=" + encodeURIComponent(token), true);
    xhr.timeout = 3000;
    xhr.onload = function () {
      if (xhr.status === 200) {
        try { var d = JSON.parse(xhr.responseText); cb(d && d.ok); return; } catch (e) {}
      }
      cb(false);
    };
    xhr.onerror = function () { cb(false); };
    xhr.ontimeout = xhr.onerror;
    xhr.send();
  }

  function showDenied() {
    $("mainContent").className = "hide";
    $("fallbackContent").className = "";
    document.querySelector(".fallback-icon").textContent = "\ud83d\udd12";
    document.querySelector(".fallback-title").textContent = "访问受限";
    document.querySelector(".fallback-desc").textContent = "请通过正确链接访问";
    $("contactLinks").innerHTML = "";
  }

  /* ===== 入口 ===== */
  function init() {
    var token = getToken();
    if (!token) { showDenied(); return; }

    setStatus("正在验证访问权限...");
    verifyToken(token, function (ok) {
      if (!ok) { showDenied(); return; }

      // 清除 URL 中的 token 参数
      if (window.history && history.replaceState) {
        history.replaceState(null, "", location.pathname);
      }

      loadConfig(function (cfg) {
        if (cfg.siteName) $("brandName").textContent = cfg.siteName;
        if (cfg.wildcard && cfg.wildcard.baseDomain) dnsPrefetch(cfg.wildcard.baseDomain);

        // 尝试缓存快速通道
        var cached = getCache();
        if (cached) {
          setStatus("快速验证上次线路...");
          checkDomain({ url: cached.url, name: "缓存" }, cfg, function (ok2) {
            if (ok2) jumpTo(cached.url);
            else startProbe(cfg);
          });
        } else {
          startProbe(cfg);
        }
      });
    });
  }

  init();
})();
