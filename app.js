(function () {
  "use strict";

  /* ========== 配置 ========== */
  var _c = {
    u: ["domains.json"],       // 配置源
    t: 2000,                   // 探测超时
    g: 300,                    // 竞速宽限
    k: "_jc",                  // 缓存 key
    l: 300000,                 // 缓存 TTL
    d: 3,                      // 倒计时
    r: 3                       // 最大重试
  };

  var _df = {
    w: { e: true, b: "", c: 6, l: 3 },
    p: [],
    h: 2,
    n: [],
    s: "",
    ct: {}
  };

  /* ========== DOM ========== */
  var $ = function (id) { return document.getElementById(id); };

  /* ========== 工具 ========== */
  function _cp(d) { return JSON.parse(JSON.stringify(d)); }

  function _nc(cfg) {
    var r = _cp(_df), s = cfg || {};
    if (s.wildcard) {
      r.w.e = s.wildcard.enabled !== false;
      r.w.b = s.wildcard.baseDomain || r.w.b;
      r.w.c = parseInt(s.wildcard.candidateCount, 10) || r.w.c;
      r.w.l = parseInt(s.wildcard.labelLength, 10) || r.w.l;
    }
    if (s.domains && s.domains.length) r.n = s.domains.slice();
    if (s.probeAssets && s.probeAssets.length) r.p = s.probeAssets.slice();
    if (s.probeAssetThreshold) r.h = parseInt(s.probeAssetThreshold, 10) || r.h;
    if (s.siteName) r.s = s.siteName;
    if (s.contact) r.ct = s.contact;
    return r;
  }

  function _rl(len) {
    var c = "abcdefghijklmnopqrstuvwxyz0123456789", v = "";
    for (var i = 0; i < len; i++) v += c.charAt(Math.floor(Math.random() * c.length));
    return v;
  }

  /* ========== 缓存 ========== */
  function _gc() {
    try {
      var raw = localStorage.getItem(_c.k);
      if (!raw) return null;
      var o = JSON.parse(raw);
      if (o && o.u && o.t && (Date.now() - o.t < _c.l)) return o;
    } catch (e) { }
    return null;
  }

  function _sc(url, lat) {
    try { localStorage.setItem(_c.k, JSON.stringify({ u: url, la: lat || 0, t: Date.now() })); } catch (e) { }
  }

  /* ========== DNS 预解析 ========== */
  function _dp(host) {
    var link = document.createElement("link");
    link.rel = "dns-prefetch";
    link.href = "//" + host;
    document.head.appendChild(link);
  }

  /* ========== 域名生成 ========== */
  function _bw(cfg) {
    var wc = cfg.w || {};
    var base = wc.b || "";
    var count = parseInt(wc.c, 10) || 6;
    var len = parseInt(wc.l, 10) || 3;
    var domains = [], used = {}, max = count * 8, att = 0;
    if (!base) return domains;
    while (domains.length < count && att < max) {
      att++;
      var label = _rl(len);
      var url = "https://" + label + "." + base;
      if (used[url]) continue;
      used[url] = true;
      domains.push({ u: url, n: "\u7ebf\u8def" + (domains.length + 1), v: "w" });
    }
    return domains;
  }

  function _rd(cfg) {
    if (cfg.n && cfg.n.length) return cfg.n;
    if (cfg.w && cfg.w.e) return _bw(cfg);
    return [];
  }

  /* ========== 探测 ========== */
  function _pa(url, timeout, cb) {
    var img = new Image(), done = false;
    var timer = setTimeout(function () { if (done) return; done = true; img.src = ""; cb(false); }, timeout);
    function fin(ok) { if (done) return; done = true; clearTimeout(timer); cb(ok); }
    img.onload = function () { fin(true); };
    img.onerror = function () { fin(false); };
    img.src = url;
  }

  function _cd(domain, cfg, cb) {
    var start = Date.now();
    var base = domain.u.replace(/\/+$/, "");
    var assets = (cfg.p && cfg.p.length) ? cfg.p : _df.p;
    var threshold = parseInt(cfg.h, 10) || _df.h;
    var state = { d: false, o: 0, t: 0, tm: null };
    state.tm = setTimeout(function () { _fn(false, 0); }, _c.t);
    function _fn(ok, lat) {
      if (state.d) return;
      state.d = true;
      clearTimeout(state.tm);
      cb(ok, lat || 0);
    }
    function _ev() {
      if (state.d) return;
      if (state.o >= threshold) { _fn(true, Date.now() - start); return; }
      if (state.t === assets.length && state.o < threshold) _fn(false, 0);
    }
    assets.forEach(function (path) {
      _pa(base + path + "?_=" + Date.now(), _c.t - 500, function (ok) {
        state.t++; if (ok) state.o++;
        _ev();
      });
    });
  }

  /* ========== UI ========== */
  function _ss(t) { $("statusText").textContent = t; }
  function _sp(v) { $("spinnerWrap").style.display = v ? "" : "none"; }

  function _rn(domains) {
    var ul = $("lineList"); ul.innerHTML = "";
    domains.forEach(function (d, i) {
      var li = document.createElement("li");
      li.id = "l-" + i;
      li.innerHTML = '<span class="line-name">' + d.n + '</span><span class="line-status checking" id="s-' + i + '">\u68c0\u6d4b\u4e2d</span>';
      ul.appendChild(li);
    });
  }

  function _ul(i, ok, lat) {
    var li = $("l-" + i), s = $("s-" + i);
    if (!li || !s) return;
    s.className = "line-status " + (ok ? "ok" : "fail");
    s.textContent = ok ? (lat + "ms") : "\u8d85\u65f6";
    li.className = ok ? "ok" : "fail";
  }

  function _mb(i) {
    var li = $("l-" + i);
    if (li) li.className = "ok best";
  }

  function _bl(i, url) {
    var li = $("l-" + i);
    if (li) li.onclick = function () { _jt(url); };
  }

  function _sf(cfg) {
    $("mainContent").className = "hide";
    $("fallbackContent").className = "";
    var ct = cfg.ct || {};
    var html = "";
    if (ct.telegram) html += '<a href="' + ct.telegram + '" target="_blank" rel="noopener">\ud83d\udcf1 Telegram</a>';
    if (ct.customerService) html += '<a href="' + ct.customerService + '" target="_blank" rel="noopener">\ud83d\udcac \u5728\u7ebf\u5ba2\u670d</a>';
    if (!html) html = '<span style="color:#8ea2c9;font-size:13px">\u8bf7\u8054\u7cfb\u60a8\u7684\u63a8\u8350\u4eba\u83b7\u53d6\u6700\u65b0\u5730\u5740</span>';
    $("contactLinks").innerHTML = html;
  }

  /* ========== 跳转 ========== */
  function _jt(url) {
    _sc(url, 0);
    _ss("\u6b63\u5728\u83b7\u53d6\u8bbf\u95ee\u51ed\u8bc1...");
    var xhr = new XMLHttpRequest();
    xhr.open("GET", "/api/gate-token", true);
    xhr.timeout = 2000;
    xhr.onload = function () {
      var tk = "";
      try { var d = JSON.parse(xhr.responseText); tk = d.token || ""; } catch (e) { }
      var sep = url.indexOf("?") >= 0 ? "&" : "?";
      window.location.replace(url + sep + "_gate=" + encodeURIComponent(tk));
    };
    xhr.onerror = function () { window.location.replace(url); };
    xhr.ontimeout = xhr.onerror;
    xhr.send();
  }

  /* ========== 倒计时 ========== */
  function _ct(results, cfg) {
    var best = results[0];
    var rem = _c.d;
    var cancelled = false;
    _sp(false);
    _ss(rem + " \u79d2\u540e\u8df3\u8f6c\u5230\u6700\u5feb\u7ebf\u8def...");
    $("mainActions").className = "actions";
    _mb(best.i);
    results.forEach(function (r) { _bl(r.i, r.u); });

    $("cancelBtn").onclick = function () {
      cancelled = true;
      clearInterval(iv);
      _ss("\u5df2\u53d6\u6d88\uff0c\u8bf7\u624b\u52a8\u9009\u62e9\u7ebf\u8def");
      $("mainActions").className = "actions hide";
    };

    var iv = setInterval(function () {
      if (cancelled) return;
      rem--;
      if (rem <= 0) {
        clearInterval(iv);
        _jt(best.u);
      } else {
        _ss(rem + " \u79d2\u540e\u8df3\u8f6c\u5230\u6700\u5feb\u7ebf\u8def...");
      }
    }, 1000);
  }

  /* ========== 全量探测 ========== */
  function _sp2(cfg, retry) {
    retry = retry || 0;
    var domains = _rd(cfg);
    if (!domains.length) { _sf(cfg); return; }
    _sp(true);
    _ss("\u6b63\u5728\u68c0\u6d4b\u6700\u5feb\u7ebf\u8def...");
    _rn(domains);

    var results = [], done = 0, finished = false, grace = null;

    function doFinish() {
      if (finished) return; finished = true;
      if (grace) clearTimeout(grace);
      if (results.length) {
        results.sort(function (a, b) { return a.la - b.la; });
        _ct(results, cfg);
      }
    }

    domains.forEach(function (d, i) {
      _cd(d, cfg, function (ok, lat) {
        done++;
        _ul(i, ok, lat);
        if (ok) {
          results.push({ u: d.u, n: d.n, la: lat, i: i });
          _bl(i, d.u);
          if (!grace) grace = setTimeout(doFinish, _c.g);
        }
        if (done === domains.length) {
          if (results.length) { doFinish(); }
          else if (retry < _c.r) {
            _ss("\u91cd\u8bd5\u4e2d (" + (retry + 1) + "/" + _c.r + ")...");
            setTimeout(function () { _sp2(cfg, retry + 1); }, 800);
          } else { _sf(cfg); }
        }
      });
    });
  }

  /* ========== 配置加载 ========== */
  function _lc(cb) {
    function tryUrl(i) {
      if (i >= _c.u.length) { cb(_nc(null)); return; }
      var xhr = new XMLHttpRequest();
      xhr.open("GET", _c.u[i] + "?_=" + Date.now(), true);
      xhr.timeout = 3000;
      xhr.onload = function () {
        if (xhr.status === 200) { try { cb(_nc(JSON.parse(xhr.responseText))); return; } catch (e) { } }
        tryUrl(i + 1);
      };
      xhr.onerror = function () { tryUrl(i + 1); };
      xhr.ontimeout = xhr.onerror;
      xhr.send();
    }
    tryUrl(0);
  }

  /* ========== 鉴权 ========== */
  function _gt() {
    var m = location.search.match(/[?&]token=([^&]+)/);
    return m ? decodeURIComponent(m[1]) : "";
  }

  function _vt(token, cb) {
    var xhr = new XMLHttpRequest();
    xhr.open("GET", "/api/verify-token?token=" + encodeURIComponent(token), true);
    xhr.timeout = 3000;
    xhr.onload = function () {
      if (xhr.status === 200) { try { var d = JSON.parse(xhr.responseText); cb(d && d.ok); } catch (e) { cb(false); } }
      else cb(false);
    };
    xhr.onerror = function () { cb(false); };
    xhr.ontimeout = xhr.onerror;
    xhr.send();
  }

  function _sd() {
    $("mainContent").className = "hide";
    $("fallbackContent").className = "";
    document.querySelector(".fallback-icon").textContent = "\ud83d\udd12";
    document.querySelector(".fallback-title").textContent = "\u8bbf\u95ee\u53d7\u9650";
    document.querySelector(".fallback-desc").textContent = "302 \u8bf7\u6c42\u906d\u5230\u62d2\u7edd";
    $("contactLinks").innerHTML = '<span style="color:#8ea2c9;font-size:13px"></span>';
  }

  /* ========== 入口 ========== */
  function _init() {
    var tk = _gt();
    if (!tk) { _sd(); return; }
    _ss("\u6b63\u5728\u9a8c\u8bc1\u8bbf\u95ee\u6743\u9650...");
    _vt(tk, function (ok) {
      if (!ok) { _sd(); return; }
      if (window.history && history.replaceState) {
        history.replaceState(null, "", location.pathname);
      }
      _lc(function (cfg) {
        if (cfg.s) $("brandName").textContent = cfg.s;
        if (cfg.w && cfg.w.b) _dp(cfg.w.b);
        var cached = _gc();
        if (cached) {
          _ss("\u5feb\u901f\u9a8c\u8bc1\u4e0a\u6b21\u7ebf\u8def...");
          _cd({ u: cached.u, n: "\u7f13\u5b58" }, cfg, function (ok2) {
            if (ok2) _jt(cached.u);
            else _sp2(cfg);
          });
        } else {
          _sp2(cfg);
        }
      });
    });
  }

  _init();
})();
