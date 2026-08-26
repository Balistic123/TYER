/** WebKit ghost — hunt silent corruption at 255, never 256 (no CE). */
var GHOST_HIT_COUNT = 0;
var ghostBaselineFetchMs = 0;
var ghostPingEnabled = false;
var ghostPageCheckEnabled = false;
var ghostPageCheckProbed = false;
var GHOST_CANARY_KEY = 'webkit_ghost_canary';
var GHOST_CANARY_VAL = 'ABCD1234GHOST';

var GHOST_WIRE_KEYS = ['safe2554x63', 'safe255Dotted', 'safe255'];

function ghostPingUrl() {
  if (typeof GHOST_PING_URL !== 'undefined' && GHOST_PING_URL && GHOST_PING_URL.length > 0) {
    return GHOST_PING_URL + (GHOST_PING_URL.indexOf('?') >= 0 ? '&' : '?') + '_=' + new Date().getTime();
  }
  return location.protocol + '//' + location.host + '/ping.txt?_=' + new Date().getTime();
}

function ghostPageCheckUrl() {
  if (typeof GHOST_PAGE_CHECK_URL !== 'undefined' && GHOST_PAGE_CHECK_URL && GHOST_PAGE_CHECK_URL.length > 0) {
    return GHOST_PAGE_CHECK_URL + (GHOST_PAGE_CHECK_URL.indexOf('?') >= 0 ? '&' : '?') + '_=' + new Date().getTime();
  }
  var path = location.pathname || '/index-ghost.html';
  var slash = path.lastIndexOf('/');
  if (slash >= 0) {
    path = path.substring(0, slash + 1) + 'index.html';
  } else {
    path = '/index.html';
  }
  return location.protocol + '//' + location.host + path + '?_=' + new Date().getTime();
}

function ghostHit(oracle, detail) {
  GHOST_HIT_COUNT++;
  log('ghost HIT oracle=' + oracle + ' ' + detail);
  log('ghost CORRUPTION-SUSPECT ' + oracle + ' ' + detail);
}

function ghostVerdict() {
  if (GHOST_HIT_COUNT > 0) {
    log('ghost VERDICT CORRUPTION-SUSPECT hits=' + GHOST_HIT_COUNT);
  } else {
    log('ghost VERDICT no-corruption-detected');
    log('ghost NOTE silent native OOB not ruled out');
  }
}

function resetGhostHits() {
  GHOST_HIT_COUNT = 0;
  log('ghost hits reset');
}

function pingUrl() {
  return ghostPingUrl();
}

function captureBaseline(cb) {
  log('ghost baseline START');
  ghostPingEnabled = false;
  var t0 = new Date().getTime();
  var x = new XMLHttpRequest();
  x.open('GET', ghostPingUrl(), true);
  x.onreadystatechange = function() {
    if (x.readyState === 4) {
      ghostBaselineFetchMs = new Date().getTime() - t0;
      var body = x.responseText || '';
      log('ghost baseline fetch ms=' + ghostBaselineFetchMs + ' status=' + x.status);
      if (x.status === 200 && body.indexOf('OK') >= 0) {
        ghostPingEnabled = true;
        log('ghost baseline pc-ping ENABLED');
      } else {
        log('ghost baseline pc-ping SKIP (no ping.txt — OK on GitHub Pages)');
        log('ghost TIP: add ping.txt to repo root, or use local pc_webkit_server.py');
      }
      if (cb) {
        cb();
      }
    }
  };
  try {
    x.send(null);
  } catch (e) {
    log('ghost baseline SKIP err=' + e);
    if (cb) {
      cb();
    }
  }
}

function oraclePcPing(tag, cb) {
  if (!ghostPingEnabled) {
    log('ghost oracle pc-ping ' + tag + ' SKIP (unavailable)');
    if (cb) {
      cb();
    }
    return;
  }
  var t0 = new Date().getTime();
  var x = new XMLHttpRequest();
  x.open('GET', ghostPingUrl(), true);
  x.onreadystatechange = function() {
    if (x.readyState === 4) {
      var ms = new Date().getTime() - t0;
      var body = x.responseText || '';
      if (x.status !== 200 || body.indexOf('OK') < 0) {
        ghostHit('pc-ping-' + tag, 'status=' + x.status + ' was-OK-before');
      } else if (ghostBaselineFetchMs > 0 && ms > ghostBaselineFetchMs + 4000) {
        ghostHit('pc-ping-slow-' + tag, 'ms=' + ms + ' base=' + ghostBaselineFetchMs);
      } else {
        log('ghost oracle pc-ping ' + tag + ' PASS ms=' + ms);
      }
      if (cb) {
        cb();
      }
    }
  };
  try {
    x.send(null);
  } catch (e) {
    ghostHit('pc-ping-' + tag, String(e));
    if (cb) {
      cb();
    }
  }
}

function oracleStorage(tag) {
  try {
    if (typeof localStorage === 'undefined') {
      log('ghost oracle storage ' + tag + ' SKIP');
      return;
    }
    localStorage.setItem(GHOST_CANARY_KEY, GHOST_CANARY_VAL);
    var v = localStorage.getItem(GHOST_CANARY_KEY);
    if (v !== GHOST_CANARY_VAL) {
      ghostHit('storage-' + tag, 'got=' + v);
    } else {
      log('ghost oracle storage ' + tag + ' PASS');
    }
  } catch (e) {
    ghostHit('storage-' + tag, String(e));
  }
}

function oracle255Flip(host, tag) {
  var url = hostUrl(host);
  var img = new Image();
  var done = false;
  img.onload = function() {
    if (!done) {
      done = true;
      ghostHit('255-flip-' + tag, 'unexpected-OK len=' + host.length);
    }
  };
  img.onerror = function() {
    if (!done) {
      done = true;
      log('ghost oracle 255-flip ' + tag + ' PASS onerror len=' + host.length);
    }
  };
  img.src = url;
}

function oracleIndexHtml(tag, cb) {
  if (!ghostPageCheckProbed) {
    ghostPageCheckProbed = true;
    var probe = new XMLHttpRequest();
    probe.open('GET', ghostPageCheckUrl(), true);
    probe.onreadystatechange = function() {
      if (probe.readyState === 4) {
        if (probe.status === 200 && (probe.responseText || '').indexOf('WebKit') >= 0) {
          ghostPageCheckEnabled = true;
        }
        oracleIndexHtmlRun(tag, cb);
      }
    };
    try {
      probe.send(null);
    } catch (e) {
      oracleIndexHtmlRun(tag, cb);
    }
    return;
  }
  oracleIndexHtmlRun(tag, cb);
}

function oracleIndexHtmlRun(tag, cb) {
  if (!ghostPageCheckEnabled) {
    log('ghost oracle index-html ' + tag + ' SKIP (no index.html on host)');
    if (cb) {
      cb();
    }
    return;
  }
  var x = new XMLHttpRequest();
  x.open('GET', ghostPageCheckUrl(), true);
  x.onreadystatechange = function() {
    if (x.readyState === 4) {
      if (x.status !== 200 || (x.responseText || '').indexOf('WebKit') < 0) {
        ghostHit('index-html-' + tag, 'status=' + x.status + ' was-OK-before');
      } else {
        log('ghost oracle index-html ' + tag + ' PASS');
      }
      if (cb) {
        cb();
      }
    }
  };
  try {
    x.send(null);
  } catch (e) {
    ghostHit('index-html-' + tag, String(e));
    if (cb) {
      cb();
    }
  }
}

function runOracleSuite(tag, cb) {
  log('ghost CHECK ' + tag + ' START');
  oracleStorage(tag);
  oracle255Flip(HOSTS.safe2554x63.host, tag + '-4x63');
  oracle255Flip(HOSTS.safe255Dotted.host, tag + '-dotted');
  oracle255Flip(HOSTS.safe255.host, tag + '-flat');
  oraclePcPing(tag, function() {
    oracleIndexHtml(tag, function() {
      log('ghost CHECK ' + tag + ' END cumulative-hits=' + GHOST_HIT_COUNT);
      if (cb) {
        cb();
      }
    });
  });
}

function storm255(host, count, vector, label) {
  var i;
  var url = hostUrl(host);
  log('ghost storm START ' + label + ' n=' + count + ' vector=' + vector + ' len=' + host.length);
  for (i = 0; i < count; i++) {
    if (vector === 'prefetch') {
      viaPrefetch(host);
    } else if (vector === 'img') {
      viaImg(url);
    } else if (vector === 'xhr') {
      viaXhr(url);
    } else if (vector === 'all') {
      viaPrefetch(host);
      viaImg(url);
    }
    if (i === 0 || i === count - 1 || ((i + 1) % 100) === 0) {
      log('ghost storm ' + label + ' i=' + i);
    }
  }
  log('ghost storm END ' + label);
}

function ghostStormThenOracle(hostKey, count, vector) {
  var spec = HOSTS[hostKey];
  if (!spec || spec.host.length >= 256) {
    log('ghost ABORT host>=256');
    return;
  }
  storm255(spec.host, count, vector, hostKey);
  runOracleSuite('post-' + hostKey + '-' + count, ghostVerdict);
}

var ghostRaceTimer = null;
var ghostRaceCount = 0;
var ghostRaceHost = null;

function startGhostRace(hostKey) {
  stopGhostRace();
  var spec = HOSTS[hostKey];
  if (!spec) {
    return;
  }
  ghostRaceHost = spec.host;
  ghostRaceCount = 0;
  log('ghost race START key=' + hostKey + ' len=' + ghostRaceHost.length);
  ghostRaceTimer = setInterval(function() {
    viaPrefetch(ghostRaceHost);
    viaImg(hostUrl(ghostRaceHost));
    if (ghostRaceCount === 0 || ((ghostRaceCount + 1) % 25) === 0) {
      log('ghost race i=' + ghostRaceCount);
    }
    ghostRaceCount++;
  }, 10);
}

function stopGhostRace() {
  if (ghostRaceTimer !== null) {
    clearInterval(ghostRaceTimer);
    ghostRaceTimer = null;
    log('ghost race STOP i=' + ghostRaceCount);
    runOracleSuite('post-race', ghostVerdict);
  }
}

function runGhostCampaign() {
  resetGhostHits();
  captureBaseline(function() {
    runOracleSuite('pre', function() {
      ghostStormThenOracle('safe2554x63', 200, 'prefetch');
    });
  });
}

function runGhostFull() {
  resetGhostHits();
  captureBaseline(function() {
    runOracleSuite('pre', function() {
      storm255(HOSTS.safe2554x63.host, 300, 'all', 'wire-4x63');
      storm255(HOSTS.safe255Dotted.host, 100, 'prefetch', 'dotted');
      storm255(HOSTS.safe255.host, 100, 'prefetch', 'flat');
      startGhostRace('safe2554x63');
      setTimeout(function() {
        stopGhostRace();
      }, 15000);
    });
  });
}
