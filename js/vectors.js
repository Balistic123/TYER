function viaPreconnect(host) {
  log('→ preconnect host len=' + host.length);
  var l = document.createElement('link');
  l.rel = 'preconnect';
  l.href = '//' + host + '/';
  document.head.appendChild(l);
  log('  preconnect added');
}

function viaVideo(url) {
  log('→ video src (' + url.length + ' url chars)');
  try {
    var v = document.createElement('video');
    v.style.display = 'none';
    v.onerror = function() { log('  video onerror'); };
    v.src = url;
    document.body.appendChild(v);
  } catch (e) {
    log('  video err: ' + e);
  }
}

function viaObject(url) {
  log('→ object data (' + url.length + ' url chars)');
  try {
    var o = document.createElement('object');
    o.style.display = 'none';
    o.data = url;
    document.body.appendChild(o);
    log('  object appended');
  } catch (e) {
    log('  object err: ' + e);
  }
}

function viaWebSocket(host) {
  log('→ WebSocket host len=' + host.length);
  try {
    if (typeof WebSocket === 'undefined') {
      log('  WebSocket SKIP undefined');
      return;
    }
    var ws = new WebSocket('ws://' + host + '/');
    ws.onerror = function() { log('  ws onerror'); };
    ws.onopen = function() { log('  ws onopen'); };
  } catch (e) {
    log('  ws err: ' + e);
  }
}

function viaAnchor(url, id) {
  log('→ anchor href (' + url.length + ' url chars)');
  var a = document.getElementById(id);
  if (!a) {
    log('  anchor missing id=' + id);
    return;
  }
  a.href = url;
  a.style.display = 'inline-block';
  log('  TAP the red link below to navigate');
}

function viaLocation(url) {
  log('→ location.assign (' + url.length + ' url chars)');
  location.assign(url);
}

function runAllVectors(host, url) {
  log('=== ALL host len=' + host.length + ' url len=' + url.length + ' ===');
  viaPrefetch(host);
  viaPreconnect(host);
  viaImg(url);
  viaXhr(url);
  viaIframe(url);
  viaScript(url);
  viaVideo(url);
  viaObject(url);
  viaWebSocket(host);
}

function runDnsOnly(host) {
  log('=== DNS-only host len=' + host.length + ' ===');
  viaPrefetch(host);
  viaPreconnect(host);
}
