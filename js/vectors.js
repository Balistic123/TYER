function viaImg(url) {
  log('→ Image src (' + url.length + ' url chars)');
  var i = new Image();
  i.onload = function() { log('  Image onload'); };
  i.onerror = function() { log('  Image onerror'); };
  i.src = url;
}

function viaXhr(url) {
  log('→ XHR GET (' + url.length + ' url chars)');
  try {
    var x = new XMLHttpRequest();
    x.open('GET', url, true);
    x.onreadystatechange = function() {
      if (x.readyState === 4) {
        log('  XHR done status=' + x.status);
      }
    };
    x.send(null);
  } catch (e) {
    log('  XHR err: ' + e);
  }
}

function viaIframe(url) {
  log('→ iframe src (' + url.length + ' url chars)');
  var f = document.createElement('iframe');
  f.style.display = 'none';
  f.src = url;
  document.body.appendChild(f);
  log('  iframe appended');
}

function viaPrefetch(host) {
  log('→ dns-prefetch host len=' + host.length);
  var l = document.createElement('link');
  l.rel = 'dns-prefetch';
  l.href = '//' + host + '/';
  document.head.appendChild(l);
  log('  prefetch link added');
}

function viaScript(url) {
  log('→ script src (' + url.length + ' url chars)');
  var s = document.createElement('script');
  s.src = url;
  s.onerror = function() { log('  script onerror'); };
  document.body.appendChild(s);
}

function runAllVectors(host, url) {
  log('=== run all host len=' + host.length + ' ===');
  viaPrefetch(host);
  viaImg(url);
  viaXhr(url);
  viaIframe(url);
  viaScript(url);
}
