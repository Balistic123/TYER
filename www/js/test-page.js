function initTestPage(hostKey) {
  var spec = HOSTS[hostKey];
  if (!spec) {
    log('Unknown host key: ' + hostKey);
    return;
  }

  var host = spec.host;
  var url = hostUrl(host);
  var btnClass = spec.danger ? 'danger' : 'safe';

  document.title = spec.title;
  var titleEl = document.getElementById('page-title');
  if (titleEl) {
    titleEl.appendChild(document.createTextNode(spec.title));
  }

  var lenEl = document.getElementById('host-len');
  if (lenEl) {
    lenEl.appendChild(document.createTextNode(String(host.length)));
  }

  var previewEl = document.getElementById('host-preview');
  if (previewEl) {
    previewEl.appendChild(document.createTextNode(clipHost(host)));
  }

  bindButton('btn-img', btnClass, function() { viaImg(url); });
  bindButton('btn-xhr', btnClass, function() { viaXhr(url); });
  bindButton('btn-iframe', btnClass, function() { viaIframe(url); });
  bindButton('btn-prefetch', btnClass, function() { viaPrefetch(host); });
  bindButton('btn-script', btnClass, function() { viaScript(url); });
  bindButton('btn-all', btnClass, function() { runAllVectors(host, url); });
  bindButton('btn-clear', '', clearLog);

  log('Ready — tap a button to test.');
}

function bindButton(id, extraClass, fn) {
  var el = document.getElementById(id);
  if (!el) {
    return;
  }
  if (extraClass) {
    el.className = extraClass;
  }
  el.onclick = fn;
}
