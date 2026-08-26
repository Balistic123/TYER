function initDualPage(hostKey) {
  var spec = HOSTS[hostKey];
  var host = spec.host;
  var url = hostUrl(host);

  document.title = spec.title;
  var titleEl = document.getElementById('page-title');
  if (titleEl) {
    titleEl.appendChild(document.createTextNode(spec.title));
  }

  var lenEl = document.getElementById('host-len');
  if (lenEl) {
    lenEl.appendChild(document.createTextNode(String(host.length)));
  }

  document.getElementById('btn-a').onclick = function() { addDualFrame(url, 1); };
  document.getElementById('btn-b').onclick = function() { addDualFrame(url, 2); };
  document.getElementById('btn-both').onclick = function() {
    addDualFrame(url, 1);
    addDualFrame(url, 2);
  };
  document.getElementById('btn-clear').onclick = clearLog;

  log('Ready — tap iframe button when ready.');
}

function addDualFrame(url, id) {
  log('→ iframe ' + id);
  var f = document.createElement('iframe');
  f.id = 'f' + id;
  f.style.display = 'none';
  f.src = url;
  document.body.appendChild(f);
  log('  iframe ' + id + ' appended');
}
