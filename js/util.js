function repeatCh(c, n) {
  var s = '';
  var i;
  for (i = 0; i < n; i++) {
    s += c;
  }
  return s;
}

function log(msg) {
  var el = document.getElementById('log');
  if (el) {
    el.innerHTML += msg + '<br>';
  }
}

function clearLog() {
  var el = document.getElementById('log');
  if (el) {
    el.innerHTML = '';
  }
}

function hostUrl(host) {
  return 'http://' + host + '/';
}

function clipHost(host) {
  if (!host || host.length <= 72) {
    return host;
  }
  return host.substring(0, 48) + '…' + host.substring(host.length - 24);
}
