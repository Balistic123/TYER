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

function describeHost(host) {
  if (!host) {
    return 'len=0';
  }
  var tail = host.length > 12 ? host.substring(host.length - 12) : host;
  return 'host-len=' + host.length + ' tail=' + tail;
}

function describeUrl(url) {
  return 'url-len=' + (url ? url.length : 0) + ' (' + describeHost(extractHostFromUrl(url)) + ')';
}

function extractHostFromUrl(url) {
  if (!url || url.indexOf('//') < 0) {
    return '';
  }
  var start = url.indexOf('//') + 2;
  var end = url.indexOf('/', start);
  if (end < 0) {
    end = url.length;
  }
  return url.substring(start, end);
}
