var MANUAL_KEYS = [
  'safe255',
  'safe255Dotted',
  'safe2554x63',
  'crash256',
  'crash256Plain',
  'crash256Dotted'
];

function buildManualPanel() {
  var root = document.getElementById('manual-hosts');
  var i;
  var spec;
  var box;
  var p;
  var row;
  var btn;
  var key;

  for (i = 0; i < MANUAL_KEYS.length; i++) {
    key = MANUAL_KEYS[i];
    spec = HOSTS[key];
    box = document.createElement('div');
    box.className = 'box';

    p = document.createElement('p');
    p.appendChild(document.createElement('strong')).appendChild(
      document.createTextNode(spec.label)
    );
    p.appendChild(document.createTextNode(' — len ' + spec.host.length));
    box.appendChild(p);

    row = document.createElement('div');
    row.className = 'btnrow';
    row.appendChild(makeManualBtn(spec, 'Image', function(h) { viaImg(hostUrl(h)); }));
    row.appendChild(makeManualBtn(spec, 'XHR', function(h) { viaXhr(hostUrl(h)); }));
    row.appendChild(makeManualBtn(spec, 'iframe', function(h) { viaIframe(hostUrl(h)); }));
    row.appendChild(makeManualBtn(spec, 'prefetch', function(h) { viaPrefetch(h); }));
    box.appendChild(row);

    root.appendChild(box);
  }

  document.getElementById('btn-clear').onclick = clearLog;
  log('Manual panel ready.');
}

function makeManualBtn(spec, label, fn) {
  var btn = document.createElement('button');
  btn.className = spec.danger ? 'danger' : 'safe';
  btn.appendChild(document.createTextNode(label));
  btn.onclick = (function(host) {
    return function() { fn(host); };
  })(spec.host);
  return btn;
}
