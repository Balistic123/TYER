var INDEX_HOST_KEYS = [
  'safe255',
  'safe255Dotted',
  'safe2554x63',
  'crash256',
  'crash256Plain',
  'crash256Dotted'
];

function buildIndex() {
  var root = document.getElementById('test-hosts');
  var i;
  var key;
  var spec;
  var host;

  for (i = 0; i < INDEX_HOST_KEYS.length; i++) {
    key = INDEX_HOST_KEYS[i];
    spec = HOSTS[key];
    host = spec.host;
    root.appendChild(makeHostBox(spec, host));
  }

  root.appendChild(makeDualBox());

  document.getElementById('btn-clear').onclick = clearLog;
  log('Ready — tap any button to test. Nothing runs automatically.');
}

function makeHostBox(spec, host) {
  var box = document.createElement('div');
  box.className = 'box' + (spec.danger ? ' danger-box' : ' safe-box');
  var url = hostUrl(host);
  var btnClass = spec.danger ? 'danger' : 'safe';

  var title = document.createElement('p');
  title.className = spec.danger ? 'warn' : 'ok';
  title.appendChild(document.createElement('strong')).appendChild(
    document.createTextNode(spec.label)
  );
  title.appendChild(document.createTextNode(' — len ' + host.length));
  box.appendChild(title);

  var preview = document.createElement('p');
  var code = document.createElement('code');
  code.appendChild(document.createTextNode(clipHost(host)));
  preview.appendChild(code);
  box.appendChild(preview);

  box.appendChild(makeBtnRow(btnClass, [
    ['Image', function() { viaImg(url); }],
    ['XHR', function() { viaXhr(url); }],
    ['iframe', function() { viaIframe(url); }],
    ['prefetch', function() { viaPrefetch(host); }],
    ['script', function() { viaScript(url); }],
    ['All', function() { runAllVectors(host, url); }]
  ]));

  return box;
}

function makeDualBox() {
  var spec = HOSTS.crash256Dual;
  var host = spec.host;
  var url = hostUrl(host);
  var box = document.createElement('div');
  box.className = 'box danger-box';

  var title = document.createElement('p');
  title.className = 'warn';
  title.appendChild(document.createElement('strong')).appendChild(
    document.createTextNode('Dual iframe 256+256 (pair-dual / UI hang)')
  );
  title.appendChild(document.createTextNode(' — len ' + host.length));
  box.appendChild(title);

  box.appendChild(makeBtnRow('danger', [
    ['iframe A', function() { addDualFrame(url, 'A'); }],
    ['iframe B', function() { addDualFrame(url, 'B'); }],
    ['Both A+B', function() { addDualFrame(url, 'A'); addDualFrame(url, 'B'); }]
  ]));

  return box;
}

function makeBtnRow(btnClass, items) {
  var row = document.createElement('div');
  row.className = 'btnrow';
  var j;
  var btn;
  for (j = 0; j < items.length; j++) {
    btn = document.createElement('button');
    btn.className = btnClass;
    btn.appendChild(document.createTextNode(items[j][0]));
    btn.onclick = items[j][1];
    row.appendChild(btn);
  }
  return row;
}

function addDualFrame(url, id) {
  log('→ dual iframe ' + id);
  var f = document.createElement('iframe');
  f.id = 'dual-f-' + id;
  f.style.display = 'none';
  f.src = url;
  document.body.appendChild(f);
  log('  iframe ' + id + ' appended');
}
