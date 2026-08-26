var VECTOR_BUTTONS = [
  ['prefetch', function(h, u) { viaPrefetch(h); }],
  ['preconnect', function(h, u) { viaPreconnect(h); }],
  ['DNS both', function(h, u) { runDnsOnly(h); }],
  ['Image', function(h, u) { viaImg(u); }],
  ['XHR', function(h, u) { viaXhr(u); }],
  ['iframe', function(h, u) { viaIframe(u); }],
  ['script', function(h, u) { viaScript(u); }],
  ['video', function(h, u) { viaVideo(u); }],
  ['object', function(h, u) { viaObject(u); }],
  ['WebSocket', function(h, u) { viaWebSocket(h); }],
  ['ALL', function(h, u) { runAllVectors(h, u); }]
];

function buildMainIndex() {
  var app = document.getElementById('app');
  var s;

  app.appendChild(makeTipsBox());

  for (s = 0; s < INDEX_SECTIONS.length; s++) {
    if (INDEX_SECTIONS[s].oracle) {
      app.appendChild(makeOracleSection());
    } else {
      app.appendChild(makeSection(INDEX_SECTIONS[s]));
    }
  }

  app.appendChild(makeDualSection());
  app.appendChild(makeAnchorBox());

  document.getElementById('btn-clear').onclick = clearLog;
  log('Ready (GitHub Pages OK). Try 261 dotted prefetch FIRST if flat 256 does nothing.');
}

function makeTipsBox() {
  var box = document.createElement('div');
  box.className = 'box';
  box.innerHTML = '<p><strong>Reading results:</strong></p>'
    + '<ul>'
    + '<li><strong>CE-36329-3</strong> = system crash (BD-J cliff) — what we want to match</li>'
    + '<li><strong>Can\u2019t connect to this server</strong> = browser tried HTTP, host not found / no route — '
    + '<em>NOT</em> the same as CE; WebKit likely used a safe error path</li>'
    + '<li>Address bar showing only <code>cccc…</code> is normal — PS4 truncates display; '
    + 'full host is 250×C + <code>.local</code> (256 total). Check log <code>tail=</code> line.</li>'
    + '</ul>'
    + '<p><strong>Try next:</strong> <strong>261 dotted → prefetch</strong> or '
    + '<strong>261 iframe (stay on page)</strong> — valid DNS labels, CE on BD-J.</p>';
  return box;
}

function makeOracleSection() {
  var box = document.createElement('div');
  box.className = 'box safe-box';
  var p = document.createElement('p');
  p.className = 'ok';
  p.appendChild(document.createElement('strong')).appendChild(
    document.createTextNode('Ghost255 oracles + storms')
  );
  box.appendChild(p);
  box.appendChild(makeBtnRow('safe', [
    ['Baseline', function() {
      resetGhostHits();
      captureBaseline(function() { runOracleSuite('pre', ghostVerdict); });
    }],
    ['Storm 300 4×63', function() {
      resetGhostHits();
      captureBaseline(function() {
        ghostStormThenOracle('safe2554x63', 300, 'prefetch');
      });
    }],
    ['Race 15s', function() {
      resetGhostHits();
      startGhostRace('safe2554x63');
      setTimeout(stopGhostRace, 15000);
    }],
    ['Verdict', ghostVerdict]
  ]));
  return box;
}

function makeSection(section) {
  var wrap = document.createElement('div');
  var h = document.createElement('h2');
  h.appendChild(document.createTextNode(section.title));
  wrap.appendChild(h);
  var i;
  for (i = 0; i < section.keys.length; i++) {
    wrap.appendChild(makeHostBox(HOSTS[section.keys[i]]));
  }
  return wrap;
}

function makeHostBox(spec) {
  var host = spec.host;
  var url = hostUrl(host);
  var box = document.createElement('div');
  box.className = 'box ' + (spec.danger ? 'danger-box' : 'safe-box');
  var btnClass = spec.danger ? 'danger' : 'safe';

  var title = document.createElement('p');
  title.className = spec.danger ? 'warn' : 'ok';
  title.appendChild(document.createElement('strong')).appendChild(
    document.createTextNode(spec.label)
  );
  title.appendChild(document.createTextNode(' — len ' + host.length));
  box.appendChild(title);

  if (spec.note) {
    var note = document.createElement('p');
    note.appendChild(document.createTextNode(spec.note));
    box.appendChild(note);
  }

  var preview = document.createElement('p');
  var code = document.createElement('code');
  code.appendChild(document.createTextNode(clipHost(host)));
  preview.appendChild(code);
  box.appendChild(preview);

  box.appendChild(makeHostBtnRow(spec, host, url, btnClass));
  return box;
}

function makeHostBtnRow(spec, host, url, btnClass) {
  var row = document.createElement('div');
  row.className = 'btnrow';
  var i;
  var btn;
  for (i = 0; i < VECTOR_BUTTONS.length; i++) {
    btn = document.createElement('button');
    btn.className = btnClass;
    btn.appendChild(document.createTextNode(VECTOR_BUTTONS[i][0]));
    btn.onclick = (function(h, u, fn, spec) {
      return function() {
        log('--- ' + spec.label + ' ' + describeHost(h) + ' ---');
        fn(h, u);
      };
    })(host, url, VECTOR_BUTTONS[i][1], spec);
    row.appendChild(btn);
  }
  return row;
}

function makeDualSection() {
  var spec = HOSTS.crash256Dual;
  var host = spec.host;
  var url = hostUrl(host);
  var box = document.createElement('div');
  box.className = 'box danger-box';
  var p = document.createElement('p');
  p.className = 'warn';
  p.appendChild(document.createElement('strong')).appendChild(
    document.createTextNode('Dual iframe 256 (UI hang hunt)')
  );
  box.appendChild(p);
  box.appendChild(makeBtnRow('danger', [
    ['iframe A', function() { addDualFrame(url, 'A'); }],
    ['iframe B', function() { addDualFrame(url, 'B'); }],
    ['Both', function() { addDualFrame(url, 'A'); addDualFrame(url, 'B'); }]
  ]));
  return box;
}

function makeAnchorBox() {
  var box = document.createElement('div');
  box.className = 'box danger-box';
  box.innerHTML = '<p class="warn"><strong>Navigate tests</strong> — prefer iframe (stays on page) over red link</p>';
  var row1 = document.createElement('div');
  row1.className = 'btnrow';
  row1.appendChild(makeBtn('danger', '261 iframe', function() {
    var u = hostUrl(HOSTS.crash256Dotted.host);
    log('261 iframe ' + describeUrl(u));
    addDualFrame(u, 'nav261');
  }));
  row1.appendChild(makeBtn('danger', '256 iframe', function() {
    var u = hostUrl(HOSTS.crash256.host);
    log('256 iframe ' + describeUrl(u));
    addDualFrame(u, 'nav256');
  }));
  row1.appendChild(makeBtn('danger', '255 4×63 iframe', function() {
    var u = hostUrl(HOSTS.safe2554x63.host);
    log('255 iframe ' + describeUrl(u));
    addDualFrame(u, 'nav255');
  }));
  box.appendChild(row1);

  var row2 = document.createElement('div');
  row2.className = 'btnrow';
  row2.appendChild(makeBtn('danger', '261 red link', function() {
    viaAnchor(hostUrl(HOSTS.crash256Dotted.host), 'manual-nav');
  }));
  row2.appendChild(makeBtn('danger', '256 red link', function() {
    viaAnchor(hostUrl(HOSTS.crash256.host), 'manual-nav');
  }));
  box.appendChild(row2);

  var a = document.createElement('a');
  a.id = 'manual-nav';
  a.className = 'nav-link';
  a.style.display = 'none';
  a.target = '_self';
  a.appendChild(document.createTextNode('TAP TO NAVIGATE'));
  box.appendChild(a);
  return box;
}

function makeBtnRow(cls, items) {
  var row = document.createElement('div');
  row.className = 'btnrow';
  var j;
  for (j = 0; j < items.length; j++) {
    row.appendChild(makeBtn(cls, items[j][0], items[j][1]));
  }
  return row;
}

function makeBtn(cls, label, fn) {
  var btn = document.createElement('button');
  btn.className = cls;
  btn.appendChild(document.createTextNode(label));
  btn.onclick = fn;
  return btn;
}

function addDualFrame(url, id) {
  log('→ dual iframe ' + id);
  var f = document.createElement('iframe');
  f.id = 'dual-f-' + id;
  f.style.display = 'none';
  f.src = url;
  document.body.appendChild(f);
}
