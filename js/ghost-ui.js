function buildGhostIndex() {
  var root = document.getElementById('ghost-panel');
  var i;
  var key;
  var spec;

  root.appendChild(makeGhostIntro());
  root.appendChild(makeGhostOracleBox());
  root.appendChild(makeGhostCampaignBox());

  for (i = 0; i < GHOST_WIRE_KEYS.length; i++) {
    key = GHOST_WIRE_KEYS[i];
    spec = HOSTS[key];
    root.appendChild(makeGhostHostBox(key, spec));
  }

  root.appendChild(makeGhostRaceBox());

  document.getElementById('btn-clear').onclick = clearLog;
  log('Ghost ready — never calls 256. Hunt silent overflow at 255.');
}

function makeGhostIntro() {
  var box = document.createElement('div');
  box.className = 'box';
  box.innerHTML = '<p class="ok"><strong>Goal:</strong> stress valid-wire <strong>255</strong> hosts via WebKit. '
    + 'If native resolver corrupts memory <em>without</em> CE, oracles should HIT.</p>'
    + '<p>Watch for: <code>ghost HIT</code> · <code>CORRUPTION-SUSPECT</code> · <code>VERDICT</code></p>';
  return box;
}

function makeGhostOracleBox() {
  var box = document.createElement('div');
  box.className = 'box safe-box';
  var p = document.createElement('p');
  p.className = 'ok';
  p.appendChild(document.createElement('strong')).appendChild(
    document.createTextNode('Oracles (run first / after storms)')
  );
  box.appendChild(p);
  box.appendChild(makeBtnRow('safe', [
    ['Baseline + pre-oracle', function() {
      resetGhostHits();
      captureBaseline(function() { runOracleSuite('manual', ghostVerdict); });
    }],
    ['PC ping only', function() { oraclePcPing('manual', function() {}); }],
    ['Storage canary', function() { oracleStorage('manual'); }],
    ['Verdict', ghostVerdict],
    ['Reset hits', resetGhostHits]
  ]));
  return box;
}

function makeGhostCampaignBox() {
  var box = document.createElement('div');
  box.className = 'box safe-box';
  var p = document.createElement('p');
  p.className = 'ok';
  p.appendChild(document.createElement('strong')).appendChild(
    document.createTextNode('Campaigns')
  );
  box.appendChild(p);
  box.appendChild(makeBtnRow('safe', [
    ['Quick (300 prefetch 4×63)', function() {
      resetGhostHits();
      captureBaseline(function() {
        ghostStormThenOracle('safe2554x63', 300, 'prefetch');
      });
    }],
    ['Full (storms + 15s race)', runGhostFull],
    ['Campaign', runGhostCampaign]
  ]));
  return box;
}

function makeGhostHostBox(key, spec) {
  var host = spec.host;
  var box = document.createElement('div');
  box.className = 'box safe-box';
  var title = document.createElement('p');
  title.className = 'ok';
  title.appendChild(document.createElement('strong')).appendChild(
    document.createTextNode(spec.label)
  );
  title.appendChild(document.createTextNode(' — len ' + host.length));
  box.appendChild(title);
  box.appendChild(makeBtnRow('safe', [
    ['prefetch', function() { viaPrefetch(host); }],
    ['Image', function() { viaImg(hostUrl(host)); }],
    ['Storm 50', function() { ghostStormThenOracle(key, 50, 'prefetch'); }],
    ['Storm 200', function() { ghostStormThenOracle(key, 200, 'prefetch'); }],
    ['Storm 50 all', function() { ghostStormThenOracle(key, 50, 'all'); }]
  ]));
  return box;
}

function makeGhostRaceBox() {
  var box = document.createElement('div');
  box.className = 'box safe-box';
  var p = document.createElement('p');
  p.className = 'ok';
  p.appendChild(document.createElement('strong')).appendChild(
    document.createTextNode('Race — continuous 255 (valid 4×63 wire)')
  );
  box.appendChild(p);
  box.appendChild(makeBtnRow('safe', [
    ['Start race', function() { startGhostRace('safe2554x63'); }],
    ['Stop + oracle', stopGhostRace]
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
