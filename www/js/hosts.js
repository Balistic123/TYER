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

var HOSTS = {
  safe255: {
    title: 'safe 255 flat',
    label: '255 flat .local (safe)',
    host: hostFlat(249),
    danger: false
  },
  safe255Dotted: {
    title: 'safe 252 dotted',
    label: '252 dotted .local (safe)',
    host: hostDotted255(),
    danger: false
  },
  safe2554x63: {
    title: 'safe 255 4x63',
    label: '255 plain 4x63 (safe)',
    host: hostFourBy63Plain(),
    danger: false
  },
  crash256: {
    title: 'CRASH 256 flat',
    label: '256 flat .local (CRASH)',
    host: hostFlat(250),
    danger: true
  },
  crash256Plain: {
    title: 'CRASH 256 plain',
    label: '256 plain no suffix (CRASH)',
    host: repeatCh('P', 256),
    danger: true
  },
  crash256Dotted: {
    title: 'CRASH 261 dotted',
    label: '261 dotted 4x63+.local (CRASH)',
    host: hostDotted261Local(),
    danger: true
  },
  crash256Dual: {
    title: 'dual 256 iframes',
    label: '256 flat .local dual iframe',
    host: hostFlat(250),
    danger: true
  }
};
