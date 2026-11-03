// built with the svg helper so they respect the csp
import { s } from './dom.js';

const SHIELD = 'M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z';
const TRAY = 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4';

const ICONS = {
  logo: [['path', { fill: 'currentColor', stroke: 'none', d: 'M11 2.25 2.5 4.5v9L11 22zM13 2.25 21.5 4.5v3H13zM13 9.75h8.5v3.75H13zM13 15.75h6.25L13 22z' }]],
  shield: [SHIELD],
  'shield-check': [SHIELD, 'm9 12 2 2 4-4'],
  menu: ['M4 6h16', 'M4 12h16', 'M4 18h16'],
  alert: ['m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3', 'M12 9v4', 'M12 17h.01'],
  check: ['M20 6 9 17l-5-5'],
  info: [['circle', { cx: 12, cy: 12, r: 10 }], 'M12 16v-4', 'M12 8h.01'],
  x: ['M18 6 6 18', 'm6 6 12 12'],
  lock: [['rect', { x: 3, y: 11, width: 18, height: 11, rx: 2 }], 'M7 11V7a5 5 0 0 1 10 0v4'],
  refresh: ['M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8', 'M21 3v5h-5'],
  download: [TRAY, 'm7 10 5 5 5-5', 'M12 15V3'],
  upload: [TRAY, 'm17 8-5-5-5 5', 'M12 3v12'],
  'arrow-right': ['M5 12h14', 'm12 5 7 7-7 7'],
  'chevron-left': ['m15 18-6-6 6-6'],
  'chevron-right': ['m9 18 6-6-6-6'],
  plus: ['M5 12h14', 'M12 5v14'],
  overview: [['rect', { x: 3, y: 3, width: 7, height: 9, rx: 1 }], ['rect', { x: 14, y: 3, width: 7, height: 5, rx: 1 }],
    ['rect', { x: 14, y: 12, width: 7, height: 9, rx: 1 }], ['rect', { x: 3, y: 16, width: 7, height: 5, rx: 1 }]],
  list: ['M3 6h.01', 'M3 12h.01', 'M3 18h.01', 'M8 6h13', 'M8 12h13', 'M8 18h13'],
  report: ['M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z', 'M14 2v4a2 2 0 0 0 2 2h4', 'M10 9H8', 'M16 13H8', 'M16 17H8'],
  scan: ['M3 7V5a2 2 0 0 1 2-2h2', 'M17 3h2a2 2 0 0 1 2 2v2', 'M21 17v2a2 2 0 0 1-2 2h-2', 'M7 21H5a2 2 0 0 1-2-2v-2',
    ['circle', { cx: 12, cy: 12, r: 3 }], 'm16 16-1.9-1.9'],
  sliders: ['M21 4h-7', 'M10 4H3', 'M21 12h-9', 'M8 12H3', 'M21 20h-5', 'M12 20H3', 'M14 2v4', 'M8 10v4', 'M16 18v4'],
  clipboard: [['rect', { x: 8, y: 2, width: 8, height: 4, rx: 1 }],
    'M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2', 'm9 14 2 2 4-4'],
  history: ['M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8', 'M3 3v5h5', 'M12 7v5l4 2'],
  users: ['M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2', ['circle', { cx: 9, cy: 7, r: 4 }], 'M22 21v-2a4 4 0 0 0-3-3.87', 'M16 3.13a4 4 0 0 1 0 7.75'],
  'log-out': ['M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4', 'm16 17 5-5-5-5', 'M21 12H9'],
};

export function icon(name, cls) {
  const parts = ICONS[name] || [];
  return s('svg', {
    class: ['icon', cls], viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 2,
    'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', focusable: 'false',
  }, ...parts.map((p) => (typeof p === 'string' ? s('path', { d: p }) : s(p[0], p[1]))));
}
