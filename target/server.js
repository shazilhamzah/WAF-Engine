'use strict';
// binds to loopback only so the vulnerable app is never reachable from the network
const http = require('node:http');
const { createTargetApp } = require('./app');

const HOST = '127.0.0.1';

function startTarget({ port = Number(process.env.TARGET_PORT) || 3001, host = HOST } = {}) {
  if (host !== '127.0.0.1' && host !== 'localhost' && host !== '::1') {
    throw new Error('The vulnerable target may only bind to a loopback address');
  }
  const server = http.createServer(createTargetApp());
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve(server);
    });
  });
}

module.exports = { startTarget };

if (require.main === module) {
  startTarget().then((server) => {
    const { port } = server.address();
    console.log(`Vulnerable Shop (LAB ONLY, deliberately vulnerable) listening on http://${HOST}:${port}`);
    console.log('Send attacks through the WAF proxy, not directly. Press Ctrl+C to stop.');
    const stop = () => server.close(() => process.exit(0));
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
  }).catch((err) => {
    console.error(`Could not start the target: ${err.code || err.message}`);
    process.exit(1);
  });
}
