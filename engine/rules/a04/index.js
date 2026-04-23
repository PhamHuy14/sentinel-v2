const { runTransportSecurityA04 } = require('./transport-security');
const { runSensitiveDataA04 } = require('./sensitive-data');
const { runCookieSecurityA04 } = require('./cookie-security');
const { runHstsAndWebsocketA04 } = require('./hsts-websocket');

function runA04Rules(context) {
  return [
    ...runTransportSecurityA04(context),
    ...runSensitiveDataA04(context),
    ...runCookieSecurityA04(context),
    ...runHstsAndWebsocketA04(context),
  ];
}

module.exports = {
  runA04Rules,
  runTransportSecurityA04,
  runSensitiveDataA04,
  runCookieSecurityA04,
  runHstsAndWebsocketA04,
};
