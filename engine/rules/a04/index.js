'use strict';

const {
  runInsecureDesignChecks,
  runInsecureDesignProjectChecks,
  runInsecureDesignUrlChecks,
} = require('./insecure-design');

function runA04Rules(context) {
  return runInsecureDesignChecks(context);
}

module.exports = {
  runA04Rules,
  runInsecureDesignChecks,
  runInsecureDesignProjectChecks,
  runInsecureDesignUrlChecks,
};
