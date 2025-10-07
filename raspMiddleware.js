// raspMiddleware.js

const logger = require("../logger");

const rules = [
  { name: "XSS", pattern: /<script.*?>/i, message: "XSS Attack detected" },
  { name: "Path Traversal", pattern: /\.\.\//, message: "Path Traversal attempt detected" },
  { name: "SQL Injection", pattern: /('|--|;|union|select|insert|drop|update)/i, message: "SQL Injection detected" },
  { name: "Command Injection", pattern: /(&&|\|\||;|`)/, message: "Command Injection detected" }
];

function checkPayload(payload) {
  for (let rule of rules) {
    if (rule.pattern.test(payload)) {
      return rule;
    }
  }
  return null;
}

module.exports = function (req, res, next) {
  const data = JSON.stringify({ body: req.body, query: req.query, params: req.params });
  const result = checkPayload(data);

  if (result) {
    console.log(`[RASP] Blocked ${result.name} - ${result.message}`);
    logger.logAttack(req, result.name, result.message);
    return res.status(403).send("Blocked by Node Security Shield 🚫");
  }

  console.log(`[RASP] ${req.method} ${req.url}`);
  next();
};
