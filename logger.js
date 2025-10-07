// logger.js
const Log = require("./models/log");

async function safePayload(req) {
  try {
    // create a short snippet of payload with no secrets
    const body = req.body ? JSON.stringify(req.body) : "";
    const query = req.query ? JSON.stringify(req.query) : "";
    // mask common secrets
    const masked = (body + " " + query).replace(/(authorization|token|password)\s*[:=]\s*["']?[^"']+/gi, "$1:***");
    // limit length
    return masked.length > 500 ? masked.slice(0, 500) + "..." : masked;
  } catch (e) {
    return "";
  }
}

module.exports.logAttack = async function (req, type, message, extra = {}) {
  try {
    const payload = await safePayload(req);
    const userId = (req.user && req.user._id) ? String(req.user._id) : extra.userId || null;

    await Log.create({
      type: type || "rule-violation",
      rule: message || "",
      message: message || "",
      ip: (req.ip || req.connection?.remoteAddress || "").toString(),
      userId,
      url: req.originalUrl || req.url || extra.url || "",
      payload
    });
  } catch (err) {
    // keep server safe even if logging fails
    console.error("[logger] error saving attack log:", err.message || err);
  }
};
