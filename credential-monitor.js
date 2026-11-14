
const crypto = require("crypto");

// Credential Security Monitor
// Accepts fictional or sanitized security-event data only.

const findings = [];

const SECRET_PATTERNS = [
  {
    type: "Possible password exposure",
    pattern: /\b(password|passwd|pwd)\s*[:=]\s*\S+/i
  },
  {
    type: "Possible PIN exposure",
    pattern: /\b(pin)\s*[:=]\s*\d{4,6}\b/i
  },
  {
    type: "Possible OTP exposure",
    pattern: /\b(otp|verification code)\s*[:=]\s*\d{4,8}\b/i
  },
  {
    type: "Possible token exposure",
    pattern: /\b(access_token|refresh_token|api_key)\s*[:=]\s*\S+/i
  }
];

function inspectEvent(event) {
  if (
    !event ||
    typeof event.message !== "string" ||
    event.message.length > 2000
  ) {
    throw new Error("Invalid security event");
  }

  const detected = SECRET_PATTERNS
    .filter(item => item.pattern.test(event.message))
    .map(item => item.type);

  const report = {
    id: crypto.randomUUID(),
    category: "credential-security",
    timestamp: new Date().toISOString(),
    eventType:
      typeof event.eventType === "string"
        ? event.eventType.slice(0, 60)
        : "unspecified",
    findings: detected,
    risk: detected.length ? "review-required" : "no-pattern-detected",
    message: "[Original event content not retained]"
  };

  findings.unshift(report);

  return report;
}

function getReports() {
  return findings.slice(0, 100);
}

module.exports = {
  inspectEvent,
  getReports
};
