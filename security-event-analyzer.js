
const crypto = require("crypto");

const ALLOWED_EVENTS = new Set([
  "login_failed",
  "login_success",
  "mfa_failed",
  "access_denied"
]);

const MAX_EVENTS = 500;

function analyzeEvents(events) {
  if (!Array.isArray(events) || events.length > MAX_EVENTS) {
    throw new Error("Provide an array of up to 500 security events");
  }

  const cleanEvents = events.map(event => {
    if (
      !event ||
      typeof event.actorId !== "string" ||
      !/^[a-zA-Z0-9_-]{1,40}$/.test(event.actorId) ||
      !ALLOWED_EVENTS.has(event.eventType) ||
      typeof event.timestamp !== "string" ||
      !Number.isFinite(Date.parse(event.timestamp))
    ) {
      throw new Error("Invalid or unsupported security event");
    }

    return {
      actorId: event.actorId,
      eventType: event.eventType,
      timestamp: Date.parse(event.timestamp)
    };
  });

  cleanEvents.sort((a, b) => a.timestamp - b.timestamp);

  const actors = new Map();

  for (const event of cleanEvents) {
    if (!actors.has(event.actorId)) {
      actors.set(event.actorId, []);
    }

    actors.get(event.actorId).push(event);
  }

  const findings = [];

  for (const [actorId, actorEvents] of actors) {
    const failures = actorEvents.filter(
      e => e.eventType === "login_failed"
    );

    const denied = actorEvents.filter(
      e => e.eventType === "access_denied"
    );

    const mfaFailures = actorEvents.filter(
      e => e.eventType === "mfa_failed"
    );

    // Five or more failed logins within ten minutes.
    for (let i = 0; i < failures.length; i++) {
      const window = failures.filter(
        e =>
          e.timestamp >= failures[i].timestamp &&
          e.timestamp - failures[i].timestamp <= 600000
      );

      if (window.length >= 5) {
        findings.push({
          id: crypto.randomUUID(),
          actorId,
          type: "Repeated failed logins",
          severity: "high",
          evidence: `${window.length} failed login attempts within ten minutes`,
          recommendation: "Review authentication logs and apply appropriate account protection."
        });
        break;
      }
    }

    // Successful login shortly after repeated failures.
    for (const success of actorEvents.filter(
      e => e.eventType === "login_success"
    )) {
      const precedingFailures = failures.filter(
        e =>
          e.timestamp < success.timestamp &&
          success.timestamp - e.timestamp <= 600000
      );

      if (precedingFailures.length >= 5) {
        findings.push({
          id: crypto.randomUUID(),
          actorId,
          type: "Login success after repeated failures",
          severity: "critical",
          evidence: "A successful login followed five or more failures within ten minutes",
          recommendation: "Verify the login using authorized audit records and investigate possible account compromise."
        });
        break;
      }
    }

    if (denied.length >= 5) {
      findings.push({
        id: crypto.randomUUID(),
        actorId,
        type: "Repeated access-denied events",
        severity: "medium",
        evidence: `${denied.length} access-denied events`,
        recommendation: "Review access-control policies and investigate unusual request patterns."
      });
    }

    if (mfaFailures.length >= 3) {
      findings.push({
        id: crypto.randomUUID(),
        actorId,
        type: "Repeated MFA failures",
        severity: "high",
        evidence: `${mfaFailures.length} failed MFA events`,
        recommendation: "Review MFA alerts and verify the activity with the account owner."
      });
    }
  }

  return {
    analyzedEvents: cleanEvents.length,
    findingsCount: findings.length,
    findings
  };
}

module.exports = { analyzeEvents };
