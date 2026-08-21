// Firefox persistent prompt injection via memory-from-history — full chain.
// Paste into the devtools console on the served payload page.
"use strict";
(() => {
  const MAX = 100;                                  // ChatUtils.sys.mjs:12

  // faithful port of ChatUtils.sys.mjs:71 sanitizeUntrustedContent
  function sanitize(text, truncateOnly) {
    let f = text;
    if (f.length > MAX) { f = f.slice(0, MAX) + "…"; }
    if (truncateOnly) { return f; }                 // <- early return skips everything below
    f = f.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\s+/g, " ");
    return '"' + f + '" (Untrusted webpage data)';
  }

  console.log("Step 1: the attacker-controlled input is the page title.");
  const t = document.title;
  console.log("  document.title =", JSON.stringify(t));

  console.log("Step 2: what every OTHER call site produces (escaped + spotlit):");
  console.log("  " + sanitize(t, false));

  console.log("Step 3: what MemoriesHistorySource.sys.mjs:287 produces (truncateOnly=true):");
  console.log("  " + JSON.stringify(sanitize(t, true)));

  console.log("Step 4: differences that matter:");
  console.log("  newline preserved      :", sanitize(t, true).includes("\n"),
              "(expected false - document.title normalizes whitespace)");
  console.log("  spotlighting marker    :",
              sanitize(t, true).includes("(Untrusted webpage data)") ? "present" : "ABSENT");

  console.log("Step 5: persistence path —");
  console.log("  title -> moz_places -> MemoriesHistoryScheduler -> memory-gen model");
  console.log("        -> stored memory -> getUserMemories (Tools.sys.mjs:1018)");
  console.log("        -> replayed into EVERY later conversation");
  console.log("  getUserMemories sets privateData WITHOUT untrustedInput (Tools.sys.mjs:1025)");
  console.log("  = exactly the state that makes the finding-01 fetch gate fail open.");

  console.log("CHAIN COMPLETE — verify storage with:");
  console.log("  sqlite3 <profile>/places.sqlite \"SELECT title FROM moz_places ORDER BY last_visit_date DESC LIMIT 1;\"");
  console.log("NOT PROVEN: that a model follows the instruction — see report.md.");
})();
