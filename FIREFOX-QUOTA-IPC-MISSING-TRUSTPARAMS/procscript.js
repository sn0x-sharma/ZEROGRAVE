// system privilege, EVERY process (parent + each content process)
// READ-ONLY: listOrigins() only. Never calls clearStorage().
(() => {
  const base = () => ({
    processType: Services.appinfo.processType,
    isParent: Services.appinfo.processType === Services.appinfo.PROCESS_TYPE_DEFAULT,
    remoteType: Services.appinfo.remoteType,
    pid: Services.appinfo.processID,
  });
  const send = (phase, extra) => {
    try {
      Services.cpmm.sendAsyncMessage("snox:result",
        Object.assign(base(), { phase }, extra || {}));
    } catch (e) {}
  };

  send("hello");                       // proves the script ran in this process

  let settled = false;
  try {
    const qms = Cc["@mozilla.org/dom/quota-manager-service;1"].getService(
      Ci.nsIQuotaManagerService
    );
    const req = qms.listOrigins();
    req.callback = {
      QueryInterface: ChromeUtils.generateQI(["nsIQuotaCallback"]),
      onComplete(r) {
        if (settled) return;
        settled = true;
        let o = null, rc = null, rerr = null;
        try { rc = r.resultCode; o = r.result; } catch (e) { rerr = String(e); }
        send("done", { resultCode: rc, origins: o, readErr: rerr });
      },
    };
    Services.tm.dispatchToMainThread(() => {
      setTimeout(() => {
        if (!settled) { settled = true; send("timeout-no-callback"); }
      }, 7000);
    });
  } catch (e) {
    settled = true;
    send("threw", { err: String(e) });
  }
})();
