// system privilege, EVERY process (parent + each content process)
// READ-ONLY: getUsage(cb, getAll=true) only. Never clearStorage()/shutdownStorage().
(() => {
  const base = () => ({
    processType: Services.appinfo.processType,
    isParent: Services.appinfo.processType === Services.appinfo.PROCESS_TYPE_DEFAULT,
    remoteType: Services.appinfo.remoteType,
    pid: Services.appinfo.processID,
  });
  const send = (phase, extra) => {
    try { Services.cpmm.sendAsyncMessage("snox:q2", Object.assign(base(), {phase}, extra||{})); } catch(e){}
  };

  send("hello");                       // FIRST - proves the script ran here

  let settled = false;
  const finish = (phase, extra) => { if (!settled) { settled = true; send(phase, extra); } };

  try {
    const qms = Cc["@mozilla.org/dom/quota-manager-service;1"]
                  .getService(Ci.nsIQuotaManagerService);
    const req = qms.getUsage({
      QueryInterface: ChromeUtils.generateQI(["nsIQuotaUsageCallback"]),
      onUsageResult(r) {
        let rows = [], rc = null, rerr = null;
        try {
          rc = r.resultCode;
          for (const e of (r.result || [])) {
            try {
              const m = e.QueryInterface(Ci.nsIQuotaUsageResult);
              rows.push({ origin: m.origin, usage: Number(m.usage),
                          lastAccessed: Number(m.lastAccessed), persisted: m.persisted });
            } catch (e2) { rows.push({ raw: String(e), qiErr: String(e2) }); }
          }
        } catch (e) { rerr = String(e); }
        finish("done", { resultCode: rc, count: rows.length, rows, readErr: rerr });
      },
    }, true);
    try {
      const { setTimeout } = ChromeUtils.importESModule("resource://gre/modules/Timer.sys.mjs");
      setTimeout(() => finish("timeout-no-callback"), 15000);
    } catch (e) { send("no-timer", { err: String(e) }); }
  } catch (e) {
    finish("threw", { err: String(e) });
  }
})();
