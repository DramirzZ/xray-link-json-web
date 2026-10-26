(function () {
  const $ = (id) => document.getElementById(id);
  const inputEl = $("input");
  const outputEl = $("output");
  const statusEl = $("status");
  function setStatus(msg, type) {
    statusEl.textContent = msg || "";
    statusEl.className = "status" + (type ? " " + type : "");
  }
  function tryParseJSON(text) {
    const t = text.trim();
    if (!t.startsWith("{") && !t.startsWith("[")) return null;
    try { return JSON.parse(t); } catch { return null; }
  }
  function randomTag() {
    const a = ["blue","red","green","swift","calm","bright","quiet","bold"];
    const b = ["fox","owl","wave","star","leaf","wind","stone","lake"];
    return a[Math.floor(Math.random()*a.length)] + "-" + b[Math.floor(Math.random()*b.length)];
  }
  function parseQuery(qs) {
    const params = {};
    if (!qs) return params;
    for (const part of qs.split("&")) {
      const [k, v] = part.split("=");
      if (k) params[decodeURIComponent(k)] = v ? decodeURIComponent(v) : "";
    }
    return params;
  }
  function buildStreamSettings(params) {
    const network = (params.type || params.net || "tcp").toLowerCase();
    const security = (params.security || params.tls || "none").toLowerCase();
    const stream = { network };
    if (network === "ws" || network === "websocket") {
      stream.network = "ws";
      stream.wsSettings = { path: params.path || "/", headers: params.host ? { Host: params.host } : undefined };
      if (!stream.wsSettings.headers) delete stream.wsSettings.headers;
    } else if (network === "grpc") {
      stream.grpcSettings = { serviceName: params.serviceName || params.path || "" };
    } else if (network === "h2" || network === "http") {
      stream.network = "http";
      stream.httpSettings = { path: params.path ? [params.path] : ["/"], host: params.host ? [params.host] : undefined };
      if (!stream.httpSettings.host) delete stream.httpSettings.host;
    } else if (network === "xhttp" || network === "splithttp") {
      stream.network = "xhttp";
      stream.xhttpSettings = { path: params.path || "/", host: params.host || undefined, mode: params.mode || undefined };
      Object.keys(stream.xhttpSettings).forEach((k) => { if (stream.xhttpSettings[k] == null) delete stream.xhttpSettings[k]; });
    }
    if (security === "tls") {
      stream.security = "tls";
      stream.tlsSettings = {
        serverName: params.sni || params.peer || params.host || undefined,
        fingerprint: params.fp || undefined,
        alpn: params.alpn ? params.alpn.split(",") : undefined,
        allowInsecure: params.allowInsecure === "1" || params.allowInsecure === "true"
      };
      Object.keys(stream.tlsSettings).forEach((k) => { if (stream.tlsSettings[k] == null || stream.tlsSettings[k] === false) delete stream.tlsSettings[k]; });
    } else if (security === "reality") {
      stream.security = "reality";
      stream.realitySettings = {
        serverName: params.sni || params.peer || undefined,
        fingerprint: params.fp || "chrome",
        publicKey: params.pbk || undefined,
        shortId: params.sid || undefined,
        spiderX: params.spx || undefined
      };
      Object.keys(stream.realitySettings).forEach((k) => { if (stream.realitySettings[k] == null) delete stream.realitySettings[k]; });
    } else { stream.security = "none"; }
    return stream;
  }
  function parseVless(link) {
    const m = link.match(/^vless:\/\/([^@]+)@([^:/?#]+):(\d+)\??([^#]*)#?(.*)$/i);
    if (!m) throw new Error("invalid vless format");
    const [, id, address, portStr, qs, fragment] = m;
    const params = parseQuery(qs);
    const tag = fragment ? decodeURIComponent(fragment) : randomTag();
    const outbound = {
      protocol: "vless", tag,
      settings: { vnext: [{ address, port: parseInt(portStr, 10), users: [{ id, encryption: params.encryption || "none", flow: params.flow || undefined }] }] },
      streamSettings: buildStreamSettings(params)
    };
    if (!outbound.settings.vnext[0].users[0].flow) delete outbound.settings.vnext[0].users[0].flow;
    return { outbounds: [outbound] };
  }
  function parseVmess(link) {
    const b64 = link.slice(8).trim();
    let raw; try { raw = atob(b64.replace(/-/g, "+").replace(/_/g, "/")); } catch { throw new Error("vmess base64 decode failed"); }
    let obj; try { obj = JSON.parse(raw); } catch { throw new Error("invalid vmess JSON"); }
    const params = { type: obj.net || "tcp", security: obj.tls || "none", path: obj.path, host: obj.host, sni: obj.sni, fp: obj.fp, alpn: obj.alpn, serviceName: obj.path };
    return { outbounds: [{ protocol: "vmess", tag: obj.ps || randomTag(), settings: { vnext: [{ address: obj.add, port: parseInt(obj.port, 10), users: [{ id: obj.id, alterId: parseInt(obj.aid || "0", 10), security: obj.scy || "auto" }] }] }, streamSettings: buildStreamSettings(params) }] };
  }
  function parseTrojan(link) {
    const m = link.match(/^trojan:\/\/([^@]+)@([^:/?#]+):(\d+)\??([^#]*)#?(.*)$/i);
    if (!m) throw new Error("invalid trojan format");
    const [, password, address, portStr, qs, fragment] = m;
    const params = parseQuery(qs);
    if (!params.security && (params.sni || params.fp || params.pbk)) params.security = params.pbk ? "reality" : "tls";
    return { outbounds: [{ protocol: "trojan", tag: fragment ? decodeURIComponent(fragment) : randomTag(), settings: { servers: [{ address, port: parseInt(portStr, 10), password: decodeURIComponent(password) }] }, streamSettings: buildStreamSettings(params) }] };
  }
  function parseSS(link) {
    let body = link.slice(5); let tag = randomTag();
    const hashIdx = body.indexOf("#");
    if (hashIdx !== -1) { tag = decodeURIComponent(body.slice(hashIdx + 1)); body = body.slice(0, hashIdx); }
    let method, password, address, port;
    if (body.includes("@")) {
      const at = body.lastIndexOf("@"); const userinfo = body.slice(0, at); const hostport = body.slice(at + 1);
      const colon = userinfo.indexOf(":"); if (colon === -1) throw new Error("invalid ss format");
      method = decodeURIComponent(userinfo.slice(0, colon)); password = decodeURIComponent(userinfo.slice(colon + 1));
      const hp = hostport.split(":"); address = hp[0]; port = parseInt(hp[1], 10);
    } else {
      let decoded; try { decoded = atob(body.replace(/-/g, "+").replace(/_/g, "/")); } catch { throw new Error("ss base64 decode failed"); }
      const at = decoded.lastIndexOf("@"); if (at === -1) throw new Error("invalid ss format");
      const userinfo = decoded.slice(0, at); const hostport = decoded.slice(at + 1);
      const colon = userinfo.indexOf(":"); method = userinfo.slice(0, colon); password = userinfo.slice(colon + 1);
      const hp = hostport.split(":"); address = hp[0]; port = parseInt(hp[1], 10);
    }
    return { outbounds: [{ protocol: "shadowsocks", tag, settings: { servers: [{ address, port, method, password }] } }] };
  }
  function parseSocks(link) {
    const m = link.match(/^socks5?h?:\/\/(?:([^:@]+):([^@]*)@)?([^:/?#]+):(\d+)#?(.*)$/i);
    if (!m) throw new Error("invalid socks format");
    const [, user, pass, address, portStr, fragment] = m;
    const server = { address, port: parseInt(portStr, 10) };
    if (user) server.users = [{ user: decodeURIComponent(user), pass: decodeURIComponent(pass || "") }];
    return { outbounds: [{ protocol: "socks", tag: fragment ? decodeURIComponent(fragment) : randomTag(), settings: { servers: [server] } }] };
  }
  function linkToJson(text) {
    const lines = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
    if (!lines.length) throw new Error("empty input");
    const outbounds = [];
    for (const line of lines) {
      const lower = line.toLowerCase(); let cfg;
      if (lower.startsWith("vless://")) cfg = parseVless(line);
      else if (lower.startsWith("vmess://")) cfg = parseVmess(line);
      else if (lower.startsWith("trojan://")) cfg = parseTrojan(line);
      else if (lower.startsWith("ss://")) cfg = parseSS(line);
      else if (lower.startsWith("socks")) cfg = parseSocks(line);
      else throw new Error("unsupported protocol: " + line.slice(0, 20));
      outbounds.push(...cfg.outbounds);
    }
    return { outbounds };
  }
  function streamParams(stream) {
    if (!stream) return {};
    const p = {}; const net = stream.network || "tcp"; p.type = net;
    if (stream.security && stream.security !== "none") p.security = stream.security;
    if (net === "ws" && stream.wsSettings) { if (stream.wsSettings.path) p.path = stream.wsSettings.path; if (stream.wsSettings.headers && stream.wsSettings.headers.Host) p.host = stream.wsSettings.headers.Host; }
    if (net === "grpc" && stream.grpcSettings && stream.grpcSettings.serviceName) p.serviceName = stream.grpcSettings.serviceName;
    if ((net === "xhttp" || net === "splithttp") && stream.xhttpSettings) { if (stream.xhttpSettings.path) p.path = stream.xhttpSettings.path; if (stream.xhttpSettings.host) p.host = stream.xhttpSettings.host; if (stream.xhttpSettings.mode) p.mode = stream.xhttpSettings.mode; }
    if (stream.tlsSettings) { if (stream.tlsSettings.serverName) p.sni = stream.tlsSettings.serverName; if (stream.tlsSettings.fingerprint) p.fp = stream.tlsSettings.fingerprint; if (stream.tlsSettings.alpn) p.alpn = Array.isArray(stream.tlsSettings.alpn) ? stream.tlsSettings.alpn.join(",") : stream.tlsSettings.alpn; }
    if (stream.realitySettings) { if (stream.realitySettings.serverName) p.sni = stream.realitySettings.serverName; if (stream.realitySettings.fingerprint) p.fp = stream.realitySettings.fingerprint; if (stream.realitySettings.publicKey) p.pbk = stream.realitySettings.publicKey; if (stream.realitySettings.shortId) p.sid = stream.realitySettings.shortId; if (stream.realitySettings.spiderX) p.spx = stream.realitySettings.spiderX; }
    return p;
  }
  function qs(params) { return Object.entries(params).filter(([, v]) => v != null && v !== "").map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v)).join("&"); }
  function outboundToVless(ob) {
    const s = ob.settings || {}; let address, port, id, encryption, flow;
    if (s.vnext && s.vnext[0]) { address = s.vnext[0].address; port = s.vnext[0].port; const u = (s.vnext[0].users && s.vnext[0].users[0]) || {}; id = u.id; encryption = u.encryption || "none"; flow = u.flow; }
    else { address = s.address; port = s.port; id = s.id; encryption = s.encryption || "none"; flow = s.flow; }
    if (!address || !port || !id) throw new Error("vless incomplete");
    const p = streamParams(ob.streamSettings); p.encryption = encryption; if (flow) p.flow = flow;
    const query = qs(p); const tag = ob.tag ? "#" + encodeURIComponent(ob.tag) : "";
    return `vless://${id}@${address}:${port}${query ? "?" + query : ""}${tag}`;
  }
  function outboundToVmess(ob) {
    const s = ob.settings || {}; const v = s.vnext && s.vnext[0]; if (!v) throw new Error("vmess incomplete");
    const u = (v.users && v.users[0]) || {}; const stream = ob.streamSettings || {};
    const obj = { v: "2", ps: ob.tag || "", add: v.address, port: String(v.port), id: u.id, aid: String(u.alterId || 0), scy: u.security || "auto", net: stream.network || "tcp", type: "none", host: "", path: "", tls: stream.security === "tls" ? "tls" : "", sni: "", fp: "" };
    if (stream.wsSettings) { obj.path = stream.wsSettings.path || ""; obj.host = (stream.wsSettings.headers && stream.wsSettings.headers.Host) || ""; }
    if (stream.tlsSettings) { obj.sni = stream.tlsSettings.serverName || ""; obj.fp = stream.tlsSettings.fingerprint || ""; }
    return "vmess://" + btoa(unescape(encodeURIComponent(JSON.stringify(obj))));
  }
  function outboundToTrojan(ob) {
    const s = ob.settings || {}; const srv = s.servers && s.servers[0]; if (!srv) throw new Error("trojan incomplete");
    const p = streamParams(ob.streamSettings); const query = qs(p); const tag = ob.tag ? "#" + encodeURIComponent(ob.tag) : "";
    return `trojan://${encodeURIComponent(srv.password)}@${srv.address}:${srv.port}${query ? "?" + query : ""}${tag}`;
  }
  function outboundToSS(ob) {
    const s = ob.settings || {}; const srv = s.servers && s.servers[0]; if (!srv) throw new Error("ss incomplete");
    const tag = ob.tag ? "#" + encodeURIComponent(ob.tag) : "";
    return `ss://${btoa(srv.method + ":" + srv.password)}@${srv.address}:${srv.port}${tag}`;
  }
  function outboundToSocks(ob) {
    const s = ob.settings || {}; const srv = s.servers && s.servers[0]; if (!srv) throw new Error("socks incomplete");
    let auth = ""; if (srv.users && srv.users[0]) auth = encodeURIComponent(srv.users[0].user) + ":" + encodeURIComponent(srv.users[0].pass || "") + "@";
    const tag = ob.tag ? "#" + encodeURIComponent(ob.tag) : "";
    return `socks5://${auth}${srv.address}:${srv.port}${tag}`;
  }
  function jsonToLinks(obj) {
    let outbounds = [];
    if (Array.isArray(obj)) outbounds = obj;
    else if (obj.outbounds) outbounds = obj.outbounds;
    else if (obj.protocol) outbounds = [obj];
    else throw new Error("unknown JSON structure (need outbounds)");
    const links = [];
    for (const ob of outbounds) {
      if (!ob || !ob.protocol) continue;
      const protocol = ob.protocol.toLowerCase();
      try {
        if (protocol === "vless") links.push(outboundToVless(ob));
        else if (protocol === "vmess") links.push(outboundToVmess(ob));
        else if (protocol === "trojan") links.push(outboundToTrojan(ob));
        else if (protocol === "shadowsocks") links.push(outboundToSS(ob));
        else if (protocol === "socks") links.push(outboundToSocks(ob));
      } catch (e) { links.push("# error " + (ob.tag || protocol) + ": " + e.message); }
    }
    if (!links.length) throw new Error("no convertible outbound");
    return links.join("\n");
  }
  function convert() {
    const raw = inputEl.value.trim();
    if (!raw) { setStatus("please provide input", "err"); return; }
    try {
      const asJson = tryParseJSON(raw);
      let result;
      if (asJson) { result = jsonToLinks(asJson); setStatus("JSON -> link(s)", "ok"); }
      else { result = JSON.stringify(linkToJson(raw), null, 2); setStatus("link -> JSON", "ok"); }
      outputEl.value = result;
    } catch (e) { outputEl.value = ""; setStatus("error: " + e.message, "err"); }
  }
  $("btnConvert").addEventListener("click", convert);
  $("btnClear").addEventListener("click", () => { inputEl.value = ""; outputEl.value = ""; setStatus(""); });
  $("btnCopy").addEventListener("click", async () => {
    if (!outputEl.value) return;
    try { await navigator.clipboard.writeText(outputEl.value); setStatus("copied", "ok"); }
    catch { outputEl.select(); document.execCommand("copy"); setStatus("copied", "ok"); }
  });
  $("btnSample").addEventListener("click", () => {
    inputEl.value = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&host=example.com&path=%2Fws&fp=chrome#sample-vless";
    setStatus("sample loaded", "ok");
  });
  inputEl.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") convert(); });
})();
