"use strict";

const typedOutbounds = {
  vless: {id: "User ID", encryption: "Encryption", flow: "Flow"},
  vmess: {id: "User ID", security: "VMess encryption"},
  trojan: {password: "Password"},
  shadowsocks: {password: "Password", method: "Cipher"}
};
const transports = {raw: "TCP", ws: "WebSocket", grpc: "gRPC", xhttp: "XHTTP"};
const transportFields = {
  ws: ["host", "path"], grpc: ["serviceName", "authority"], xhttp: ["host", "path", "mode"]
};
const securityFields = {
  tls: ["serverName", "fingerprint"],
  reality: ["serverName", "fingerprint", "password", "shortId", "spiderX"]
};
const fieldLabels = {
  host: "HTTP host", path: "HTTP path", mode: "XHTTP mode", serviceName: "gRPC service name",
  authority: "gRPC authority", serverName: "TLS server name", fingerprint: "TLS fingerprint",
  password: "REALITY public key", shortId: "REALITY short ID", spiderX: "REALITY spider path"
};
const permittedValues = {
  "VMess encryption": {auto: "Automatic", "aes-128-gcm": "AES-128-GCM", "chacha20-poly1305": "ChaCha20-Poly1305", none: "None", zero: "Zero"},
  Cipher: Object.fromEntries(["aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"].map((method) => [method, method])),
  Flow: {"": "None", "xtls-rprx-vision": "XTLS Vision", "xtls-rprx-vision-udp443": "XTLS Vision (UDP 443)"}
};

function cascadeForm(box, outbound) {
  const imported = typeof outbound.config === "string" && !outbound.endpoint;
  const mode = field(box, "Cascade configuration", options(node("select"),
    {fields: "Connection fields", toml: "Paste exported TOML"}, imported ? "toml" : "fields"));
  mode.addEventListener("change", () => { if (collect()) redraw(); });
  if (imported) {
    const config = input(box, "Remote endpoint TOML", outbound.config, "Paste the TrustTunnel TOML export", true);
    return () => mode.value === "toml" ? {config: config.value} : {endpoint: {}};
  }
  const settings = outbound.endpoint ?? {};
  const grid = node("div", "", "grid");
  box.append(grid);
  const host = input(grid, "TLS hostname", settings.hostname, "vpn.example.com");
  const user = input(grid, "Username", settings.username);
  const password = input(grid, "Password", settings.password);
  password.type = "password";
  const upstream = field(grid, "Upstream protocol", options(node("select"),
    {http2: "HTTP/2", http3: "HTTP/3"}, settings.upstream_protocol ?? "http2"));
  const addresses = input(box, "Endpoint addresses, one per line", settings.addresses?.join("\n"),
    "vpn.example.com:443", true);
  addresses.rows = 2;
  const certificate = input(box, "Endpoint certificate (optional PEM)", settings.certificate, "", true);
  return () => mode.value === "fields" ? {endpoint: {
    ...settings, hostname: host.value.trim(), username: user.value.trim(), password: password.value,
    upstream_protocol: upstream.value, addresses: addresses.value.split("\n").map((line) => line.trim()).filter(Boolean),
    certificate: certificate.value.trim()
  }} : {config: ""};
}

function typedForm(box, outbound) {
  const {protocol, settings = {}, streamSettings: stream = {}} = outbound;
  const schema = Object.hasOwn(typedOutbounds, protocol) && typedOutbounds[protocol];
  if (!schema || !settings || !stream || typeof settings !== "object" || typeof stream !== "object"
      || Array.isArray(settings) || Array.isArray(stream) || settings.vnext || settings.servers) return null;
  const grid = node("div", "", "grid");
  box.append(grid);
  const address = input(grid, "Remote address", settings.address, "proxy.example.com");
  const port = input(grid, "Port", settings.port ?? 443);
  port.inputMode = "numeric";
  const defaults = {encryption: "none", security: "auto", method: "aes-128-gcm"};
  const controls = Object.entries(schema).map(([key, label]) => {
    const value = settings[key] ?? defaults[key] ?? "";
    const element = permittedValues[label] ? field(grid, label, options(node("select"), permittedValues[label], value))
      : input(grid, label, value);
    if (key === "password") element.type = "password";
    return [key, element];
  });

  const network = stream.network ?? "raw";
  const transport = field(grid, "Transport", options(node("select"), transports, network));
  const security = stream.security ?? (protocol === "trojan" && !outbound.streamSettings ? "tls" : "none");
  const tlsMode = field(grid, "Transport security", options(node("select"), {none: "None", tls: "TLS", reality: "REALITY"}, security));
  const streamControls = [];
  for (const key of [network, security]) {
    const keys = transportFields[key] || securityFields[key];
    if (!keys) continue;
    const section = key + "Settings";
    streamControls.push([section, keys.map((name) => [
      name, input(grid, fieldLabels[name], stream[section]?.[name] ?? (key === "reality" && name === "fingerprint" ? "chrome" : ""))
    ])]);
  }
  for (const select of [transport, tlsMode]) {
    select.addEventListener("change", () => { if (collect()) redraw(); });
  }
  return () => {
    const result = {...outbound, settings: {...settings, address: address.value.trim(), port: Number(port.value)}};
    for (const [key, element] of controls) result.settings[key] = key === "password" ? element.value : element.value.trim();
    const nextStream = {...stream, network: transport.value, security: tlsMode.value};
    for (const [section, fields] of streamControls) {
      nextStream[section] = {...stream[section]};
      for (const [key, element] of fields) {
        if (element.value.trim()) nextStream[section][key] = element.value.trim();
        else delete nextStream[section][key];
      }
    }
    if (transport.value !== network) {
      delete nextStream[network + "Settings"];
      if (network === "tcp" || network === "raw") {
        delete nextStream.tcpSettings;
        delete nextStream.rawSettings;
      }
    }
    if (tlsMode.value !== security) delete nextStream[security + "Settings"];
    result.streamSettings = nextStream;
    return result;
  };
}
