"use strict";

const find = (id) => document.getElementById(id);
const source = find("routing-spec");
const editor = find("routing-editor");
const error = find("routing-error");
const customProtocols = {
  socks: "SOCKS5", http: "HTTP", trusttunnel: "TrustTunnel", freedom: "Freedom",
  blackhole: "Blackhole", vless: "VLESS", vmess: "VMess", trojan: "Trojan",
  shadowsocks: "Shadowsocks", xray: "Other Xray protocol"
};
let spec;
let fieldReaders = [];
let draggedRule = null;

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text) element.textContent = text;
  if (className) element.className = className;
  return element;
}

function edit(element, handler) {
  element.onclick = () => {
    if (!collect()) return;
    handler();
    redraw();
  };
  return element;
}

function button(text, handler) {
  const element = node("button", text);
  element.type = "button";
  return edit(element, handler);
}

function icon(pathData) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  for (const [key, value] of Object.entries({
    width: "14", height: "14", viewBox: "0 0 16 16", fill: "none",
    stroke: "currentColor", "stroke-width": "1.6", "stroke-linecap": "round",
    "stroke-linejoin": "round", "aria-hidden": "true"
  })) svg.setAttribute(key, value);
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", pathData);
  svg.append(path);
  return svg;
}

function iconButton(label, handler, pathData) {
  const element = node("button", "", "icon-button small");
  element.type = "button";
  element.setAttribute("aria-label", label);
  element.append(icon(pathData));
  return edit(element, handler);
}

function expandButton(label, rowId) {
  const element = node("button", "", "icon-button small");
  element.type = "button";
  element.dataset.expand = "";
  element.setAttribute("aria-controls", rowId);
  element.setAttribute("aria-expanded", "false");
  element.setAttribute("aria-label", label);
  element.append(icon("M6 3.5 10.5 8 6 12.5"));
  return element;
}

function openDetail(rowId, focus) {
  const row = find(rowId);
  if (!row) return;
  row.classList.add("open");
  const toggle = document.querySelector(`[aria-controls="${rowId}"]`);
  if (toggle) toggle.setAttribute("aria-expanded", "true");
  if (focus) {
    const control = row.querySelector("input, textarea, select");
    if (control) control.focus();
  }
}

function cellControl(element, label) {
  element.setAttribute("aria-label", label);
  element.addEventListener("change", collect);
  return element;
}

function field(container, title, element) {
  const label = node("label", title);
  element.setAttribute("aria-label", title);
  label.append(element);
  container.append(label);
  element.addEventListener("change", collect);
  return element;
}

function input(container, title, value, placeholder = "", multiline = false) {
  const element = node(multiline ? "textarea" : "input");
  element.value = value ?? "";
  element.placeholder = placeholder;
  element.spellcheck = false;
  if (multiline) {
    element.className = "code";
    element.rows = 5;
  }
  return field(container, title, element);
}

function options(select, choices, current) {
  select.replaceChildren();
  for (const [value, label] of Object.entries(choices)) select.add(new Option(label, value));
  if (current !== undefined && !Object.hasOwn(choices, current)) {
    select.add(new Option(current || "Select an outbound", current));
  }
  select.value = current;
  return select;
}

function targets() {
  return Object.fromEntries(["direct", "block", ...spec.outbounds.map((outbound) => outbound.tag)]
    .filter(Boolean).map((tag) => [tag, tag]));
}

function showRoutingOrder() {
  const entries = spec.rules.map((rule, index) =>
    node("li", `Rule ${index + 1} → ${rule.outboundTag || "Choose an outbound"}`));
  find("routing-order").replaceChildren(...entries, node("li", `Default → ${spec.default}`));
}

function destinationText(outbound) {
  const kind = outbound.protocol;
  if (kind === "freedom" || kind === "blackhole") return "—";
  if (kind === "trusttunnel") {
    return outbound.endpoint?.hostname || (typeof outbound.config === "string" ? "Imported TOML" : "—");
  }
  const servers = outbound.settings?.servers;
  if (Array.isArray(servers) && servers.length) {
    if (servers.length > 1) return `${servers.length} servers`;
    const server = servers[0];
    return server?.address ? server.address + (server.port !== undefined ? `:${server.port}` : "") : "—";
  }
  const address = outbound.settings?.address;
  if (address) return address + (outbound.settings.port !== undefined ? `:${outbound.settings.port}` : "");
  return "—";
}

function listSummary(values) {
  if (!values?.length) return "Any";
  return values[0] + (values.length > 1 ? ` +${values.length - 1}` : "");
}

function syncSummaries() {
  const domains = document.querySelectorAll("[data-domains]");
  const ips = document.querySelectorAll("[data-ips]");
  spec.rules.forEach((rule, index) => {
    if (domains[index]) {
      domains[index].textContent = listSummary(rule.domain);
      domains[index].title = (rule.domain ?? []).join("\n");
    }
    if (ips[index]) {
      ips[index].textContent = listSummary(rule.ip);
      ips[index].title = (rule.ip ?? []).join("\n");
    }
  });
  const destinations = document.querySelectorAll("[data-destination]");
  spec.outbounds.forEach((outbound, index) => {
    if (destinations[index]) destinations[index].textContent = destinationText(outbound);
  });
}

function collect() {
  try {
    for (const read of fieldReaders) read();
    spec.enabled = find("routing-enabled").checked;
    spec.default = find("routing-default").value;
    spec.domainStrategy = find("routing-strategy").value;
    source.value = JSON.stringify(spec, null, 2);
    syncSummaries();
    showRoutingOrder();
    error.hidden = true;
    return true;
  } catch (problem) {
    error.textContent = problem.message;
    error.hidden = false;
    return false;
  }
}

function detailRow(id, columns) {
  const row = node("tr", "", "detail-row");
  row.id = id;
  const cell = node("td");
  cell.colSpan = columns;
  const box = node("div", "", "detail-grid");
  cell.append(box);
  row.append(cell);
  return [row, box];
}

function redraw() {
  fieldReaders = [];
  find("routing-enabled").checked = spec.enabled;
  find("routing-strategy").value = spec.domainStrategy;
  options(find("routing-default"), targets(), spec.default);

  const outbounds = find("outbounds");
  outbounds.replaceChildren();
  if (!spec.outbounds.length) {
    const row = node("tr");
    const cell = node("td", "No custom outbounds. Traffic uses direct or block.", "empty");
    cell.colSpan = 4;
    row.append(cell);
    outbounds.append(row);
  }
  spec.outbounds.forEach((outbound, index) => {
    const row = node("tr");
    const nameCell = node("td");
    const tag = cellControl(node("input"), "Outbound name");
    tag.value = outbound.tag ?? "";
    tag.placeholder = "proxy";
    tag.spellcheck = false;
    nameCell.append(tag);
    const kind = Object.hasOwn(customProtocols, outbound.protocol) ? outbound.protocol : "xray";
    const protocolCell = node("td");
    const protocol = cellControl(options(node("select"), customProtocols, kind), "Type");
    protocolCell.append(protocol);
    const destinationCell = node("td", "", "mono subtle");
    destinationCell.dataset.destination = "";
    const actionsCell = node("td", "", "actions-cell");
    const actions = node("div", "", "actions");
    const detailId = `outbound-detail-${index}`;
    actions.append(expandButton(`Edit details for outbound ${outbound.tag || index + 1}`, detailId));
    const remove = button("Delete", () => spec.outbounds.splice(index, 1));
    remove.className = "small danger";
    actions.append(remove);
    actionsCell.append(actions);
    row.append(nameCell, protocolCell, destinationCell, actionsCell);
    outbounds.append(row);

    const [detail, box] = detailRow(detailId, 4);
    outbounds.append(detail);
    let address, port, user, password, advanced;
    const typed = typedForm(box, outbound);
    const cascade = kind === "trusttunnel" ? cascadeForm(box, outbound) : null;
    const server = outbound.settings?.servers?.[0];
    const proxy = ["socks", "http"].includes(kind);
    const {tag: _tag, protocol: _protocol, ...extra} = outbound;
    const emptyProxy = !Object.keys(extra).length;
    const simple = proxy && outbound.settings?.servers?.length === 1
      && Object.keys(extra).length === 1
      && Object.keys(outbound.settings).every((key) => key === "servers")
      && Object.keys(server ?? {}).every((key) => ["address", "port", "users"].includes(key))
      && (!server?.users || (server.users.length <= 1
        && Object.keys(server.users[0] ?? {}).every((key) => ["user", "pass"].includes(key))));
    if (proxy && (simple || emptyProxy)) {
      const grid = node("div", "", "grid");
      box.append(grid);
      address = input(grid, "Proxy address", server?.address, "proxy.example.com");
      port = input(grid, "Port", server?.port, "1080");
      port.inputMode = "numeric";
      user = input(grid, "Username", server?.users?.[0]?.user);
      password = input(grid, "Password", server?.users?.[0]?.pass);
      password.type = "password";
    } else if (!typed && !cascade && (kind === "xray" || proxy || Object.keys(outbound).length > 2)) {
      advanced = input(box, "Xray outbound options (JSON)", JSON.stringify({protocol: _protocol, ...extra}, null, 2), "", true);
    } else if (!box.childNodes.length) {
      box.append(node("p", "No additional options for this protocol.", "subtle"));
    }
    tag.addEventListener("change", () => {
      if (!collect()) return;
      options(find("routing-default"), targets(), spec.default);
      for (const select of document.querySelectorAll(".rule-target")) {
        options(select, targets(), select.value);
      }
    });
    protocol.addEventListener("change", () => {
      if (collect()) redraw();
    });
    fieldReaders.push(() => {
      const nextTag = tag.value.trim();
      if (nextTag && outbound.tag !== nextTag) {
        if (find("routing-default").value === outbound.tag) {
          find("routing-default").selectedOptions[0].value = nextTag;
        }
        for (const select of document.querySelectorAll(".rule-target")) {
          if (select.value === outbound.tag) select.selectedOptions[0].value = nextTag;
        }
      }
      if (protocol.value !== kind) {
        spec.outbounds[index] = {tag: nextTag, protocol: protocol.value === "xray" ? "wireguard" : protocol.value};
      } else if (typed) {
        spec.outbounds[index] = {...typed(), tag: nextTag};
      } else if (address) {
        const target = {address: address.value.trim(), port: Number(port.value)};
        if (user.value || password.value) target.users = [{user: user.value, pass: password.value}];
        spec.outbounds[index] = {tag: nextTag, protocol: kind, settings: {servers: [target]}};
      } else if (cascade) {
        spec.outbounds[index] = {tag: nextTag, protocol: kind, ...cascade()};
      } else if (advanced) {
        const config = JSON.parse(advanced.value);
        if (!config || typeof config !== "object" || Array.isArray(config)) {
          throw new Error("Xray outbound options must be a JSON object.");
        }
        spec.outbounds[index] = {...config, tag: nextTag};
      } else {
        spec.outbounds[index] = {tag: nextTag, protocol: outbound.protocol};
      }
      outbound = spec.outbounds[index];
    });
  });

  const rules = find("rules");
  rules.replaceChildren();
  if (!spec.rules.length) {
    const row = node("tr");
    const cell = node("td", "No rules. Unmatched traffic uses the default outbound.", "empty");
    cell.colSpan = 6;
    row.append(cell);
    rules.append(row);
  }
  spec.rules.forEach((rule, index) => {
    const row = node("tr");
    const priority = node("td", String(index + 1), "num priority");
    const domainsCell = node("td");
    const domainsSummary = node("span", "", "truncate rule-summary");
    domainsSummary.dataset.domains = "";
    domainsCell.append(domainsSummary);
    const ipsCell = node("td");
    const ipsSummary = node("span", "", "truncate rule-summary");
    ipsSummary.dataset.ips = "";
    ipsCell.append(ipsSummary);
    const portsCell = node("td", "", "mono");
    const targetCell = node("td");
    const target = cellControl(options(node("select", "", "rule-target"), targets(), rule.outboundTag), "Outbound");
    targetCell.append(target);
    const actionsCell = node("td", "", "actions-cell");
    const actions = node("div", "", "actions");
    const handle = node("span", "", "drag-handle");
    handle.title = "Drag to reorder";
    handle.setAttribute("aria-label", `Drag rule ${index + 1} to reorder`);
    handle.append(icon("M5 4h.01M11 4h.01M5 8h.01M11 8h.01M5 12h.01M11 12h.01"));
    handle.draggable = true;
    handle.addEventListener("dragstart", (event) => {
      if (!collect()) return event.preventDefault();
      draggedRule = index;
      event.dataTransfer.setData("text/plain", "ttui-rule");
    });
    handle.addEventListener("dragend", () => { draggedRule = null; });
    row.addEventListener("dragover", (event) => {
      if (draggedRule !== null) event.preventDefault();
    });
    row.addEventListener("drop", (event) => {
      if (draggedRule === null) return;
      event.preventDefault();
      const [moved] = spec.rules.splice(draggedRule, 1);
      spec.rules.splice(index, 0, moved);
      draggedRule = null;
      redraw();
    });
    actions.append(handle);
    for (const [delta, label, pathData] of [
      [-1, "Move rule up", "M8 12V4M4.5 7.5 8 4l3.5 3.5"],
      [1, "Move rule down", "M8 4v8M4.5 8.5 8 12l3.5-3.5"]
    ]) {
      const move = iconButton(label, () => {
        [spec.rules[index], spec.rules[index + delta]] = [spec.rules[index + delta], spec.rules[index]];
      }, pathData);
      move.disabled = index + delta < 0 || index + delta >= spec.rules.length;
      actions.append(move);
    }
    const detailId = `rule-detail-${index}`;
    actions.append(expandButton(`Edit details for rule ${index + 1}`, detailId));
    const remove = button("Delete", () => spec.rules.splice(index, 1));
    remove.className = "small danger";
    actions.append(remove);
    actionsCell.append(actions);
    row.append(priority, domainsCell, ipsCell, portsCell, targetCell, actionsCell);
    rules.append(row);

    const [detail, box] = detailRow(detailId, 6);
    rules.append(detail);
    const domains = input(box, "Domains, one per line", rule.domain?.join("\n"), "regexp:^.*\\.example\\.org$", true);
    const ips = input(box, "IP addresses and CIDR ranges, one per line", rule.ip?.join("\n"), "geoip:private", true);
    const network = field(box, "Network", options(node("select"), {"": "Any", tcp: "TCP", udp: "UDP"}, rule.network ?? ""));
    domains.rows = ips.rows = 2;
    const port = cellControl(node("input"), "Destination ports");
    port.value = rule.port ?? "";
    port.placeholder = "80,443,1000-2000";
    port.spellcheck = false;
    portsCell.append(port);
    fieldReaders.push(() => {
      const updated = {...rule, outboundTag: target.value};
      for (const [key, element] of [["domain", domains], ["ip", ips]]) {
        const values = element.value.split("\n").map((line) => line.trim()).filter(Boolean);
        if (values.length) updated[key] = values;
        else delete updated[key];
      }
      if (port.value.trim()) updated.port = port.value.trim();
      else delete updated.port;
      if (network.value) updated.network = network.value;
      else delete updated.network;
      spec.rules[index] = updated;
    });
  });
  source.value = JSON.stringify(spec, null, 2);
  syncSummaries();
  showRoutingOrder();
}

function load() {
  try {
    const data = JSON.parse(source.value);
    if (!data || !Array.isArray(data.rules) || !Array.isArray(data.outbounds)) {
      throw new Error("Provide outbounds and rules arrays.");
    }
    spec = data;
    redraw();
    editor.inert = false;
    editor.hidden = false;
    error.hidden = true;
    return true;
  } catch (problem) {
    editor.inert = true;
    error.textContent = problem.message;
    error.hidden = false;
    return false;
  }
}

for (const id of ["routing-enabled", "routing-default", "routing-strategy"]) {
  find(id).addEventListener("change", collect);
}
find("add-outbound").onclick = () => {
  if (!collect()) return;
  spec.outbounds.push({tag: "", protocol: "socks"});
  redraw();
  openDetail(`outbound-detail-${spec.outbounds.length - 1}`, true);
};
find("add-rule").onclick = () => {
  if (!collect()) return;
  spec.rules.push({outboundTag: spec.default});
  redraw();
  openDetail(`rule-detail-${spec.rules.length - 1}`, true);
};
source.addEventListener("input", () => {
  editor.inert = true;
  error.textContent = "The JSON has changed. Load it into the editor to continue using the form.";
  error.hidden = false;
});
find("load-spec").hidden = false;
find("load-spec").addEventListener("click", load);
find("routing-form").addEventListener("submit", (event) => {
  if (!editor.inert && !collect()) event.preventDefault();
});
if (load()) find("routing-raw").open = false;