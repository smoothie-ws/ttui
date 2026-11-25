"use strict";

const find = (id) => document.getElementById(id);
const source = find("routing-spec");
const editor = find("routing-editor");
const error = find("routing-error");
const customProtocols = {
  socks: "SOCKS5", http: "HTTP", trusttunnel: "TrustTunnel", freedom: "Freedom",
  blackhole: "Блокировка", xray: "Другой протокол Xray"
};
let spec;
let fieldReaders = [];

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text) element.textContent = text;
  if (className) element.className = className;
  return element;
}

function button(text, handler) {
  const element = node("button", text);
  element.type = "button";
  element.addEventListener("click", () => {
    if (collect()) handler();
  });
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
    select.add(new Option(current || "Выберите выход", current));
  }
  select.value = current;
  return select;
}

function targets() {
  return Object.fromEntries(["direct", "block", ...spec.outbounds.map((outbound) => outbound.tag)]
    .filter(Boolean).map((tag) => [tag, tag]));
}

function collect() {
  try {
    for (const read of fieldReaders) read();
    spec.enabled = find("routing-enabled").checked;
    spec.default = find("routing-default").value;
    spec.domainStrategy = find("routing-strategy").value;
    source.value = JSON.stringify(spec, null, 2);
    error.hidden = true;
    return true;
  } catch (problem) {
    error.textContent = problem.message;
    error.hidden = false;
    return false;
  }
}

function redraw() {
  fieldReaders = [];
  find("routing-enabled").checked = spec.enabled;
  find("routing-strategy").value = spec.domainStrategy;
  options(find("routing-default"), targets(), spec.default);
  const outbounds = find("outbounds");
  outbounds.replaceChildren();
  spec.outbounds.forEach((outbound, index) => {
    const box = node("div", "", "editor-item stack");
    const top = node("div", "", "row");
    box.append(top);
    const tag = input(top, "Имя выхода", outbound.tag, "proxy");
    const kind = Object.hasOwn(customProtocols, outbound.protocol) ? outbound.protocol : "xray";
    const protocol = field(top, "Тип", options(node("select"), customProtocols, kind));
    top.append(button("Удалить", () => {
      spec.outbounds.splice(index, 1);
      redraw();
    }));
    let address, port, user, password, advanced;
    const server = outbound.settings?.servers?.[0];
    const proxy = ["socks", "http"].includes(kind);
    const emptyProxy = Object.keys(outbound).every((key) => ["tag", "protocol"].includes(key));
    const simple = proxy && outbound.settings?.servers?.length === 1
      && Object.keys(outbound).every((key) => ["tag", "protocol", "settings"].includes(key))
      && Object.keys(outbound.settings).every((key) => key === "servers")
      && Object.keys(server ?? {}).every((key) => ["address", "port", "users"].includes(key))
      && (!server?.users || (server.users.length <= 1
        && Object.keys(server.users[0] ?? {}).every((key) => ["user", "pass"].includes(key))));
    if (proxy && (simple || emptyProxy)) {
      const grid = node("div", "", "grid");
      box.append(grid);
      address = input(grid, "Адрес прокси", server?.address, "proxy.example.com");
      port = input(grid, "Порт", server?.port, "1080");
      port.inputMode = "numeric";
      user = input(grid, "Логин", server?.users?.[0]?.user);
      password = input(grid, "Пароль", server?.users?.[0]?.pass);
      password.type = "password";
    } else if (kind === "trusttunnel") {
      advanced = input(box, "TOML удалённого endpoint", outbound.config, "Вставьте экспорт TOML из TrustTunnel", true);
    } else if (kind === "xray" || proxy || Object.keys(outbound).length > 2) {
      const {tag: _tag, ...configuration} = outbound;
      advanced = input(box, "Параметры выхода Xray (JSON)", JSON.stringify(configuration, null, 2), "", true);
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
        spec.outbounds[index] = {tag: nextTag, protocol: protocol.value === "xray" ? "vless" : protocol.value};
      } else if (address) {
        const target = {address: address.value.trim(), port: Number(port.value)};
        if (user.value || password.value) target.users = [{user: user.value, pass: password.value}];
        spec.outbounds[index] = {tag: nextTag, protocol: kind, settings: {servers: [target]}};
      } else if (kind === "trusttunnel") {
        spec.outbounds[index] = {tag: nextTag, protocol: kind, config: advanced.value};
      } else if (advanced) {
        const config = JSON.parse(advanced.value);
        if (!config || typeof config !== "object" || Array.isArray(config)) {
          throw new Error("Параметры выхода Xray должны быть объектом JSON.");
        }
        spec.outbounds[index] = {...config, tag: nextTag};
      } else {
        spec.outbounds[index] = {tag: nextTag, protocol: outbound.protocol};
      }
      outbound = spec.outbounds[index];
    });
    outbounds.append(box);
  });

  const rules = find("rules");
  rules.replaceChildren();
  spec.rules.forEach((rule, index) => {
    const box = node("div", "", "editor-item stack");
    const top = node("div", "", "row");
    box.append(top);
    const target = field(top, "Выход", options(node("select", "", "rule-target"), targets(), rule.outboundTag));
    const port = input(top, "Порты назначения", rule.port, "80,443,1000-2000");
    const actions = node("div", "", "actions");
    top.append(actions);
    for (const [delta, label] of [[-1, "Выше"], [1, "Ниже"]]) {
      const move = button(label, () => {
        [spec.rules[index], spec.rules[index + delta]] = [spec.rules[index + delta], spec.rules[index]];
        redraw();
      });
      move.disabled = index + delta < 0 || index + delta >= spec.rules.length;
      actions.append(move);
    }
    actions.append(button("Удалить", () => {
      spec.rules.splice(index, 1);
      redraw();
    }));
    const domains = input(box, "Домены, по одному на строку", rule.domain?.join("\n"), "regexp:^.*\\.example\\.org$", true);
    const ips = input(box, "IP и CIDR, по одному на строку", rule.ip?.join("\n"), "geoip:private", true);
    domains.rows = ips.rows = 2;
    fieldReaders.push(() => {
      const updated = {...rule, outboundTag: target.value};
      for (const [key, element] of [["domain", domains], ["ip", ips]]) {
        const values = element.value.split("\n").map((line) => line.trim()).filter(Boolean);
        if (values.length) updated[key] = values;
        else delete updated[key];
      }
      if (port.value.trim()) updated.port = port.value.trim();
      else delete updated.port;
      spec.rules[index] = updated;
    });
    rules.append(box);
  });
  source.value = JSON.stringify(spec, null, 2);
}

function load() {
  try {
    const data = JSON.parse(source.value);
    if (!data || !Array.isArray(data.rules) || !Array.isArray(data.outbounds)) {
      throw new Error("Укажите массивы outbounds и rules.");
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
find("add-outbound").addEventListener("click", () => {
  if (!collect()) return;
  spec.outbounds.push({tag: "", protocol: "socks"});
  redraw();
});
find("add-rule").addEventListener("click", () => {
  if (!collect()) return;
  spec.rules.push({outboundTag: spec.default});
  redraw();
});
source.addEventListener("input", () => {
  editor.inert = true;
  error.textContent = "JSON изменён. Загрузите его в редактор, чтобы продолжить работу с формой.";
  error.hidden = false;
});
find("load-spec").hidden = false;
find("load-spec").addEventListener("click", load);
find("routing-form").addEventListener("submit", (event) => {
  if (!editor.inert && !collect()) event.preventDefault();
});
if (load()) find("routing-raw").open = false;
