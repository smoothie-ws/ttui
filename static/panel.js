"use strict";

document.documentElement.classList.replace("no-js", "js");

/* Theme: follow the system by default, remember an explicit choice. */
const THEME_KEY = "ttui-theme";
const pageRoot = document.documentElement;
try {
  const stored = localStorage.getItem(THEME_KEY);
  if (stored === "light" || stored === "dark") pageRoot.dataset.theme = stored;
} catch { /* Storage unavailable: keep the system theme. */ }
const isDark = () => pageRoot.dataset.theme === "dark"
  || (!pageRoot.dataset.theme && matchMedia("(prefers-color-scheme: dark)").matches);
const syncThemeToggle = () => {
  for (const toggle of document.querySelectorAll(".theme-toggle")) {
    toggle.setAttribute("aria-pressed", String(isDark()));
  }
};
syncThemeToggle();
document.addEventListener("click", (event) => {
  if (!event.target.closest(".theme-toggle")) return;
  pageRoot.dataset.theme = isDark() ? "light" : "dark";
  try { localStorage.setItem(THEME_KEY, pageRoot.dataset.theme); } catch { /* Ignore. */ }
  syncThemeToggle();
});

/* Anchor links open the targeted disclosure, including collapsed table rows. */
document.addEventListener("click", (event) => {
  const link = event.target.closest('a[href^="#"]');
  if (!link) return;
  const target = document.getElementById(decodeURIComponent(link.getAttribute("href").slice(1)));
  if (!target) return;
  const row = target.closest("tr.detail-row");
  if (row) row.classList.add("open");
  if (target instanceof HTMLDetailsElement) target.open = true;
});

/* Expandable table rows. */
document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-expand]");
  if (!button) return;
  const row = document.getElementById(button.getAttribute("aria-controls"));
  if (!row) return;
  const open = row.classList.toggle("open");
  button.setAttribute("aria-expanded", String(open));
});

/* Dropdown menus: one open at a time, close on outside click and Escape. */
const closeMenus = (except) => {
  for (const menu of document.querySelectorAll("details.menu[open]")) {
    if (menu !== except) menu.open = false;
  }
};
document.addEventListener("click", (event) => {
  const summary = event.target.closest("details.menu > summary");
  if (summary) { closeMenus(summary.parentElement); return; }
  const item = event.target.closest(".menu-panel a");
  if (item) { closeMenus(); return; }
  if (!event.target.closest("details.menu")) closeMenus();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeMenus();
});

/* Dialogs. */
document.addEventListener("click", (event) => {
  const opener = event.target.closest("[data-open-dialog]");
  if (opener) {
    const dialog = document.getElementById(opener.dataset.openDialog);
    if (dialog && typeof dialog.showModal === "function") {
      dialog.showModal();
      const first = dialog.querySelector("input:not([type=hidden]), select, textarea");
      if (first) first.focus();
    }
    return;
  }
  const closer = event.target.closest("[data-close-dialog]");
  if (closer) closer.closest("dialog")?.close();
});

/* Dangerous-operation confirmation. */
document.addEventListener("submit", (event) => {
  const message = event.submitter?.dataset.confirmButton || event.target.dataset.confirm;
  if (message && !window.confirm(message)) event.preventDefault();
});

/* Copy and download buttons. */
document.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-copy], button[data-download]");
  if (!button) return;
  const field = document.getElementById(button.dataset.copy || button.dataset.download);
  const label = button.textContent;
  const flash = (text) => {
    button.textContent = text;
    setTimeout(() => { button.textContent = label; }, 1600);
  };
  if (button.dataset.copy) {
    try {
      await navigator.clipboard.writeText(field.value);
      flash("Copied");
    } catch {
      field.focus();
      field.select();
      flash("Text selected");
    }
    return;
  }
  const file = URL.createObjectURL(new Blob([field.value], {type: "text/plain;charset=utf-8"}));
  const link = document.createElement("a");
  link.href = file;
  link.download = button.dataset.filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(file), 1000);
});

/* Poll through a running panel update. */
if (document.querySelector("[data-update-running]")) {
  const waitForUpdate = async () => {
    try {
      const response = await fetch(location.href, {cache: "no-store"});
      if (response.ok && !new DOMParser().parseFromString(await response.text(), "text/html").querySelector("[data-update-running]")) {
        location.replace(location.href);
        return;
      }
    } catch {
      // Wait through the panel restart.
    }
    setTimeout(waitForUpdate, 4000);
  };
  setTimeout(waitForUpdate, 4000);
}

/* Tabs: every [data-tabs] set scopes the panels inside its [data-tabs-scope]. */
for (const tabSet of document.querySelectorAll("[data-tabs]")) {
  const scope = tabSet.closest("[data-tabs-scope]") || tabSet.parentElement;
  const buttons = [...tabSet.querySelectorAll("[data-tab]")];
  const panels = [...scope.querySelectorAll("[data-tab-panel]")];
  const names = new Set(panels.map((panel) => panel.dataset.tabPanel));
  const activate = (name, remember) => {
    if (!names.has(name)) return;
    for (const button of buttons) {
      const selected = button.dataset.tab === name;
      button.setAttribute("aria-selected", selected ? "true" : "false");
      button.tabIndex = selected ? 0 : -1;
    }
    for (const panel of panels) panel.hidden = panel.dataset.tabPanel !== name;
    if (remember) history.replaceState(null, "", "#" + name);
  };
  buttons.forEach((button, index) => {
    button.addEventListener("click", () => activate(button.dataset.tab, true));
    button.addEventListener("keydown", (event) => {
      if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
      event.preventDefault();
      const next = buttons[(index + (event.key === "ArrowRight" ? 1 : buttons.length - 1)) % buttons.length];
      activate(next.dataset.tab, true);
      next.focus();
    });
  });
  const requested = tabSet.dataset.openTab || location.hash.slice(1);
  activate(names.has(requested) ? requested : buttons[0]?.dataset.tab, false);
}

/* Connection filter rows. */
const filterForm = document.querySelector("[data-filter-form]");
if (filterForm) {
  const rows = filterForm.querySelector("[data-filter-rows]");
  filterForm.addEventListener("click", (event) => {
    const button = event.target.closest("[data-filter-action]");
    if (!button) return;
    const row = button.closest("[data-filter-row]");
    switch (button.dataset.filterAction) {
      case "add":
        rows.append(filterForm.querySelector("[data-filter-template]").content.cloneNode(true));
        filterForm.elements.state.value = "on";
        rows.lastElementChild.querySelector("select").focus();
        break;
      case "up":
        if (row.previousElementSibling) rows.insertBefore(row, row.previousElementSibling);
        break;
      case "down":
        if (row.nextElementSibling) rows.insertBefore(row.nextElementSibling, row);
        break;
      case "remove":
        row.remove();
        break;
    }
  });
}

/* Clients: instant search over the visible page, bulk selection state. */
const clientTable = document.querySelector("[data-client-table]");
if (clientTable) {
  const search = document.querySelector("[data-client-search]");
  const rows = [...clientTable.querySelectorAll("tbody tr[data-client-row]")];
  const emptyRow = clientTable.querySelector("[data-client-empty]");
  const applyFilter = () => {
    const query = search.value.trim().toLowerCase();
    let visible = 0;
    for (const row of rows) {
      const match = !query || row.textContent.toLowerCase().includes(query);
      row.hidden = !match;
      const detail = row.nextElementSibling;
      if (detail?.classList.contains("detail-row") && !match) detail.classList.remove("open");
      if (match) visible += 1;
    }
    if (emptyRow) emptyRow.hidden = visible > 0 || !query;
  };
  if (search) search.addEventListener("input", applyFilter);

  const bulk = document.getElementById("bulk-clients");
  const boxes = [...clientTable.querySelectorAll('input[name="selected"]')];
  const selectAll = clientTable.querySelector("[data-select-all]");
  const bulkButtons = bulk ? [...bulk.querySelectorAll("button")] : [];
  const syncBulk = () => {
    const any = boxes.some((box) => box.checked);
    for (const button of bulkButtons) button.disabled = !any;
    if (selectAll) {
      selectAll.checked = any && boxes.every((box) => box.checked);
      selectAll.indeterminate = any && !selectAll.checked;
    }
  };
  for (const box of boxes) box.addEventListener("change", syncBulk);
  if (selectAll) selectAll.addEventListener("change", () => {
    for (const box of boxes) if (!box.closest("tr").hidden) box.checked = selectAll.checked;
    syncBulk();
  });
  syncBulk();
}