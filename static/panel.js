"use strict";

document.addEventListener("submit", (event) => {
  const message = event.submitter?.dataset.confirmButton || event.target.dataset.confirm;
  if (message && !window.confirm(message)) event.preventDefault();
});

document.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-copy], button[data-download]");
  if (!button) return;
  const field = document.getElementById(button.dataset.copy || button.dataset.download);
  if (button.dataset.copy) {
    try {
      await navigator.clipboard.writeText(field.value);
      button.textContent = "Copied";
    } catch {
      field.focus();
      field.select();
      button.textContent = "Text selected";
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
