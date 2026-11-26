"use strict";
const journal = document.getElementById("journal-entries");
if (journal?.dataset.refresh) {
  let refreshing = false;
  setInterval(async () => {
    if (refreshing || document.hidden) return;
    refreshing = true;
    try {
      const response = await fetch(location.href, {cache: "no-store"});
      if (response.redirected || !response.ok) return;
      const page = new DOMParser().parseFromString(await response.text(), "text/html");
      const updated = page.getElementById("journal-entries");
      if (updated) journal.replaceChildren(...updated.childNodes);
    } catch {
      // Keep the last successful results until the next refresh.
    } finally {
      refreshing = false;
    }
  }, 10000);
}
