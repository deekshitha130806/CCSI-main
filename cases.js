(() => {
  document.addEventListener("submit", (e) => {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;

    const btn = form.querySelector("[data-confirm]");
    if (!btn) return;
    const msg = btn.getAttribute("data-confirm");
    if (!msg) return;
    if (!confirm(msg)) e.preventDefault();
  });
})();

