(() => {
  document.addEventListener("submit", (e) => {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    const btn = form.querySelector("[data-confirm]");
    if (!btn) return;
    if (!confirm(btn.getAttribute("data-confirm"))) e.preventDefault();
  });
})();
