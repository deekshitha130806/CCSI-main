(() => {
  const dateEl = document.getElementById("currentDate");
  if (dateEl) {
    const iso = dateEl.getAttribute("data-now");
    const dt = iso ? new Date(iso) : new Date();
    dateEl.textContent = dt.toLocaleDateString(undefined, {
      weekday: "short", year: "numeric", month: "short", day: "2-digit",
    });
  }

  const sidebar = document.getElementById("sidebar");
  const toggle = document.getElementById("toggleSidebar");
  if (toggle && sidebar) toggle.addEventListener("click", () => sidebar.classList.toggle("open"));
})();
