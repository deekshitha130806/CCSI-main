(() => {
  const extMap = {
    jpg: "Images", jpeg: "Images", png: "Images", webp: "Images", gif: "Images",
    mp4: "Videos", avi: "Videos", mov: "Videos", mkv: "Videos",
    pdf: "Documents", doc: "Documents", docx: "Documents", txt: "Documents", log: "Log Files",
    exe: "Executable", dll: "Executable", bat: "Script", cmd: "Script", ps1: "Script", js: "Script", py: "Script",
    zip: "Archive", rar: "Archive", "7z": "Archive",
    mp3: "Audio Files", wav: "Audio Files",
    img: "Hard Disk Image", dd: "Hard Disk Image", e01: "Hard Disk Image",
  };

  const fileInput = document.getElementById("evidenceFile");
  const typeSelect = document.getElementById("evidenceType");
  const fileInfo = document.getElementById("fileInfo");

  if (fileInput) {
    fileInput.addEventListener("change", () => {
      const f = fileInput.files && fileInput.files[0];
      if (!f) return;
      const ext = (f.name.split(".").pop() || "").toLowerCase();
      const suggested = extMap[ext] || "Other";
      if (typeSelect && !typeSelect.value) typeSelect.value = suggested;
      if (fileInfo) fileInfo.textContent = `Selected: ${f.name} | Size: ${f.size.toLocaleString()} bytes | Extension: .${ext}`;
    });
  }

  document.querySelectorAll(".copy-hash").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const hash = btn.getAttribute("data-hash");
      if (!hash) return;
      try {
        await navigator.clipboard.writeText(hash);
        btn.textContent = "Copied";
        setTimeout(() => { btn.textContent = "Copy"; }, 1200);
      } catch (_) {}
    });
  });

  document.addEventListener("submit", (e) => {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    const btn = form.querySelector("[data-confirm]");
    if (!btn) return;
    if (!confirm(btn.getAttribute("data-confirm"))) e.preventDefault();
  });
})();
