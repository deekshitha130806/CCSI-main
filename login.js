(() => {
  const forgot = document.getElementById("forgotPassword");
  if (forgot) {
    forgot.addEventListener("click", (e) => {
      e.preventDefault();
      alert("Password recovery module will be added in the next development step.");
    });
  }

  // Lightweight animated binary background
  const canvas = document.getElementById("binaryCanvas");
  if (!canvas) return;

  const ctx = canvas.getContext("2d", { alpha: true });
  const DPR = Math.max(1, Math.min(2, window.devicePixelRatio || 1));

  const state = {
    w: 0,
    h: 0,
    cols: 0,
    font: 14,
    y: [],
    speed: [],
  };

  function resize() {
    state.w = Math.floor(window.innerWidth);
    state.h = Math.floor(window.innerHeight);
    canvas.width = Math.floor(state.w * DPR);
    canvas.height = Math.floor(state.h * DPR);
    canvas.style.width = state.w + "px";
    canvas.style.height = state.h + "px";
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);

    state.font = state.w < 520 ? 12 : 14;
    ctx.font = `${state.font}px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace`;

    state.cols = Math.ceil(state.w / (state.font * 1.1));
    state.y = new Array(state.cols).fill(0).map(() => Math.random() * state.h);
    state.speed = new Array(state.cols).fill(0).map(() => 0.6 + Math.random() * 1.4);
  }

  function tick() {
    ctx.clearRect(0, 0, state.w, state.h);

    // Subtle fade layer
    ctx.fillStyle = "rgba(6, 10, 18, 0.20)";
    ctx.fillRect(0, 0, state.w, state.h);

    for (let i = 0; i < state.cols; i++) {
      const x = i * (state.font * 1.1);
      const y = state.y[i];

      const bit = Math.random() > 0.5 ? "1" : "0";
      ctx.fillStyle = "rgba(38, 230, 255, 0.16)";
      ctx.fillText(bit, x, y);

      // Occasional brighter bit
      if (Math.random() > 0.985) {
        ctx.fillStyle = "rgba(42, 118, 255, 0.22)";
        ctx.fillText(Math.random() > 0.5 ? "1" : "0", x, y - state.font * 1.2);
      }

      state.y[i] += state.speed[i] * state.font * 0.9;
      if (state.y[i] > state.h + 40) state.y[i] = -Math.random() * 120;
    }

    requestAnimationFrame(tick);
  }

  window.addEventListener("resize", resize, { passive: true });
  resize();
  tick();
})();

