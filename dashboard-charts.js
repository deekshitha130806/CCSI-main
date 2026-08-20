document.addEventListener("DOMContentLoaded", () => {
  const dataEl = document.getElementById("ccsi-chart-data");
  if (!dataEl) return;

  if (!window.Chart) {
    console.error("Chart.js failed to load.");
    return;
  }

  let chartData = {};
  try {
    chartData = JSON.parse(dataEl.textContent || "{}");
  } catch (e) {
    console.error("Invalid chart JSON:", e);
    return;
  }

  const common = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { labels: { color: "rgba(232,240,255,0.75)" } } },
    scales: {
      x: { ticks: { color: "rgba(232,240,255,0.65)" }, grid: { color: "rgba(255,255,255,0.06)" } },
      y: { ticks: { color: "rgba(232,240,255,0.65)" }, grid: { color: "rgba(255,255,255,0.06)" }, beginAtZero: true },
    },
  };

  function showEmpty(emptyId, canvasId) {
    const empty = document.getElementById(emptyId);
    const canvas = document.getElementById(canvasId);
    if (empty) empty.hidden = false;
    if (canvas) canvas.style.display = "none";
  }

  // Case Status (Open, Closed, Pending only per spec)
  const cs = chartData.caseStatus || {};
  const caseValues = [cs.open || 0, cs.closed || 0, cs.pending || 0];
  const caseTotal = caseValues.reduce((a, b) => a + b, 0);
  const caseCanvas = document.getElementById("caseStatusChart");
  if (caseCanvas) {
    if (caseTotal === 0) {
      showEmpty("caseStatusEmpty", "caseStatusChart");
    } else {
      new Chart(caseCanvas, {
        type: "doughnut",
        data: {
          labels: ["Open", "Closed", "Pending"],
          datasets: [{
            data: caseValues,
            backgroundColor: ["rgba(38,230,255,0.65)", "rgba(91,227,138,0.55)", "rgba(42,118,255,0.55)"],
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: "bottom", labels: { color: "rgba(232,240,255,0.75)" } } },
          cutout: "62%",
        },
      });
    }
  }

  // Evidence Type Distribution
  const evLabels = chartData.evidenceLabels || [];
  const evValues = chartData.evidenceValues || [];
  const evTotal = evValues.reduce((a, b) => a + b, 0);
  const evCanvas = document.getElementById("evidenceTypeChart");
  if (evCanvas) {
    if (!evLabels.length || evTotal === 0) {
      showEmpty("evidenceTypeEmpty", "evidenceTypeChart");
    } else {
      new Chart(evCanvas, {
        type: "bar",
        data: {
          labels: evLabels,
          datasets: [{
            label: "Items",
            data: evValues,
            backgroundColor: "rgba(38,230,255,0.20)",
            borderColor: "rgba(38,230,255,0.40)",
            borderWidth: 1,
          }],
        },
        options: common,
      });
    }
  }

  // Monthly Cases
  const mLabels = chartData.monthlyLabels || [];
  const mValues = chartData.monthlyValues || [];
  const mTotal = mValues.reduce((a, b) => a + b, 0);
  const mCanvas = document.getElementById("monthlyCasesChart");
  if (mCanvas) {
    if (mTotal === 0) {
      showEmpty("monthlyCasesEmpty", "monthlyCasesChart");
    } else {
      new Chart(mCanvas, {
        type: "line",
        data: {
          labels: mLabels,
          datasets: [{
            label: "Cases",
            data: mValues,
            borderColor: "rgba(38,230,255,0.75)",
            backgroundColor: "rgba(38,230,255,0.10)",
            tension: 0.35,
            fill: true,
            pointRadius: 3,
          }],
        },
        options: common,
      });
    }
  }
});
