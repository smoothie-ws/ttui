"use strict";
const chartData = document.getElementById("history-data");
if (chartData) {
  const points = JSON.parse(chartData.dataset.points);
  const kinds = {
    usage: [[1, "CPU", 1], [2, "RAM", 1]],
    disk: [[3, "Free disk", 1073741824]],
    traffic: [[4, "Received", 1024], [5, "Sent", 1024]]
  };

  function draw(canvas) {
    const series = kinds[canvas.dataset.chart];
    const width = canvas.clientWidth;
    const height = 190;
    if (width < 100) return;
    const scale = window.devicePixelRatio;
    canvas.width = width * scale;
    canvas.height = height * scale;
    const ctx = canvas.getContext("2d");
    ctx.scale(scale, scale);
    ctx.font = "11px system-ui";
    const theme = getComputedStyle(document.body);
    const colors = [theme.getPropertyValue("--accent").trim(), theme.getPropertyValue("--green").trim()];
    const ink = theme.getPropertyValue("--ink").trim();
    const pad = 42;
    const end = points[points.length - 1][0];
    const start = points[0][0];
    const max = canvas.dataset.chart === "usage" ? 100 : Math.max(1, ...points.flatMap(
      (row) => series.map(([index, , unit]) => row[index] / unit)));
    const x = (at) => pad + (at - start) / Math.max(1, end - start) * (width - pad - 8);
    const y = (value) => height - 42 - value / max * (height - 55);
    ctx.strokeStyle = theme.getPropertyValue("--line").trim();
    ctx.beginPath();
    ctx.moveTo(pad, y(max));
    ctx.lineTo(pad, y(0));
    ctx.lineTo(width - 8, y(0));
    ctx.stroke();
    ctx.fillStyle = ink;
    ctx.fillText(Math.round(max * 10) / 10, 2, y(max) + 5);
    ctx.fillText("0", 2, y(0));
    const date = (time) => new Date(time * 1000).toLocaleString([], {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"
    });
    ctx.fillText(date(start), pad, height - 23);
    if (start !== end && width >= 260) {
      ctx.textAlign = "right";
      ctx.fillText(date(end), width - 8, height - 23);
      ctx.textAlign = "left";
    }
    series.forEach(([index, label, unit], n) => {
      ctx.fillStyle = ctx.strokeStyle = colors[n];
      ctx.fillText(label, pad + n * 77, height - 5);
      ctx.beginPath();
      let previous = false;
      points.forEach((row) => {
        const value = row[index];
        if (value === null) { previous = false; return; }
        ctx[previous ? "lineTo" : "moveTo"](x(row[0]), y(value / unit));
        ctx.fillRect(x(row[0]) - 1, y(value / unit) - 1, 2, 2);
        previous = true;
      });
      ctx.stroke();
    });
  }

  const charts = chartData.querySelectorAll("canvas");
  const resize = new ResizeObserver(() => charts.forEach(draw));
  resize.observe(chartData);
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => charts.forEach(draw));
}
