(() => {
  "use strict";
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // --- mobile menu -------------------------------------------------------
  const nav = document.querySelector(".nav");
  const toggle = document.getElementById("menu-toggle");
  const setMenu = (open) => {
    nav.classList.toggle("nav--open", open);
    toggle.setAttribute("aria-expanded", String(open));
    toggle.textContent = open ? "Zamknij" : "Menu";
  };
  toggle.addEventListener("click", () =>
    setMenu(!nav.classList.contains("nav--open"))
  );
  nav.querySelectorAll(".nav__links a").forEach((a) =>
    a.addEventListener("click", () => setMenu(false))
  );
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && nav.classList.contains("nav--open")) setMenu(false);
  });

  // --- copy install command ---------------------------------------------
  const copy = document.getElementById("copy");
  const cmd = document.getElementById("cmd");
  if (copy && cmd) {
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(cmd.innerText);
        copy.textContent = "Skopiowano";
        setTimeout(() => (copy.textContent = "Kopiuj"), 1600);
      } catch {
        copy.textContent = "Zaznacz i skopiuj";
      }
    });
  }

  // --- fit the live report preview to its frame --------------------------
  const reportBody = document.querySelector(".frame__body");
  const reportFrame = reportBody && reportBody.querySelector("iframe");
  const fitReport = () => {
    if (!reportBody || !reportFrame) return;
    const virtual = window.innerWidth <= 640 ? 720 : 1440;
    const scale = reportBody.clientWidth / virtual;
    reportFrame.style.width = `${virtual}px`;
    reportFrame.style.height = "900px";
    reportFrame.style.transform = `scale(${scale})`;
    reportBody.style.height = `${Math.round(900 * scale)}px`;
  };
  if (reportBody && reportFrame) {
    fitReport();
    window.addEventListener("resize", fitReport);
    reportFrame.addEventListener("load", fitReport, { once: true });
  }

  // --- one hero moment: the scan runs once -------------------------------
  const app = document.getElementById("console");
  if (!app || reduce) return;

  const logs = [...app.querySelectorAll("#log p")];
  const finds = [...app.querySelectorAll("#findings p")];
  const steps = [...app.querySelectorAll("#trace li")];

  const setStage = (active) => {
    steps.forEach((step, i) => {
      step.dataset.state = i < active ? "done" : i === active ? "current" : "";
    });
  };

  logs.forEach((l) => l.classList.remove("is-on"));
  finds.forEach((f) => f.classList.remove("is-on"));
  app.classList.add("is-live");
  setStage(0);

  const afterLine = (index) => {
    if (index === 1) setStage(1);
    if (index === 3) setStage(2);
    if (index === 5) setStage(3);
    if (index === 7) steps.forEach((s) => (s.dataset.state = "done"));
  };

  const revealFindings = (i) => {
    if (i < finds.length) {
      finds[i].classList.add("is-on");
      setTimeout(() => revealFindings(i + 1), 220);
    } else {
      app.classList.remove("is-live");
    }
  };

  const revealLog = (i) => {
    if (i < logs.length) {
      logs[i].classList.add("is-on");
      afterLine(i);
      setTimeout(() => revealLog(i + 1), 190);
    } else {
      steps.forEach((s) => (s.dataset.state = "done"));
    }
  };

  setTimeout(() => {
    revealLog(0);
    setTimeout(() => revealFindings(0), 700);
  }, 400);
})();
