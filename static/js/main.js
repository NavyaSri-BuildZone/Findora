// ===============================
// Findora Main JS (Lightweight)
// ===============================

// Auto hide flash messages after few seconds
document.addEventListener("DOMContentLoaded", () => {
  const alerts = document.querySelectorAll(".alert");

  if (alerts.length > 0) {
    setTimeout(() => {
      alerts.forEach((a) => {
        try {
          a.classList.remove("show");
          a.classList.add("fade");
        } catch (e) {}
      });
    }, 4000);
  }

  // Smooth scroll to top on page load (optional clean effect)
  window.scrollTo({ top: 0, behavior: "smooth" });
});
