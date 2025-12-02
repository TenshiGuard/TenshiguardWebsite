/* ============================================================
   🌗 TenshiGuard Theme Switcher (Dark / Light)
   Works with CSS variables in dashboard.css
   Supports auto-save using localStorage
   ============================================================ */

document.addEventListener("DOMContentLoaded", () => {
  const root = document.documentElement;
  const toggle = document.getElementById("themeToggle");

  // -------------------------------
  // Load saved theme
  // -------------------------------
  const savedTheme = localStorage.getItem("tg-theme") || "dark";
  root.setAttribute("data-theme", savedTheme);

  if (toggle) {
    toggle.checked = savedTheme === "light";
  }

  // -------------------------------
  // Toggle Theme
  // -------------------------------
  if (toggle) {
    toggle.addEventListener("change", function () {
      const newTheme = this.checked ? "light" : "dark";
      root.setAttribute("data-theme", newTheme);
      localStorage.setItem("tg-theme", newTheme);
    });
  }
});
