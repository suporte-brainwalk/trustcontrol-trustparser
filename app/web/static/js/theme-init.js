(function () { /* aplica o tema antes de pintar a página */
  var t = null;
  try { t = localStorage.getItem("tc-theme"); } catch (e) {}
  if (!t) t = window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", t);
})();
