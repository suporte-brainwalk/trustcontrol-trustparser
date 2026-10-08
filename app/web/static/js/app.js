/* Trust Parser — comportamento de interface (sem scripts inline; CSP script-src 'self') */
(function () {
  "use strict";
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  // ---- tema claro/escuro
  $$("[data-theme-toggle]").forEach(function (el) {
    el.addEventListener("click", function () {
      var t = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", t);
      try { localStorage.setItem("tc-theme", t); } catch (e) {}
    });
  });

  // ---- menu lateral no celular
  $$("[data-menu-toggle]").forEach(function (el) {
    el.addEventListener("click", function () { var s = document.getElementById("side"); if (s) s.classList.toggle("open"); });
  });

  // ---- confirmação simples
  $$("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (ev) { if (!window.confirm(f.getAttribute("data-confirm"))) ev.preventDefault(); });
  });

  $$("button[data-confirm-btn]").forEach(function (b) {
    b.addEventListener("click", function (ev) { if (!window.confirm(b.getAttribute("data-confirm-btn"))) ev.preventDefault(); });
  });

  // ---- confirmação digitando um valor (ex.: e-mail do admin)
  $$("form[data-confirm-type]").forEach(function (f) {
    var input = f.querySelector("[data-confirm-input]"), btn = f.querySelector("[type=submit]");
    var expected = (f.getAttribute("data-confirm-type") || "").toLowerCase();
    var check = function () { if (btn) btn.disabled = (input.value.trim().toLowerCase() !== expected); };
    if (input) { input.addEventListener("input", check); check(); }
  });

  // ---- selects que enviam o formulário
  $$("[data-autosubmit]").forEach(function (el) {
    el.addEventListener("change", function () { if (el.form) el.form.submit(); });
  });

  // ---- copiar para a área de transferência (ex.: chave de API recém-criada)
  $$("[data-copy]").forEach(function (b) {
    b.addEventListener("click", function () {
      var el = document.getElementById(b.getAttribute("data-copy")); if (!el) return;
      var done = function () { var t = b.textContent; b.textContent = "Copiado ✓"; setTimeout(function () { b.textContent = t; }, 2000); };
      if (navigator.clipboard) { navigator.clipboard.writeText(el.value || el.textContent).then(done, function () { el.select(); document.execCommand("copy"); done(); }); }
      else { el.select(); document.execCommand("copy"); done(); }
    });
  });

  // ---- diálogos
  $$("[data-open-dialog]").forEach(function (el) {
    el.addEventListener("click", function (ev) {
      ev.preventDefault();
      var d = document.getElementById(el.getAttribute("data-open-dialog"));
      if (d && d.showModal) d.showModal();
    });
  });
  $$("dialog [data-close-dialog]").forEach(function (el) {
    el.addEventListener("click", function (ev) { ev.preventDefault(); el.closest("dialog").close(); });
  });

  // ---- datas DD/MM/AAAA com máscara (independe do idioma do navegador)
  var pad = function (n) { return (n < 10 ? "0" : "") + n; };
  var validBR = function (v) {
    var m = /^(\d{2})\/(\d{2})\/(\d{4})$/.exec(v); if (!m) return false;
    var d = +m[1], mo = +m[2], y = +m[3], dt = new Date(y, mo - 1, d);
    return dt.getFullYear() === y && dt.getMonth() === mo - 1 && dt.getDate() === d;
  };
  $$("input.date-br").forEach(function (el) {
    el.addEventListener("input", function () {
      var v = el.value.replace(/\D/g, "").slice(0, 8);
      if (v.length > 4) v = v.slice(0, 2) + "/" + v.slice(2, 4) + "/" + v.slice(4);
      else if (v.length > 2) v = v.slice(0, 2) + "/" + v.slice(2);
      el.value = v; el.classList.remove("bad"); el.setCustomValidity("");
    });
    el.addEventListener("blur", function () {
      if (el.value && !validBR(el.value)) { el.classList.add("bad"); el.setCustomValidity("Data inválida — use DD/MM/AAAA"); }
    });
    var cal = el.parentElement && el.parentElement.querySelector(".date-native");
    var btn = el.parentElement && el.parentElement.querySelector(".date-cal");
    if (cal && btn) {
      btn.addEventListener("click", function () { try { cal.showPicker(); } catch (e) { cal.click(); } });
      cal.addEventListener("change", function () {
        if (!cal.value) return; var p = cal.value.split("-"); el.value = p[2] + "/" + p[1] + "/" + p[0]; el.classList.remove("bad");
        if (el.form && el.hasAttribute("data-autosubmit-date")) el.form.submit();
      });
    }
  });

  // ---- período personalizado: mostra/esconde campos
  $$("select[data-period]").forEach(function (sel) {
    var box = document.getElementById(sel.getAttribute("data-period"));
    var upd = function () { if (box) box.hidden = sel.value !== "custom"; };
    sel.addEventListener("change", function () { upd(); if (sel.value !== "custom" && sel.form) sel.form.submit(); });
    upd();
  });

  // ---- chips de modelos/versões no formulário de produto
  $$("[data-chips]").forEach(function (box) {
    var hidden = box.querySelector("input[type=hidden]"), input = box.querySelector("[data-chip-input]"),
        list = box.querySelector("[data-chip-list]");
    var locked = (box.getAttribute("data-locked") || "").split("|").filter(Boolean);
    var items = hidden.value ? hidden.value.split("|").filter(Boolean) : [];
    var render = function () {
      list.innerHTML = "";
      items.forEach(function (m, i) {
        var span = document.createElement("span"); span.className = "chip-ed"; span.textContent = m;
        var b = document.createElement("button"); b.type = "button"; b.textContent = "×";
        if (locked.indexOf(m) >= 0) { b.disabled = true; b.title = "Em uso por cliente"; }
        b.addEventListener("click", function () { items.splice(i, 1); sync(); });
        span.appendChild(b); list.appendChild(span);
      });
      if (!items.length) { var e = document.createElement("span"); e.className = "sm muted"; e.textContent = "Nenhum modelo ainda."; list.appendChild(e); }
    };
    var sync = function () { hidden.value = items.join("|"); render(); };
    var add = function () {
      input.value.split(",").map(function (x) { return x.trim(); }).filter(Boolean).forEach(function (x) {
        if (items.indexOf(x) < 0 && x.indexOf("|") < 0) items.push(x);
      });
      input.value = ""; sync();
    };
    input.addEventListener("keydown", function (ev) { if (ev.key === "Enter") { ev.preventDefault(); add(); } });
    var addBtn = box.querySelector("[data-chip-add]"); if (addBtn) addBtn.addEventListener("click", add);
    render();
  });

  // ---- filtro de cartões (fabricantes)
  $$("[data-filter-cards]").forEach(function (inp) {
    inp.addEventListener("input", function () {
      var q = inp.value.toLowerCase();
      $$(inp.getAttribute("data-filter-cards")).forEach(function (c) { c.hidden = q && c.textContent.toLowerCase().indexOf(q) < 0; });
    });
  });

  // ---- Trust Parser: mostra/oculta blocos conforme um select/radio (data-show-if="nome=valor1|valor2")
  var syncShow = function () {
    $$("[data-show-if]").forEach(function (el) {
      var spec = el.getAttribute("data-show-if").split("="), name = spec[0], vals = (spec[1] || "").split("|");
      var form = el.closest("form") || document;
      var ctl = form.querySelector("[name='" + name + "']:checked") || form.querySelector("select[name='" + name + "']");
      var v = ctl ? ctl.value : "";
      var on = vals.indexOf(v) >= 0;
      el.style.display = on ? "" : "none";
      $$("input,select,textarea", el).forEach(function (i) { if (i.hasAttribute("data-req")) i.required = on; });
    });
  };
  $$("select,input[type=radio]").forEach(function (el) { el.addEventListener("change", syncShow); });
  syncShow();
})();
