/* Trust Parser API · Swagger UI local. Carrega a especificação com a sessão de administrador; se não houver sessão,
   pede a chave de API (guardada só em memória) e a usa nos testes "Try it out". */
(function () {
  "use strict";
  var me = document.currentScript, specUrl = me.getAttribute("data-spec"), key = null;
  var $ = function (id) { return document.getElementById(id); };

  function boot(spec) {
    $("ad-gate").hidden = true;
    window.SwaggerUIBundle({
      spec: spec, dom_id: "#swagger-ui", deepLinking: true, docExpansion: "list", defaultModelsExpandDepth: 0,
      tryItOutEnabled: false, persistAuthorization: false, validatorUrl: null, displayRequestDuration: true, filter: true,
      supportedSubmitMethods: ["get"],  /* escrita só por integração (curl/sistemas), nunca pelo navegador */
      requestInterceptor: function (req) { if (key && !req.headers.Authorization) req.headers.Authorization = "Bearer " + key; return req; }
    });
    if (key) { $("ad-keybar").hidden = false; $("ad-keyprefix").textContent = key.slice(0, 17) + "…"; }
  }

  function load(withKey) {
    var opts = { credentials: "same-origin", headers: { Accept: "application/json" } };
    if (withKey) opts.headers.Authorization = "Bearer " + withKey;
    return fetch(specUrl, opts).then(function (r) {
      if (r.status === 200) return r.json();
      var e = new Error(String(r.status)); e.status = r.status; throw e;
    });
  }

  load(null).then(boot).catch(function () { $("ad-gate").hidden = false; $("ad-key").focus(); });

  $("ad-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var k = $("ad-key").value.trim(), err = $("ad-err");
    err.hidden = true;
    load(k).then(function (spec) { key = k; $("ad-key").value = ""; boot(spec); })
      .catch(function (e) {
        err.textContent = e.status === 429 ? "Limite de requisições da chave excedido. Aguarde um minuto." :
          e.status === 403 ? "Esta chave não pode ser usada deste endereço IP." : "Chave inválida, revogada ou expirada.";
        err.hidden = false;
      });
  });
  $("ad-forget").addEventListener("click", function () { key = null; location.reload(); });
})();
