// All client-side script lives here: the CSP forbids inline scripts.
(function () {
  "use strict";

  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
  }

  // Every htmx request carries the session's CSRF token.
  document.addEventListener("htmx:configRequest", function (event) {
    var token = csrfToken();
    if (token) {
      event.detail.headers["X-CSRF-Token"] = token;
    }
  });

  // fetch() with the CSRF token. Use this instead of fetch() for same-origin calls.
  window.pmFetch = function (url, options) {
    var opts = Object.assign({ credentials: "same-origin" }, options);
    var headers = new Headers(opts.headers || {});
    var token = csrfToken();
    if (token) {
      headers.set("X-CSRF-Token", token);
    }
    opts.headers = headers;
    return fetch(url, opts);
  };
})();
