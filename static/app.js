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

  // A 429 (a search by meaning already running) carries a message for the
  // results area: show it instead of dropping the response.
  document.addEventListener("htmx:beforeSwap", function (event) {
    if (event.detail.xhr && event.detail.xhr.status === 429) {
      event.detail.shouldSwap = true;
      event.detail.isError = false;
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

  // ---- Drag & drop / multi-file upload (documents list page) --------------
  //
  // One POST per file to /api/upload, one after the other. The server reads
  // the text fields (title, tags, date, on_duplicate) before the file and
  // streams the file straight to disk, so the client MUST append `file` LAST
  // in the FormData: anything after it is ignored.
  function initUpload() {
    var zone = document.getElementById("dropzone");
    var input = document.getElementById("file-input");
    var list = document.getElementById("upload-status");
    if (!zone || !input || !list) {
      return;
    }
    var queue = [];
    var running = false;

    function refreshResults() {
      if (window.htmx) {
        window.htmx.ajax("GET", "/documents", "#results");
      }
    }

    function addRow(file) {
      var li = document.createElement("li");
      var name = document.createElement("span");
      name.className = "upload-name";
      name.textContent = file.name;
      var status = document.createElement("span");
      status.className = "upload-state muted";
      li.appendChild(name);
      li.appendChild(document.createTextNode(" "));
      li.appendChild(status);
      list.appendChild(li);
      return { li: li, status: status };
    }

    function setState(row, text, isError) {
      row.status.textContent = text;
      row.status.className = "upload-state " + (isError ? "error" : "muted");
    }

    function send(file, row, onDuplicate) {
      setState(row, "uploading", false);
      var body = new FormData();
      body.append("on_duplicate", onDuplicate);
      body.append("file", file, file.name); // file last
      return window
        .pmFetch("/api/upload", { method: "POST", body: body })
        .then(function (resp) {
          return resp
            .json()
            .catch(function () {
              return {};
            })
            .then(function (data) {
              if (!resp.ok) {
                setState(
                  row,
                  "error: " + (data.message || data.error || resp.status),
                  true
                );
              } else if (data.status === "duplicate") {
                setState(row, "duplicate of " + data.existing_title + " ", false);
                var btn = document.createElement("button");
                btn.type = "button";
                btn.className = "link";
                btn.textContent = "Upload anyway";
                btn.addEventListener("click", function () {
                  btn.remove();
                  send(file, row, "keep").then(refreshResults);
                });
                row.status.appendChild(btn);
              } else {
                setState(row, "stored", false);
              }
            });
        })
        .catch(function () {
          setState(row, "error: network", true);
        });
    }

    function drain() {
      if (running) {
        return;
      }
      running = true;
      (function next() {
        var item = queue.shift();
        if (!item) {
          running = false;
          refreshResults();
          return;
        }
        send(item.file, item.row, "skip").then(next);
      })();
    }

    function addFiles(files) {
      for (var i = 0; i < files.length; i++) {
        queue.push({ file: files[i], row: addRow(files[i]) });
        setState(queue[queue.length - 1].row, "waiting", false);
      }
      drain();
    }

    input.addEventListener("change", function () {
      addFiles(input.files);
      input.value = "";
    });
    ["dragenter", "dragover"].forEach(function (type) {
      zone.addEventListener(type, function (e) {
        e.preventDefault();
        zone.classList.add("dragging");
      });
    });
    ["dragleave", "drop"].forEach(function (type) {
      zone.addEventListener(type, function () {
        zone.classList.remove("dragging");
      });
    });
    zone.addEventListener("drop", function (e) {
      e.preventDefault();
      if (e.dataTransfer && e.dataTransfer.files) {
        addFiles(e.dataTransfer.files);
      }
    });
  }

  // Install hint: a dismissible banner on the Documents page. Shown only where
  // installing is possible and the app is not already running standalone.
  var HINT_KEY = "pms.installHint.dismissed";

  function hintDismissed() {
    try {
      return window.localStorage.getItem(HINT_KEY) === "1";
    } catch (e) {
      return false;
    }
  }

  function dismissHint(hint) {
    hint.hidden = true;
    try {
      window.localStorage.setItem(HINT_KEY, "1");
    } catch (e) {}
  }

  function isStandalone() {
    return (
      navigator.standalone === true ||
      (window.matchMedia && window.matchMedia("(display-mode: standalone)").matches)
    );
  }

  function isIosSafari() {
    var ua = navigator.userAgent || "";
    var iphoneOrIpad = /iPhone|iPad|iPod/.test(ua);
    // iPadOS 13+ reports a Mac UA; tell it apart by touch support.
    var ipadAsMac = /Macintosh/.test(ua) && navigator.maxTouchPoints > 1;
    return (iphoneOrIpad || ipadAsMac) && navigator.standalone === false;
  }

  // Runs at once (the script is deferred, so <html> exists and the page is
  // parsed): the standalone shell must not wait for DOMContentLoaded.
  function markStandalone() {
    if (isStandalone()) {
      document.documentElement.classList.add("standalone");
    }
  }

  // Bottom tab bar (shown only when standalone, see app.css): highlights the
  // current tab and makes Search focus the documents search field.
  function initTabbar() {
    var bar = document.querySelector(".tabbar");
    if (!bar) {
      return;
    }
    var tabs = bar.querySelectorAll(".tab");
    function current() {
      var path = window.location.pathname;
      if (path === "/documents" && window.location.hash === "#q") {
        return "/documents#q";
      }
      if (path === "/scan" || path === "/settings") {
        return path;
      }
      return path.indexOf("/documents") === 0 ? "/documents" : "";
    }
    function mark() {
      var here = current();
      Array.prototype.forEach.call(tabs, function (tab) {
        if (tab.getAttribute("href") === here) {
          tab.setAttribute("aria-current", "page");
        } else {
          tab.removeAttribute("aria-current");
        }
      });
    }
    function focusSearch() {
      var q = document.getElementById("q");
      if (q) {
        q.focus();
        if (q.scrollIntoView) {
          q.scrollIntoView({ block: "center" });
        }
      }
      return !!q;
    }
    Array.prototype.forEach.call(tabs, function (tab) {
      if (tab.getAttribute("href") !== "/documents#q") {
        return;
      }
      tab.addEventListener("click", function (e) {
        // Already on the documents page: no reload, just focus the field.
        if (window.location.pathname === "/documents" && focusSearch()) {
          e.preventDefault();
          window.history.replaceState(null, "", "/documents#q");
          mark();
        }
      });
    });
    mark();
    if (window.location.pathname === "/documents" && window.location.hash === "#q") {
      focusSearch();
    }
  }

  function initInstallHint() {
    var hint = document.getElementById("install-hint");
    if (!hint) {
      return;
    }
    if (isStandalone() || hintDismissed()) {
      return;
    }
    function show(kind) {
      Array.prototype.forEach.call(
        hint.querySelectorAll(".install-hint-" + kind),
        function (el) {
          el.hidden = false;
        },
      );
      hint.hidden = false;
    }
    var dismiss = document.getElementById("install-hint-dismiss");
    if (dismiss) {
      dismiss.addEventListener("click", function () {
        dismissHint(hint);
      });
    }
    if (isIosSafari()) {
      show("ios");
      return;
    }
    var installBtn = document.getElementById("install-hint-install");
    var deferred = null;
    window.addEventListener("beforeinstallprompt", function (event) {
      event.preventDefault();
      deferred = event;
      show("android");
    });
    window.addEventListener("appinstalled", function () {
      hint.hidden = true;
    });
    if (installBtn) {
      installBtn.addEventListener("click", function () {
        if (!deferred) {
          return;
        }
        var prompt = deferred;
        deferred = null;
        hint.hidden = true;
        prompt.prompt();
      });
    }
  }

  // Installable app: the worker caches only the static app shell.
  if ("serviceWorker" in navigator) {
    window.addEventListener("load", function () {
      navigator.serviceWorker
        .register("/sw.js", { scope: "/" })
        .catch(function () {});
    });
  }

  markStandalone();

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initUpload);
    document.addEventListener("DOMContentLoaded", initInstallHint);
    document.addEventListener("DOMContentLoaded", initTabbar);
  } else {
    initUpload();
    initInstallHint();
    initTabbar();
  }
})();
