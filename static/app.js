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
                setState(row, "error: " + (data.error || resp.status), true);
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

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initUpload);
  } else {
    initUpload();
  }
})();
