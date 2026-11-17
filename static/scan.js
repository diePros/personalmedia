// Scan screen: photos become pages in memory, then one POST to /api/scan.
// Pages are Blobs held in this closure only (never in browser storage); object
// URLs for the thumbnails are revoked as soon as a page goes away.
(function () {
  "use strict";

  var MAX_PAGES = 50;
  var MAX_SIDE = 2400;
  var QUALITY = 0.85;

  var app = document.getElementById("scan-app");
  if (!app) {
    return;
  }
  function $(id) {
    return document.getElementById(id);
  }

  var els = {
    empty: $("scan-empty"),
    wrap: $("scan-pages-wrap"),
    strip: $("scan-pages"),
    savebar: $("scan-savebar"),
    save: $("scan-save"),
    sheet: $("scan-sheet"),
    form: $("scan-form"),
    title: $("scan-title"),
    date: $("scan-date"),
    notes: $("scan-notes"),
    tags: $("scan-tags"),
    progress: $("scan-progress"),
    progressText: $("scan-progress-text"),
    bar: $("scan-bar"),
    cancel: $("scan-cancel"),
    done: $("scan-done"),
    another: $("scan-another"),
    open: $("scan-open"),
    offline: $("scan-offline"),
    error: $("scan-error"),
    status: $("scan-status"),
    viewer: $("scan-viewer"),
    viewerImg: $("scan-viewer-img"),
    camera: $("scan-camera"),
    library: $("scan-library"),
    files: $("scan-files"),
  };

  var pages = []; // { blob, url }
  var xhr = null;
  var busy = false; // preparing or uploading
  var saved = false;

  function announce(text) {
    els.status.textContent = text;
  }

  function showError(text) {
    els.error.textContent = text;
    els.error.hidden = !text;
  }

  function csrf() {
    var m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.getAttribute("content") : "";
  }

  // ---- Image preparation ---------------------------------------------------

  // Decodes with the EXIF orientation applied. Resolves to
  // { source, width, height, release }.
  function decode(file) {
    function viaImg() {
      return new Promise(function (resolve, reject) {
        var url = URL.createObjectURL(file);
        var img = new Image();
        img.onload = function () {
          resolve({
            source: img,
            width: img.naturalWidth,
            height: img.naturalHeight,
            release: function () {
              URL.revokeObjectURL(url);
            },
          });
        };
        img.onerror = function () {
          URL.revokeObjectURL(url);
          reject(new Error("decode"));
        };
        img.src = url;
      });
    }
    if (window.createImageBitmap) {
      return window
        .createImageBitmap(file, { imageOrientation: "from-image" })
        .then(function (bmp) {
          return {
            source: bmp,
            width: bmp.width,
            height: bmp.height,
            release: function () {
              if (bmp.close) {
                bmp.close();
              }
            },
          };
        })
        .catch(viaImg);
    }
    return viaImg();
  }

  // Longest side at most 2400 px, JPEG quality 0.85.
  function prepare(file) {
    return decode(file).then(function (img) {
      var scale = Math.min(1, MAX_SIDE / Math.max(img.width, img.height));
      var canvas = document.createElement("canvas");
      canvas.width = Math.max(1, Math.round(img.width * scale));
      canvas.height = Math.max(1, Math.round(img.height * scale));
      var ctx = canvas.getContext("2d");
      ctx.fillStyle = "#fff"; // transparent pixels must not turn black
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img.source, 0, 0, canvas.width, canvas.height);
      img.release();
      return new Promise(function (resolve, reject) {
        canvas.toBlob(
          function (blob) {
            canvas.width = canvas.height = 0;
            if (blob) {
              resolve(blob);
            } else {
              reject(new Error("encode"));
            }
          },
          "image/jpeg",
          QUALITY
        );
      });
    });
  }

  // ---- Pages ---------------------------------------------------------------

  function plural(n) {
    return n + (n === 1 ? " page" : " pages");
  }

  function iconButton(cls, label, text) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = cls;
    b.setAttribute("aria-label", label);
    b.textContent = text;
    return b;
  }

  function move(i, delta) {
    var j = i + delta;
    if (j < 0 || j >= pages.length) {
      return;
    }
    var t = pages[i];
    pages[i] = pages[j];
    pages[j] = t;
    render();
    announce("Page moved to position " + (j + 1));
    var btns = els.strip.querySelectorAll(delta < 0 ? ".move-left" : ".move-right");
    if (btns[j] && !btns[j].disabled) {
      btns[j].focus();
    }
  }

  function removePage(i) {
    URL.revokeObjectURL(pages[i].url);
    pages.splice(i, 1);
    render();
    announce("Page removed. " + plural(pages.length) + " left");
  }

  function render() {
    var n = pages.length;
    els.strip.textContent = "";
    pages.forEach(function (p, i) {
      var li = document.createElement("li");
      var thumb = iconButton("thumb", "View page " + (i + 1), "");
      var img = document.createElement("img");
      img.src = p.url;
      img.alt = "Page " + (i + 1);
      var badge = document.createElement("span");
      badge.className = "badge";
      badge.textContent = String(i + 1);
      thumb.appendChild(img);
      thumb.appendChild(badge);
      thumb.addEventListener("click", function () {
        openViewer(i);
      });
      var del = iconButton("page-del", "Delete page " + (i + 1), "");
      var x = document.createElement("span");
      x.setAttribute("aria-hidden", "true");
      x.textContent = "✕";
      del.appendChild(x);
      del.addEventListener("click", function () {
        removePage(i);
      });
      var mv = document.createElement("div");
      mv.className = "move";
      var left = iconButton("move-left", "Move page " + (i + 1) + " left", "←");
      var right = iconButton("move-right", "Move page " + (i + 1) + " right", "→");
      left.disabled = i === 0;
      right.disabled = i === n - 1;
      left.addEventListener("click", function () {
        move(i, -1);
      });
      right.addEventListener("click", function () {
        move(i, 1);
      });
      mv.appendChild(left);
      mv.appendChild(right);
      li.appendChild(thumb);
      li.appendChild(del);
      li.appendChild(mv);
      els.strip.appendChild(li);
    });
    if (n > 0 && n < MAX_PAGES) {
      var add = document.createElement("li");
      var tile = document.createElement("label");
      tile.className = "add-tile";
      tile.setAttribute("for", "scan-camera");
      tile.setAttribute("role", "button");
      tile.setAttribute("aria-label", "Add a page");
      tile.textContent = "+";
      add.appendChild(tile);
      els.strip.appendChild(add);
    }
    var editing = n > 0 && !saved;
    els.empty.hidden = n > 0 || saved;
    els.wrap.hidden = !editing;
    els.savebar.hidden = !editing || busy;
    els.done.hidden = !saved;
    els.save.textContent = "Save (" + plural(n) + ")";
  }

  function addFiles(list) {
    var files = Array.prototype.slice.call(list || []);
    if (!files.length) {
      return;
    }
    showError("");
    var pdfs = files.filter(function (f) {
      return f.type === "application/pdf" || /\.pdf$/i.test(f.name);
    });
    var images = files.filter(function (f) {
      return pdfs.indexOf(f) === -1;
    });
    var chain = Promise.resolve();
    if (images.length) {
      busy = true;
      render();
      announce("Preparing photos");
      var room = MAX_PAGES - pages.length;
      if (images.length > room) {
        showError("A scan can have at most " + MAX_PAGES + " pages. Extra photos were skipped.");
        images = images.slice(0, Math.max(0, room));
      }
      images.forEach(function (file) {
        chain = chain.then(function () {
          return prepare(file).then(
            function (blob) {
              pages.push({ blob: blob, url: URL.createObjectURL(blob) });
              render();
            },
            function () {
              showError("One photo could not be read. Try a JPEG or PNG photo.");
            }
          );
        });
      });
      chain = chain.then(function () {
        busy = false;
        render();
        announce(plural(pages.length) + " ready");
      });
    }
    if (pdfs.length) {
      chain = chain.then(function () {
        return uploadPdfs(pdfs);
      });
    }
  }

  // ---- Viewer --------------------------------------------------------------

  var viewerReturn = null;

  function openViewer(i) {
    viewerReturn = document.activeElement;
    els.viewerImg.src = pages[i].url;
    els.viewerImg.alt = "Page " + (i + 1);
    els.viewer.hidden = false;
    $("scan-viewer-close").focus();
  }

  function closeViewer() {
    els.viewer.hidden = true;
    els.viewerImg.removeAttribute("src");
    if (viewerReturn && viewerReturn.focus) {
      viewerReturn.focus();
    }
  }

  // ---- Save sheet ----------------------------------------------------------

  function openSheet() {
    if (!pages.length || busy) {
      return;
    }
    showError("");
    els.sheet.hidden = false;
    els.title.focus();
  }

  function closeSheet() {
    els.sheet.hidden = true;
    if (!els.savebar.hidden) {
      els.save.focus();
    }
  }

  function selectedTags() {
    return Array.prototype.filter
      .call(els.tags.querySelectorAll(".chip"), function (c) {
        return c.getAttribute("aria-pressed") === "true";
      })
      .map(function (c) {
        return c.getAttribute("data-tag");
      });
  }

  // ---- Upload --------------------------------------------------------------

  function setOffline() {
    els.offline.hidden = navigator.onLine !== false;
  }

  function setProgress(text, pct) {
    els.progressText.textContent = text;
    if (pct === null) {
      els.bar.removeAttribute("value");
    } else {
      els.bar.value = pct;
    }
  }

  // Sends `form` to `url`; resolves { status, data, aborted, network }.
  function send(url, form, label) {
    return new Promise(function (resolve) {
      var req = new XMLHttpRequest();
      xhr = req;
      req.open("POST", url);
      req.setRequestHeader("X-CSRF-Token", csrf());
      req.setRequestHeader("Accept", "application/json");
      req.upload.onprogress = function (e) {
        if (e.lengthComputable) {
          var pct = Math.round((e.loaded / e.total) * 100);
          setProgress(label + " " + pct + "%", pct);
        }
      };
      req.upload.onload = function () {
        setProgress("Processing…", null);
      };
      req.onload = function () {
        xhr = null;
        var data = null;
        try {
          data = JSON.parse(req.responseText);
        } catch (e) {
          data = null;
        }
        resolve({ status: req.status, data: data });
      };
      req.onerror = function () {
        xhr = null;
        resolve({ network: true });
      };
      req.onabort = function () {
        xhr = null;
        resolve({ aborted: true });
      };
      req.send(form);
    });
  }

  function failureText(r) {
    if (r.network) {
      return navigator.onLine === false
        ? "You are offline. Your pages are kept; try again when you are back online."
        : "The upload did not go through. Your pages are kept; try again.";
    }
    var d = r.data;
    if (r.status === 413) {
      if (d && d.status === "quota_exceeded") {
        return "Your storage is full. " + (d.message || "") + " Your pages are kept here.";
      }
      return "This scan is too large for the server. Delete a page or two and try again.";
    }
    if (!d) {
      return "Your session may have expired. Log in again in another tab, then retry; your pages are kept.";
    }
    return (d.error || d.message || "The scan could not be saved") + ". Your pages are kept.";
  }

  function setBusy(on) {
    busy = on;
    els.progress.hidden = !on;
    els.savebar.hidden = on || !pages.length || saved;
    if (on) {
      els.sheet.hidden = true;
      setProgress("Uploading… 0%", 0);
    }
  }

  function finish(id) {
    pages.forEach(function (p) {
      URL.revokeObjectURL(p.url);
    });
    pages = [];
    saved = true;
    els.open.href = id ? "/documents/" + encodeURIComponent(id) : "/documents";
    setBusy(false);
    render();
    announce("Saved. Text recognition runs in the background");
    els.another.focus();
  }

  function upload() {
    if (!pages.length || busy) {
      return;
    }
    if (navigator.onLine === false) {
      setOffline();
      showError("You are offline. Your pages are kept; upload when you are back online.");
      return;
    }
    showError("");
    var form = new FormData();
    // Text fields first: the server reads them before the pages.
    form.append("title", els.title.value.trim());
    form.append("tags", selectedTags().join(","));
    form.append("date", els.date.value);
    form.append("notes", els.notes.value.trim());
    pages.forEach(function (p, i) {
      form.append("page", p.blob, "page-" + (i + 1) + ".jpg");
    });
    setBusy(true);
    send("/api/scan", form, "Uploading").then(function (r) {
      if (r.aborted) {
        setBusy(false);
        render();
        els.sheet.hidden = false;
        announce("Upload cancelled. Your pages are kept");
        return;
      }
      if (!r.network && r.status === 200 && r.data && r.data.status) {
        finish(r.data.id || r.data.existing_id);
        return;
      }
      setBusy(false);
      render();
      showError(failureText(r));
      els.sheet.hidden = false;
      setOffline();
    });
  }

  // PDFs picked under "Files" go through the normal upload route, one by one.
  function uploadPdfs(files) {
    if (navigator.onLine === false) {
      setOffline();
      showError("You are offline. Try the PDF again when you are back online.");
      return Promise.resolve();
    }
    var lastId = null;
    var failed = null;
    var chain = Promise.resolve();
    setBusy(true);
    files.forEach(function (file, i) {
      chain = chain.then(function () {
        if (failed) {
          return null;
        }
        var form = new FormData();
        form.append("on_duplicate", "skip");
        form.append("file", file, file.name); // file last
        var label = "Uploading " + file.name;
        setProgress(label, 0);
        return send("/api/upload", form, label).then(function (r) {
          if (r.aborted) {
            failed = "Upload cancelled.";
          } else if (!r.network && r.status === 200 && r.data) {
            lastId = r.data.id || r.data.existing_id;
          } else {
            failed = failureText(r).replace(" Your pages are kept.", "");
          }
        });
      });
    });
    return chain.then(function () {
      setBusy(false);
      if (failed) {
        render();
        showError(failed);
      } else if (!pages.length) {
        finish(files.length === 1 ? lastId : null);
      } else {
        render();
        announce("PDF uploaded");
      }
    });
  }

  function reset() {
    saved = false;
    els.title.value = "";
    els.date.value = "";
    els.notes.value = "";
    Array.prototype.forEach.call(els.tags.querySelectorAll(".chip"), function (c) {
      c.setAttribute("aria-pressed", "false");
    });
    showError("");
    render();
    els.camera.focus();
  }

  // ---- Wiring --------------------------------------------------------------

  [els.camera, els.library, els.files].forEach(function (input) {
    input.addEventListener("change", function () {
      var picked = input.files;
      addFiles(picked);
      // Copy happened in addFiles (Array.slice); clearing lets the same photo be picked again.
      input.value = "";
    });
  });
  els.save.addEventListener("click", openSheet);
  els.form.addEventListener("submit", function (e) {
    e.preventDefault();
    upload();
  });
  $("scan-sheet-cancel").addEventListener("click", closeSheet);
  $("scan-sheet-backdrop").addEventListener("click", closeSheet);
  els.cancel.addEventListener("click", function () {
    if (xhr) {
      xhr.abort();
    }
  });
  els.another.addEventListener("click", reset);
  els.tags.addEventListener("click", function (e) {
    var chip = e.target.closest ? e.target.closest(".chip") : null;
    if (chip) {
      chip.setAttribute(
        "aria-pressed",
        chip.getAttribute("aria-pressed") === "true" ? "false" : "true"
      );
    }
  });
  $("scan-viewer-close").addEventListener("click", closeViewer);
  els.viewer.addEventListener("click", function (e) {
    if (e.target === els.viewer) {
      closeViewer();
    }
  });
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") {
      return;
    }
    if (!els.viewer.hidden) {
      closeViewer();
    } else if (!els.sheet.hidden) {
      closeSheet();
    }
  });
  window.addEventListener("online", setOffline);
  window.addEventListener("offline", setOffline);
  window.addEventListener("beforeunload", function (e) {
    if (pages.length && !saved) {
      e.preventDefault();
      e.returnValue = "";
    }
  });
  window.addEventListener("pagehide", function () {
    pages.forEach(function (p) {
      URL.revokeObjectURL(p.url);
    });
  });

  setOffline();
  render();
})();
