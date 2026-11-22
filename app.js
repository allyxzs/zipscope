(function () {
  "use strict";

  var MB = 1024 * 1024;
  var GB = 1024 * MB;

  var EXT_GROUPS = {
    executavel: ["exe", "dll", "sys", "scr", "com", "pif", "msi", "msp", "cpl", "ocx", "drv",
      "elf", "so", "dylib", "apk", "app", "dmg", "pkg", "deb", "rpm", "jar", "war",
      "vhd", "vhdx", "iso", "img", "lnk", "url", "reg", "chm", "hta", "ade", "adp"],
    script: ["bat", "cmd", "ps1", "psm1", "vbs", "vbe", "jse", "wsf", "wsh", "sh",
      "bash", "zsh", "scpt", "ahk", "command"],
    macro: ["docm", "dotm", "xlsm", "xltm", "pptm", "potm", "ppsm", "xlam", "xlsb"],
    arquivo: ["zip", "rar", "7z", "tar", "gz", "bz2", "xz", "tgz", "tbz", "cab", "arj",
      "lzh", "zst", "ace"]
  };

  var EXT_CATEGORY = {};
  Object.keys(EXT_GROUPS).forEach(function (category) {
    EXT_GROUPS[category].forEach(function (ext) {
      EXT_CATEGORY[ext] = category;
    });
  });

  var FLAG_LABEL = {
    executavel: "Executável",
    script: "Script",
    macro: "Macro",
    arquivo: "Compactado",
    traversal: "Caminho ..",
    absoluto: "Caminho absoluto",
    dupla: "Extensão dupla",
    oculto: "Oculto"
  };

  var INNOCENT_EXT = ["jpg", "jpeg", "png", "gif", "webp", "bmp", "svg", "pdf", "txt", "doc",
    "docx", "xls", "xlsx", "ppt", "pptx", "mp3", "mp4", "avi", "mkv", "csv", "json", "html", "xml"];

  var SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

  var SEVERITY_LABEL = { critical: "crítico", high: "alto", medium: "médio", low: "baixo" };

  var UNITS = ["B", "KB", "MB", "GB", "TB"];

  var TONE_COLOR = {
    safe: "#3be08f",
    medium: "#ffc94a",
    high: "#ff8a3d",
    critical: "#ff4d5e"
  };

  var LIMIT = 200;

  function formatBytes(bytes) {
    var value = Number(bytes);
    if (!isFinite(value) || value <= 0) return "0 B";
    var index = 0;
    var size = value;
    while (size >= 1024 && index < UNITS.length - 1) {
      size = size / 1024;
      index += 1;
    }
    var digits = index === 0 ? 0 : size >= 100 ? 0 : size >= 10 ? 1 : 2;
    return size.toLocaleString("pt-BR", {
      minimumFractionDigits: digits,
      maximumFractionDigits: digits
    }) + " " + UNITS[index];
  }

  function formatRatio(ratio) {
    if (!isFinite(ratio) || ratio <= 0) return "—";
    var digits = ratio >= 100 ? 0 : ratio >= 10 ? 1 : 2;
    return ratio.toLocaleString("pt-BR", {
      minimumFractionDigits: digits,
      maximumFractionDigits: digits
    }) + "×";
  }

  function formatCount(value) {
    return Number(value || 0).toLocaleString("pt-BR");
  }

  function basename(path) {
    var parts = String(path || "").split("/");
    return parts[parts.length - 1] || String(path || "");
  }

  function dirname(path) {
    var parts = String(path || "").split("/");
    parts.pop();
    return parts.join("/");
  }

  function extOf(path) {
    var name = basename(path);
    var dot = name.lastIndexOf(".");
    if (dot <= 0) return "";
    return name.slice(dot + 1).toLowerCase();
  }

  function esc(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function levelFor(score) {
    if (score >= 70) {
      return {
        tone: "critical",
        label: "Bomba provável",
        blurb: "Perfil clássico de zip bomb ou de pacote armadilhado. Não extraia este arquivo sem um ambiente isolado e limites de disco."
      };
    }
    if (score >= 45) {
      return {
        tone: "high",
        label: "Suspeito",
        blurb: "Há sinais suficientes para desconfiar. Se for extrair, faça isso em uma pasta isolada, com espaço em disco monitorado."
      };
    }
    if (score >= 20) {
      return {
        tone: "medium",
        label: "Atenção",
        blurb: "Nada com cara de bomba, mas existem pontos que merecem uma conferida antes de abrir o conteúdo."
      };
    }
    return {
      tone: "safe",
      label: "Tranquilo",
      blurb: "Perfil de arquivo comum: sem expansão absurda, sem caminhos maliciosos e sem extensões críticas."
    };
  }

  function analyze(entries) {
    var files = [];
    var dirCount = 0;

    entries.forEach(function (entry) {
      if (entry.isDir) dirCount += 1;
      else files.push(entry);
    });

    var totalSize = 0;
    var totalCompressed = 0;
    var largest = null;
    var extremeRatio = null;

    var traversal = [];
    var absolute = [];
    var doubleExt = [];
    var dangerousMap = {};
    var rows = [];

    files.forEach(function (file) {
      totalSize += file.size;
      totalCompressed += file.compressed;
      if (!largest || file.size > largest.size) {
        largest = { path: file.path, size: file.size };
      }

      var ext = extOf(file.path);
      var category = EXT_CATEGORY[ext] || null;
      var flags = [];

      if (category) {
        flags.push(category);
        var current = dangerousMap[ext] || { ext: ext, category: category, count: 0, size: 0 };
        current.count += 1;
        current.size += file.size;
        dangerousMap[ext] = current;
      }

      var segments = file.path.split("/");
      if (segments.indexOf("..") !== -1) {
        traversal.push(file.path);
        flags.push("traversal");
      }
      if (file.path.charAt(0) === "/" || /^[a-zA-Z]:[\\/]/.test(file.path) || file.path.slice(0, 2) === "\\\\") {
        absolute.push(file.path);
        flags.push("absoluto");
      }

      var nameParts = basename(file.path).toLowerCase().split(".");
      if (nameParts.length >= 3 && category && INNOCENT_EXT.indexOf(nameParts[nameParts.length - 2]) !== -1) {
        doubleExt.push(file.path);
        flags.push("dupla");
      }

      if (basename(file.path).charAt(0) === ".") flags.push("oculto");

      var ratio = file.compressed > 0 ? file.size / file.compressed : null;
      if (ratio && ratio >= 1000 && file.size >= 10 * MB && !extremeRatio) {
        extremeRatio = { path: file.path, ratio: ratio, size: file.size };
      }

      rows.push({
        path: file.path,
        size: file.size,
        compressed: file.compressed,
        ext: ext,
        category: category,
        ratio: ratio,
        flags: flags
      });
    });

    var ratioTotal = totalCompressed > 0 ? totalSize / totalCompressed : null;
    var alerts = [];
    var score = 0;

    function addAlert(severity, title, detail) {
      alerts.push({ severity: severity, title: title, detail: detail });
    }

    if (traversal.length) {
      score += 45;
      addAlert("critical", "Caminhos que escapam da pasta",
        formatCount(traversal.length) + " entrada(s) usam \"..\" no caminho. Ao extrair, o conteúdo pode ser gravado fora da pasta de destino e sobrescrever arquivos do sistema.");
    }

    if (absolute.length) {
      score += 18;
      addAlert("high", "Caminhos absolutos",
        formatCount(absolute.length) + " entrada(s) apontam para um caminho absoluto (como /etc ou C:\\). Um extrator descuidado pode escrever direto no sistema.");
    }

    if (ratioTotal !== null) {
      if (ratioTotal >= 1000) {
        score += 38;
        addAlert("critical", "Expansão absurda",
          "O pacote ocupa pouco e descomprime " + formatRatio(ratioTotal) + " o próprio tamanho. É a assinatura clássica de uma zip bomb.");
      } else if (ratioTotal >= 300) {
        score += 26;
        addAlert("high", "Taxa de compressão muito alta",
          "Descompacta " + formatRatio(ratioTotal) + " o tamanho do arquivo. Arquivos de texto comuns ficam bem abaixo disso.");
      } else if (ratioTotal >= 100) {
        score += 15;
        addAlert("medium", "Taxa de compressão alta",
          "Descompacta " + formatRatio(ratioTotal) + " o tamanho do arquivo. Confira o volume total antes de extrair.");
      } else if (ratioTotal >= 40) {
        score += 6;
        addAlert("low", "Taxa de compressão acima do normal",
          "Descompacta " + formatRatio(ratioTotal) + " o tamanho do arquivo. Costuma ser normal em textos e logs, mas vale conferir.");
      }
    }

    if (totalSize >= 4 * GB) {
      score += 26;
      addAlert("critical", "Descompacta para um volume enorme",
        "O conteúdo ocupa " + formatBytes(totalSize) + " depois de extraído. Isso pode encher o disco inteiro.");
    } else if (totalSize >= 1 * GB) {
      score += 18;
      addAlert("high", "Conteúdo muito grande",
        "São " + formatBytes(totalSize) + " descompactados. Reserve espaço em disco antes de extrair.");
    } else if (totalSize >= 200 * MB) {
      score += 8;
      addAlert("medium", "Conteúdo grande",
        "São " + formatBytes(totalSize) + " descompactados em " + formatCount(files.length) + " arquivo(s).");
    } else if (totalSize >= 50 * MB) {
      score += 3;
      addAlert("low", "Conteúdo acima da média",
        "São " + formatBytes(totalSize) + " descompactados.");
    }

    var execList = [];
    var scriptList = [];
    var macroList = [];
    var nestedList = [];

    Object.keys(dangerousMap).forEach(function (key) {
      var item = dangerousMap[key];
      if (item.category === "executavel") execList.push(item);
      if (item.category === "script") scriptList.push(item);
      if (item.category === "macro") macroList.push(item);
      if (item.category === "arquivo") nestedList.push(item);
    });

    function countOf(list) {
      return list.reduce(function (sum, item) { return sum + item.count; }, 0);
    }

    function extText(list) {
      return list.map(function (item) { return "." + item.ext; }).join(", ");
    }

    var execCount = countOf(execList);
    var scriptCount = countOf(scriptList);
    var macroCount = countOf(macroList);
    var nestedCount = countOf(nestedList);

    if (execCount) {
      score += Math.min(24, execCount * 6);
      addAlert("high", "Arquivos executáveis",
        formatCount(execCount) + " entrada(s) são executáveis ou instaladores (" + extText(execList) + "). Só rode se confiar na origem.");
    }

    if (scriptCount) {
      score += Math.min(12, scriptCount * 2);
      addAlert("medium", "Scripts no pacote",
        formatCount(scriptCount) + " entrada(s) são scripts que podem executar comandos (" + extText(scriptList) + ").");
    }

    if (macroCount) {
      score += Math.min(10, macroCount * 3);
      addAlert("high", "Documentos com macro",
        formatCount(macroCount) + " entrada(s) são documentos com macro habilitada, um vetor comum de malware.");
    }

    if (nestedCount) {
      score += Math.min(12, nestedCount * 4);
      addAlert("medium", "Arquivos compactados dentro do ZIP",
        formatCount(nestedCount) + " entrada(s) são outros arquivos compactados. Bomba dentro de bomba é uma técnica real de escape.");
    }

    if (doubleExt.length) {
      score += 12;
      addAlert("high", "Extensão dupla",
        formatCount(doubleExt.length) + " arquivo(s) escondem um executável atrás de uma extensão inofensiva, como foto.jpg.exe.");
    }

    if (extremeRatio) {
      score += 10;
      addAlert("high", "Arquivo com expansão extrema",
        basename(extremeRatio.path) + " descompacta " + formatRatio(extremeRatio.ratio) + " e passa de " + formatBytes(extremeRatio.size) + ".");
    }

    if (files.length >= 20000) {
      score += 10;
      addAlert("high", "Quantidade de arquivos fora do normal",
        formatCount(files.length) + " arquivos em um único pacote. Extrair isso gera uma enxurrada de arquivos no disco.");
    } else if (files.length >= 5000) {
      score += 5;
      addAlert("medium", "Muitos arquivos",
        formatCount(files.length) + " arquivos em um único pacote.");
    }

    var finalScore = Math.max(0, Math.min(100, Math.round(score)));

    alerts.sort(function (a, b) {
      return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    });

    rows.sort(function (a, b) {
      if (a.flags.length !== b.flags.length) return b.flags.length - a.flags.length;
      return b.size - a.size;
    });

    var dangerousList = Object.keys(dangerousMap).map(function (key) {
      return dangerousMap[key];
    }).sort(function (a, b) { return b.count - a.count; });

    return {
      fileCount: files.length,
      dirCount: dirCount,
      totalSize: totalSize,
      totalCompressed: totalCompressed,
      ratio: ratioTotal,
      largest: largest,
      score: finalScore,
      level: levelFor(finalScore),
      alerts: alerts,
      rows: rows,
      dangerous: dangerousList,
      summary: formatCount(files.length) + " arquivos · " + formatBytes(totalSize) + " descompactados" +
        (ratioTotal ? " · " + formatRatio(ratioTotal) + " de compressão" : "")
    };
  }

  /* ---------- render ---------- */

  var dropEl = document.getElementById("drop");
  var dropTitle = document.getElementById("drop-title");
  var inputEl = document.getElementById("file");
  var errorEl = document.getElementById("error");
  var resultEl = document.getElementById("result");

  var state = { rows: [], onlyFlagged: false };

  var DEFAULT_TITLE = "Solte o .zip aqui";

  function showError(message) {
    errorEl.textContent = message;
    errorEl.hidden = false;
    dropEl.classList.remove("is-busy");
    dropTitle.textContent = DEFAULT_TITLE;
  }

  function statCard(label, value, hint, accent) {
    return '<div class="stat">' +
      '<p class="stat-label">' + label + "</p>" +
      '<p class="stat-value' + (accent ? " is-accent" : "") + '">' + value + "</p>" +
      '<p class="stat-hint">' + esc(hint) + "</p>" +
      "</div>";
  }

  function renderStats(analysis) {
    var flagged = analysis.rows.filter(function (row) { return row.flags.length > 0; }).length;
    document.getElementById("stats").innerHTML =
      statCard("Arquivos", formatCount(analysis.fileCount), formatCount(analysis.dirCount) + " pastas", false) +
      statCard("Descompactado", formatBytes(analysis.totalSize), "tamanho real somado", false) +
      statCard("Compactado", formatBytes(analysis.totalCompressed), "tamanho do .zip", false) +
      statCard("Taxa de compressão", formatRatio(analysis.ratio), "descompactado ÷ compactado", true) +
      statCard("Maior arquivo", analysis.largest ? formatBytes(analysis.largest.size) : "—",
        analysis.largest ? basename(analysis.largest.path) : "sem arquivos", false) +
      statCard("Sinalizados", formatCount(flagged), "entradas com algum alerta", false);
  }

  function renderAlerts(alerts, dangerous) {
    var box = document.getElementById("alerts");
    var count = document.getElementById("alert-count");
    count.textContent = alerts.length === 0 ? "nenhum sinal" : alerts.length + " encontrado(s)";

    var html = "";
    if (alerts.length === 0) {
      html = '<div class="alerts-ok"><div><strong>Nada suspeito por aqui</strong>' +
        "<span>Nenhuma extensão crítica, caminho malicioso ou expansão anormal foi detectada neste pacote.</span></div></div>";
    } else {
      html = alerts.map(function (alert) {
        return '<div class="alert alert-' + alert.severity + '">' +
          '<div class="alert-body">' +
            '<div class="alert-top">' +
              '<p class="alert-title">' + esc(alert.title) + "</p>" +
              '<span class="alert-sev">' + (SEVERITY_LABEL[alert.severity] || "") + "</span>" +
            "</div>" +
            '<p class="alert-detail">' + esc(alert.detail) + "</p>" +
          "</div>" +
        "</div>";
      }).join("");
    }

    if (dangerous.length) {
      html += '<div class="ext-list"><p class="ext-title">Extensões que merecem atenção</p><div class="ext-items">' +
        dangerous.slice(0, 14).map(function (item) {
          return '<span class="ext">.' + esc(item.ext) + "<i>×" + item.count + "</i></span>";
        }).join("") +
        "</div></div>";
    }

    box.innerHTML = html;
  }

  function renderRows() {
    var list = state.onlyFlagged
      ? state.rows.filter(function (row) { return row.flags.length > 0; })
      : state.rows;
    var shown = list.slice(0, LIMIT);
    var tbody = document.getElementById("rows");

    if (!shown.length) {
      tbody.innerHTML = '<tr><td class="empty" colspan="5">Nenhum arquivo com sinal de alerta neste pacote.</td></tr>';
    } else {
      tbody.innerHTML = shown.map(function (row) {
        var flags = row.flags.length
          ? row.flags.map(function (flag) {
              return '<span class="tag tag-' + flag + '">' + (FLAG_LABEL[flag] || flag) + "</span>";
            }).join("")
          : '<span class="tag-ok">ok</span>';
        var ratio = row.ratio
          ? '<span class="ratio' + (row.ratio >= 100 ? " is-hot" : "") + '">' + formatRatio(row.ratio) + "</span>"
          : '<span class="ratio">—</span>';
        var dir = dirname(row.path);

        return "<tr>" +
          '<td class="cell-path" title="' + esc(row.path) + '">' +
            (dir ? '<span class="path-dir">' + esc(dir) + "/</span>" : "") +
            '<span class="path-name">' + esc(basename(row.path)) + "</span>" +
          "</td>" +
          '<td class="cell-num">' + formatBytes(row.size) + "</td>" +
          '<td class="cell-num cell-muted">' + formatBytes(row.compressed) + "</td>" +
          "<td>" + ratio + "</td>" +
          '<td class="cell-flags">' + flags + "</td>" +
        "</tr>";
      }).join("");
    }

    var note = document.getElementById("table-note");
    if (list.length > LIMIT) {
      note.hidden = false;
      note.textContent = "Mostrando " + LIMIT + " de " + formatCount(list.length) + " entradas";
    } else {
      note.hidden = true;
    }

    document.getElementById("tab-flagged").textContent =
      "Suspeitos · " + formatCount(state.rows.filter(function (row) { return row.flags.length > 0; }).length);
  }

  function setTab(onlyFlagged) {
    state.onlyFlagged = onlyFlagged;
    document.getElementById("tab-all").classList.toggle("is-on", !onlyFlagged);
    document.getElementById("tab-flagged").classList.toggle("is-on", onlyFlagged);
    renderRows();
  }

  document.getElementById("tab-all").addEventListener("click", function () { setTab(false); });
  document.getElementById("tab-flagged").addEventListener("click", function () { setTab(true); });

  function render(file, analysis) {
    document.getElementById("file-name").textContent = file.name;
    document.getElementById("file-meta").textContent = formatBytes(file.size) + " no disco";
    document.getElementById("summary").textContent = analysis.summary;

    var color = TONE_COLOR[analysis.level.tone] || TONE_COLOR.safe;
    var scoreEl = document.getElementById("score");
    scoreEl.textContent = analysis.score;
    scoreEl.style.color = color;

    var chip = document.getElementById("level-chip");
    chip.textContent = analysis.level.label;
    chip.className = "chip chip-" + analysis.level.tone;

    document.getElementById("verdict").textContent = analysis.level.blurb;

    var arc = document.getElementById("gauge-arc");
    var length = Math.PI * 86;
    arc.style.stroke = color;
    arc.setAttribute("stroke-dasharray", (analysis.score / 100) * length + " " + (length + 10));

    renderStats(analysis);
    renderAlerts(analysis.alerts, analysis.dangerous);

    state.rows = analysis.rows;
    state.onlyFlagged = false;
    document.getElementById("tab-all").classList.add("is-on");
    document.getElementById("tab-flagged").classList.remove("is-on");
    renderRows();

    resultEl.hidden = false;
    resultEl.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function handleFile(file) {
    errorEl.hidden = true;
    dropEl.classList.add("is-busy");
    dropTitle.textContent = "Lendo o índice do ZIP…";

    if (typeof JSZip === "undefined") {
      showError("A biblioteca JSZip não carregou. Verifique sua conexão e recarregue a página.");
      return;
    }

    JSZip.loadAsync(file).then(function (zip) {
      var entries = [];
      zip.forEach(function (path, entry) {
        var data = entry._data || {};
        entries.push({
          path: path,
          isDir: !!entry.dir,
          size: typeof data.uncompressedSize === "number" ? data.uncompressedSize : 0,
          compressed: typeof data.compressedSize === "number" ? data.compressedSize : 0
        });
      });
      render(file, analyze(entries));
      dropEl.classList.remove("is-busy");
      dropTitle.textContent = "Analisar outro arquivo";
    }).catch(function () {
      showError("Não foi possível ler este arquivo como ZIP. Ele pode estar corrompido, protegido por senha ou simplesmente não ser um ZIP.");
    });
  }

  function openPicker() {
    inputEl.click();
  }

  dropEl.addEventListener("click", openPicker);
  dropEl.addEventListener("keydown", function (event) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      openPicker();
    }
  });
  dropEl.addEventListener("dragover", function (event) {
    event.preventDefault();
    dropEl.classList.add("is-drag");
  });
  dropEl.addEventListener("dragleave", function () {
    dropEl.classList.remove("is-drag");
  });
  dropEl.addEventListener("drop", function (event) {
    event.preventDefault();
    dropEl.classList.remove("is-drag");
    if (event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0]) {
      handleFile(event.dataTransfer.files[0]);
    }
  });
  inputEl.addEventListener("change", function () {
    if (inputEl.files && inputEl.files[0]) handleFile(inputEl.files[0]);
    inputEl.value = "";
  });
})();
