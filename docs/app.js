// patch-now client-side checker. No network, no HTML string sinks, no eval.
// Every advisory-derived string reaches the DOM only through textContent.
'use strict';
(function () {
  const P = PatchNow;
  const MAX_CHARS = 20 * 1024 * 1024;
  const $ = (id) => document.getElementById(id);

  function setStatus(msg, bad) {
    $('status').textContent = msg;
    $('status').className = bad ? 'bad' : '';
  }

  function cell(tr, text) {
    const td = document.createElement('td');
    td.textContent = P.safeText(text, 400);
    tr.appendChild(td);
    return td;
  }

  function parseInventory(kind, text, eco) {
    if (kind === 'list') return P.parsePlainList(text, eco || null);
    if (kind === 'pip') return P.parsePipList(text);
    if (kind === 'dpkg') {
      if (eco && !/^(Debian|Ubuntu)(:[A-Za-z0-9.]{1,20}){0,3}$/.test(eco)) throw new Error('distribution must look like Debian:12 or Ubuntu:22.04:LTS');
      return P.parseDpkgStatus(text, eco || 'Debian');
    }
    let json;
    try {
      json = JSON.parse(text);
    } catch (e) {
      throw new Error('package list is not valid JSON');
    }
    return kind === 'npm-lock' ? P.parseNpmLock(json) : P.parseNpmLs(json);
  }

  function loadOsv(index, text, wanted) {
    const t = text.trim();
    try {
      P.addJsonValue(index, JSON.parse(t), wanted);
      return;
    } catch (e) {
      if (!(e instanceof SyntaxError)) throw e;
    }
    let ok = 0;
    for (const line of t.split('\n')) {
      if (!line.trim()) continue;
      try {
        P.addJsonValue(index, JSON.parse(line), wanted);
        ok++;
      } catch (e) {
        if (!(e instanceof SyntaxError)) throw e;
      }
    }
    if (!ok) throw new Error('OSV data is neither JSON nor NDJSON');
  }

  function render(report) {
    const tbody = $('results').querySelector('tbody');
    tbody.replaceChildren();
    const rows = report.findings.concat(report.undetermined);
    for (const f of rows) {
      const tr = document.createElement('tr');
      if (f.known_exploited) tr.className = 'kev';
      else if (f.malicious_package) tr.className = 'mal';
      if (f.match.status !== 'affected') tr.classList.add('undecided');
      cell(tr, f.priority ? String(f.priority) : '?');
      cell(tr, f.ecosystem + ' ' + f.package);
      cell(tr, f.installed);
      const aka = f.also_known_as || [];
      cell(tr, f.id + (aka.length ? ' (also ' + aka.slice(0, 4).join(', ') + (aka.length > 4 ? ', ...' : '') + ')' : ''));
      cell(tr, f.severity.rating + (f.severity.score !== null ? ' ' + f.severity.score.toFixed(1) : ''));
      const flags = [];
      if (f.known_exploited) flags.push('KNOWN EXPLOITED (' + f.known_exploited.cve + ')');
      if (f.malicious_package) flags.push('MALICIOUS: remove');
      if (f.match.approximate) flags.push('approximate');
      if (f.match.status !== 'affected') flags.push('could not decide');
      cell(tr, flags.join(', '));
      cell(tr, f.fixed_versions.length ? f.fixed_versions.join(', ') : 'none listed');
      cell(tr, f.summary);
      tbody.appendChild(tr);
    }
    $('results').hidden = rows.length === 0;
    $('json').value = P.safeJson(report);
  }

  function run() {
    try {
      const fields = ['inv', 'osv', 'kev', 'eco'].map((id) => $(id).value);
      if (fields.some((v) => v.length > MAX_CHARS)) throw new Error('input over ' + MAX_CHARS + ' characters');
      const [invText, osvText, kevText, eco] = fields;
      if (!invText.trim()) throw new Error('paste a package list first');
      if (!osvText.trim()) throw new Error('paste OSV advisory JSON');
      const inv = parseInventory($('kind').value, invText, eco.trim());
      const index = P.createIndex();
      loadOsv(index, osvText, P.wantedKeys(inv.packages));
      let kev = null;
      if (kevText.trim()) {
        let kj;
        try {
          kj = JSON.parse(kevText);
        } catch (e) {
          throw new Error('KEV data is not valid JSON');
        }
        kev = P.parseKev(kj);
      }
      const findings = P.matchPackages(index, inv.packages);
      if (index.findingsTruncated) inv.warnings.push('finding limit reached; the report is incomplete');
      const report = P.buildReport({ inventory: inv, findings, kev, mode: 'browser (offline)', osvInfo: { records_used: index.count } });
      render(report);
      const s = report.summary;
      setStatus('Checked ' + s.packages_checked + ' packages: ' + s.findings + ' findings (' + s.known_exploited + ' known exploited, ' +
        s.malicious_packages + ' malicious), ' + s.undetermined + ' undecided, ' + s.skipped_entries + ' entries skipped.' +
        (kev ? '' : ' No KEV catalog given, so known-exploited flags are missing.'), false);
    } catch (e) {
      $('results').hidden = true;
      $('json').value = '';
      setStatus('Error: ' + P.safeText(e && e.message, 300), true);
    }
  }

  function demo() {
    $('kind').value = PATCH_NOW_DEMO.kind;
    $('eco').value = PATCH_NOW_DEMO.eco;
    $('inv').value = PATCH_NOW_DEMO.inv;
    $('osv').value = PATCH_NOW_DEMO.osv;
    $('kev').value = PATCH_NOW_DEMO.kev;
    run();
  }

  for (const a of P.ATTRIBUTION) {
    const li = document.createElement('li');
    li.textContent = a;
    $('attribution').appendChild(li);
  }
  $('run').addEventListener('click', run);
  $('demo').addEventListener('click', demo);
})();
