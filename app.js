// 화면 연결: 로컬 JSON 선택·비교 결과 표시·AI 입력 내보내기·AI 결과 가져오기(모든 문서 내용은 textContent로만 출력)
(function (root) {
  'use strict';
  const E = root.ChangeEngine || (typeof require === 'function' ? require('./engine.js') : null);

  function el(doc, tag, text, cls) {
    const n = doc.createElement(tag);
    if (text != null) n.textContent = String(text);
    if (cls) n.className = cls;
    return n;
  }

  function table(doc, headers, rows, rowClass) {
    const t = el(doc, 'table');
    const head = el(doc, 'tr');
    headers.forEach(h => head.appendChild(el(doc, 'th', h)));
    t.appendChild(head);
    rows.forEach((cells, i) => {
      const tr = el(doc, 'tr', null, rowClass ? rowClass(i) : null);
      cells.forEach(c => tr.appendChild(el(doc, 'td', c == null ? '—' : c)));
      t.appendChild(tr);
    });
    return t;
  }

  function renderDocMeta(doc, role, d) {
    const box = el(doc, 'div', null, 'meta');
    box.appendChild(el(doc, 'strong', role + ' '));
    if (d && d.synthetic === true) box.appendChild(el(doc, 'span', '가상 규정(합성 데이터)', 'badge virtual'));
    else box.appendChild(el(doc, 'span', '실제 규정 여부 미확인 — 공식 출처와 대조 필요', 'badge unknown'));
    if (d && d.title) box.appendChild(el(doc, 'div', d.title));
    const line = d === undefined ? '파일 미선택' : d && typeof d === 'object'
      ? `documentId ${d.documentId ?? '—'} · version ${d.version ?? '—'} · 시행일 ${d.effectiveDate ?? '—'} · 출처 ${d.sourceUrl || '없음'}`
      : `JSON 객체가 아닙니다(${JSON.stringify(d)}).`;
    box.appendChild(el(doc, 'div', line, 'small'));
    return box;
  }

  function renderHolds(doc, holds) {
    const ul = el(doc, 'ul', null, 'holds');
    holds.forEach(h => ul.appendChild(el(doc, 'li', `[${h.code}] ${h.message}`)));
    return ul;
  }

  function renderDiff(doc, rows) {
    return table(doc, ['조항 ID', '구분', '변경 전', '변경 후', '비고'],
      rows.map(r => [r.clauseId, r.typeLabel, r.beforeText, r.afterText, r.suspicious ? '문서 내 명령문 의심' : '']),
      i => 'type-' + rows[i].type);
  }

  function renderFindings(doc, imported) {
    const f = imported.findings;
    return table(doc, ['상태', '조항', '문안', 'AI 제안 impact', '조항 인용', '문안 인용', 'AI 이유', '검증 메모'],
      f.map(x => [x.status, x.finding && x.finding.clauseId, x.finding && x.finding.labelId, x.finding && x.finding.impact,
        x.finding && x.finding.clauseQuote, x.finding && x.finding.labelQuote, x.finding && x.finding.reason, x.reasons.join(' ')]),
      i => f[i].status === '거부' ? 'st-reject' : f[i].status === '보류' ? 'st-hold' : 'st-ok');
  }

  // 상태 배지 색: 가져온 결과가 전부 검토 후보로 통과했을 때만 정상색
  function statusClass(a, imported) {
    if (a && a.status === '보류') return 'st-hold';
    if (!imported) return '';
    if (!imported.accepted) return 'st-reject';
    return imported.contaminated || !imported.findings.length || imported.findings.some(x => x.status !== 'AI 제안(검토 필요)') ? 'st-hold' : 'st-ok';
  }

  if (typeof module === 'object' && module.exports) {
    module.exports = { el, renderDocMeta, renderHolds, renderDiff, renderFindings, statusClass };
    return;
  }

  // ---------- 브라우저 연결 ----------
  const doc = root.document;
  const $ = id => doc.getElementById(id);
  // before/after/labels: 아직 안 읽었으면 undefined(null·0·false 같은 JSON 값도 '읽음'으로 보고 형식 보류를 보인다)
  const state = { before: undefined, after: undefined, labels: undefined, pkg: null, analysis: null, imported: null, names: {}, errs: {} };
  const named = (role, key) => state.names[key] ? `${role} (${state.names[key]})` : role;

  function readJsonFile(file, cb) {
    const r = new FileReader();
    r.onload = () => {
      try { cb(null, JSON.parse(r.result)); } catch (e) { cb('JSON을 읽을 수 없습니다: ' + e.message); }
    };
    r.onerror = () => cb('파일을 읽을 수 없습니다.');
    r.readAsText(file, 'utf-8');
  }

  function download(name, text, type) {
    const a = doc.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type }));
    a.download = name;
    doc.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  function replace(id, ...nodes) {
    $(id).replaceChildren(...nodes);
  }

  function refresh() {
    const L = state.labels;
    replace('meta', renderDocMeta(doc, named('변경 전', 'before'), state.before), renderDocMeta(doc, named('변경 후', 'after'), state.after),
      el(doc, 'div', L === undefined ? '문안 파일 미선택' : named('문안', 'labels') + ` ${L && Array.isArray(L.labels) ? L.labels.length : 0}개` +
        (L && L.synthetic === true ? ' · 가상 문안(합성 데이터)' : ''), 'small'));

    const ready = ['before', 'after', 'labels'].every(k => state[k] !== undefined);
    state.analysis = null;
    state.pkg = null;
    if (ready) {
      state.pkg = E.buildAiPackage(state.before, state.after, state.labels);
      state.analysis = state.pkg.analysis;
    }
    const a = state.analysis;
    $('status').textContent = E.overallStatus(a, state.imported);
    $('status').className = 'status ' + statusClass(a, state.imported);

    if (!a) {
      replace('holds');
      replace('diff', el(doc, 'p', '변경 전·변경 후·문안 JSON 파일 세 개를 모두 선택하세요.', 'small'));
    } else {
      replace('holds', ...(a.holds.length ? [el(doc, 'p', '보류 사유 — 해결 전에는 AI 입력을 만들지 않습니다.'), renderHolds(doc, a.holds)] : []));
      const c = a.counts;
      replace('diff', el(doc, 'p', `변경없음 ${c.unchanged} · 수정 ${c.modified} · 추가 ${c.added} · 삭제 ${c.removed}`),
        ...(a.suspects.length ? [el(doc, 'p', `문서 내 명령문 의심: ${a.suspects.join(', ')} — AI 결과를 가져와도 전부 보류합니다.`, 'st-hold')] : []),
        ...(a.rows.length ? [renderDiff(doc, a.rows)] : [el(doc, 'p', a.skipReason || '비교할 조항이 없습니다.', 'small')]));
    }

    const ok = !!(state.pkg && state.pkg.ok);
    ['btnPrompt', 'btnInput', 'resultFile', 'btnPaste'].forEach(id => { $(id).disabled = !ok; });
    $('hash').textContent = ok ? state.pkg.inputSha256 : '—';
    $('prompt').value = ok ? state.pkg.prompt : '';

    if (!state.imported) {
      replace('findings', el(doc, 'p', ok ? '분석 전 — 아직 AI 결과를 가져오지 않았습니다.' : '분석 전', 'small'));
    } else if (!state.imported.accepted) {
      replace('findings', el(doc, 'p', '가져오기 거부: ' + state.imported.error, 'st-reject'));
    } else {
      const im = state.imported;
      const summary = Object.keys(im.counts).map(k => `${k} ${im.counts[k]}`).join(' · ') || '결과 항목 0개';
      replace('findings',
        el(doc, 'p', `입력 SHA-256 일치 확인. ${summary}. AI 결과는 사람이 검토할 후보이며 정답이나 법적 판정이 아닙니다.`),
        renderFindings(doc, im),
        el(doc, 'p', uncoveredText(im), 'small'));
    }
  }

  // (조항, 문안) 조합 단위로 검토 후보가 없는 곳을 알린다. 보류·거부 조합도 분석 전과 같다.
  function uncoveredText(im) {
    const total = state.pkg.input.changes.length * state.pkg.input.labels.length;
    const n = im.uncovered.reduce((s, u) => s + u.labelIds.length, 0);
    if (!n) return `모든 (조항, 문안) 조합 ${total}개에 검토 후보가 있습니다. 후보마다 사람이 원문과 대조해야 합니다.`;
    return `검토 후보가 없는 (조항, 문안) 조합 ${n}/${total}개는 분석 전입니다(보류·거부 포함): ` +
      im.uncovered.map(u => `${u.clauseId}: ${u.labelIds.join(', ')}`).join(' · ');
  }

  function onDocFile(key) {
    return e => {
      const file = e.target.files[0];
      if (!file) return;
      e.target.value = ''; // 같은 파일을 고쳐 다시 골라도 change 이벤트가 나게 한다
      readJsonFile(file, (err, data) => {
        state[key] = err ? undefined : data;
        state.names[key] = err ? '' : file.name;
        state.imported = null; // 입력이 바뀌면 이전 AI 결과는 해시가 맞지 않으므로 버린다
        state.errs[key] = err ? `${file.name}: ${err}` : ''; // 다른 칸을 다시 읽어도 이 칸의 오류는 남는다
        $('err').textContent = Object.values(state.errs).filter(Boolean).join(' / ');
        refresh();
      });
    };
  }

  function importResult(data) {
    state.imported = E.importAiResult(state.pkg, data);
    refresh();
  }

  $('fileBefore').addEventListener('change', onDocFile('before'));
  $('fileAfter').addEventListener('change', onDocFile('after'));
  $('fileLabels').addEventListener('change', onDocFile('labels'));
  $('btnPrompt').addEventListener('click', () => download(`ai-prompt-${state.pkg.inputSha256.slice(0, 12)}.txt`, state.pkg.prompt, 'text/plain;charset=utf-8'));
  $('btnInput').addEventListener('click', () => download(`ai-input-${state.pkg.inputSha256.slice(0, 12)}.json`,
    JSON.stringify({ inputSha256: state.pkg.inputSha256, input: state.pkg.input }, null, 2), 'application/json'));
  $('resultFile').addEventListener('change', e => {
    const file = e.target.files[0];
    if (!file) return;
    readJsonFile(file, (err, data) => {
      if (err) { state.imported = { accepted: false, error: err }; refresh(); } else importResult(data);
      e.target.value = '';
    });
  });
  $('btnPaste').addEventListener('click', () => {
    let data;
    try { data = JSON.parse($('pasted').value); } catch (e) {
      state.imported = { accepted: false, error: 'JSON을 읽을 수 없습니다: ' + e.message };
      return refresh();
    }
    importResult(data);
  });
  refresh();
})(typeof window !== 'undefined' ? window : globalThis);
