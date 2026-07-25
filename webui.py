"""Локальный веб-интерфейс к demo.py: пароль -> Argon2id -> шифротекст.

Запускается из demo.py::

    python demo.py --serve
    python demo.py --serve --port 8800 --no-browser

Сервер поднимается на стандартной библиотеке -- никаких зависимостей сверх
уже нужных demo.py. Страница самодостаточна: ни одного внешнего запроса,
весь CSS и JS встроены. Это не украшательство, а требование: инструмент,
который показывает пароли и ключи, не должен ходить в чужие CDN.

Защита. Сервер слушает ТОЛЬКО 127.0.0.1, но этого мало: любая открытая в
браузере страница может отправить запрос на localhost. Поэтому дополнительно
проверяются три вещи.

* Заголовок Host обязан быть 127.0.0.1 или localhost с нашим портом. Это
  закрывает DNS rebinding, когда чужой домен резолвится в 127.0.0.1.
* Заголовок Origin, если он есть, обязан совпадать с нашим. Браузер шлёт
  Origin при кросс-сайтовых запросах, так что это отсекает CSRF.
* POST принимается только с Content-Type: application/json. Форма с чужого
  сайта такой заголовок поставить не может без preflight, а preflight мы не
  разрешаем.

Пароли не пишутся в лог: у HTTP-сервера отключён журнал запросов, а тела
запросов не логируются вовсе.
"""

from __future__ import annotations

import base64
import json
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dedalyan as D
import demo

MAX_BODY = 4 * 1024 * 1024        # 4 МиБ: демонстрация, не файловый сервис
MAX_TEXT_BYTES = 256 * 1024


# --------------------------------------------------------------------------
# Страница
# --------------------------------------------------------------------------

PAGE = r"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dedalyan-96/256 — Argon2id + HMAC</title>
<style>
:root {
  --bg: #0f1115;
  --panel: #171a21;
  --panel-2: #1d212a;
  --line: #2a2f3a;
  --fg: #e6e9ef;
  --fg-dim: #98a0b0;
  --accent: #6aa9ff;
  --ok: #4ec9a0;
  --bad: #ff6b6b;
  --warn: #e0b050;
  --seg-hdr: #6aa9ff;
  --seg-salt: #b98cff;
  --seg-nonce: #4ec9a0;
  --seg-ct: #5a6272;
  --seg-tag: #e0b050;
  --radius: 10px;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #f4f6fa; --panel: #ffffff; --panel-2: #f0f2f7; --line: #dde1e9;
    --fg: #1a1d24; --fg-dim: #616a7d; --accent: #2563eb; --ok: #0f9d76;
    --bad: #d92d20; --warn: #b45309; --seg-ct: #98a0b0;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.55 ui-sans-serif, system-ui, "Segoe UI", Roboto, sans-serif;
}
.wrap { max-width: 980px; margin: 0 auto; padding: 28px 20px 80px; }
header { margin-bottom: 22px; }
h1 { font-size: 22px; margin: 0 0 6px; letter-spacing: -0.01em; }
.sub { color: var(--fg-dim); font-size: 13.5px; }
.badges { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
.badge {
  font-size: 12px; padding: 3px 9px; border-radius: 999px;
  border: 1px solid var(--line); background: var(--panel); color: var(--fg-dim);
}
.badge.warn { border-color: var(--warn); color: var(--warn); }
.badge.ok { border-color: var(--ok); color: var(--ok); }

.tabs { display: flex; gap: 4px; margin: 22px 0 0; border-bottom: 1px solid var(--line); }
.tab {
  padding: 9px 16px; cursor: pointer; border: none; background: none;
  color: var(--fg-dim); font: inherit; font-size: 14px;
  border-bottom: 2px solid transparent; margin-bottom: -1px;
}
.tab:hover { color: var(--fg); }
.tab.active { color: var(--fg); border-bottom-color: var(--accent); }

.panel {
  background: var(--panel); border: 1px solid var(--line);
  border-radius: var(--radius); padding: 18px; margin-top: 18px;
}
label { display: block; font-size: 13px; color: var(--fg-dim); margin: 0 0 5px; }
input[type=text], input[type=password], textarea, input[type=number] {
  width: 100%; background: var(--panel-2); color: var(--fg);
  border: 1px solid var(--line); border-radius: 7px; padding: 9px 11px;
  font: inherit; outline: none;
}
input:focus, textarea:focus { border-color: var(--accent); }
textarea { resize: vertical; min-height: 90px; font-family: ui-monospace, Consolas, monospace; font-size: 13px; }
.row { display: flex; gap: 12px; flex-wrap: wrap; }
.row > * { flex: 1; min-width: 150px; }
.field { margin-bottom: 14px; }
.pw-wrap { position: relative; }
.pw-toggle {
  position: absolute; right: 8px; top: 50%; transform: translateY(-50%);
  background: none; border: none; color: var(--fg-dim); cursor: pointer;
  font-size: 12px; padding: 4px 6px;
}
button.go {
  background: var(--accent); color: #fff; border: none; border-radius: 7px;
  padding: 10px 20px; font: inherit; font-weight: 500; cursor: pointer;
}
button.go:hover { filter: brightness(1.1); }
button.go:disabled { opacity: .55; cursor: default; }
button.ghost {
  background: none; color: var(--fg-dim); border: 1px solid var(--line);
  border-radius: 7px; padding: 9px 15px; font: inherit; cursor: pointer;
}
button.ghost:hover { color: var(--fg); border-color: var(--accent); }
.actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }

details.params { margin-bottom: 14px; }
details.params summary {
  cursor: pointer; color: var(--fg-dim); font-size: 13px; padding: 4px 0;
}

.stage {
  border: 1px solid var(--line); border-radius: var(--radius);
  background: var(--panel); margin-top: 14px; overflow: hidden;
}
.stage > h3 {
  margin: 0; padding: 11px 16px; font-size: 13.5px; font-weight: 600;
  background: var(--panel-2); border-bottom: 1px solid var(--line);
  display: flex; align-items: center; gap: 9px;
}
.num {
  display: inline-flex; align-items: center; justify-content: center;
  width: 21px; height: 21px; border-radius: 50%; background: var(--accent);
  color: #fff; font-size: 11.5px; font-weight: 700; flex: none;
}
.stage > .body { padding: 14px 16px; }
.note { color: var(--fg-dim); font-size: 13px; margin: 9px 0 0; }

.kv { display: grid; grid-template-columns: max-content 1fr; gap: 7px 14px; align-items: start; }
.kv dt { color: var(--fg-dim); font-size: 13px; white-space: nowrap; }
.kv dd { margin: 0; min-width: 0; }
.mono {
  font-family: ui-monospace, Consolas, "Cascadia Mono", monospace;
  font-size: 12.5px; word-break: break-all; line-height: 1.5;
}
.copy {
  background: none; border: none; color: var(--fg-dim); cursor: pointer;
  font-size: 11px; padding: 1px 5px; border-radius: 4px; margin-left: 6px;
  border: 1px solid var(--line);
}
.copy:hover { color: var(--accent); border-color: var(--accent); }
.scroll { max-height: 190px; overflow: auto; }

.keybox {
  background: var(--panel-2); border: 1px solid var(--line);
  border-radius: 7px; padding: 10px 12px; margin: 6px 0 0;
}
.keybox .lbl { font-size: 11.5px; color: var(--fg-dim); margin-bottom: 3px; letter-spacing: .04em; }

.subkeys {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(158px, 1fr));
  gap: 5px 12px;
}
.subkeys span { font-family: ui-monospace, Consolas, monospace; font-size: 12px; color: var(--fg-dim); }
.subkeys b { color: var(--fg); font-weight: 500; }

.segbar { display: flex; height: 26px; border-radius: 6px; overflow: hidden; margin: 4px 0 9px; }
.segbar div { display: flex; align-items: center; justify-content: center;
  font-size: 10.5px; color: #0f1115; font-weight: 600; min-width: 2px; }
.legend { display: flex; gap: 14px; flex-wrap: wrap; font-size: 12px; color: var(--fg-dim); }
.legend i { display: inline-block; width: 9px; height: 9px; border-radius: 2px; margin-right: 5px; }

.verdict { padding: 13px 15px; border-radius: 8px; font-size: 14px; margin-top: 4px; }
.verdict.ok { background: color-mix(in srgb, var(--ok) 14%, transparent); border: 1px solid var(--ok); }
.verdict.bad { background: color-mix(in srgb, var(--bad) 14%, transparent); border: 1px solid var(--bad); }
.verdict b { display: block; margin-bottom: 3px; }

.spinner {
  display: none; width: 15px; height: 15px; border: 2px solid var(--line);
  border-top-color: var(--accent); border-radius: 50%;
  animation: spin .7s linear infinite;
}
.spinner.on { display: inline-block; }
@keyframes spin { to { transform: rotate(360deg); } }

footer { margin-top: 34px; color: var(--fg-dim); font-size: 12.5px; line-height: 1.7; }
footer code { background: var(--panel-2); padding: 1px 5px; border-radius: 4px; }
.hidden { display: none; }
</style>
</head>
<body>
<div class="wrap">

<header>
  <h1>Dedalyan-96/256 · Argon2id · HMAC-SHA256</h1>
  <div class="sub">Пароль → ключи → шифрование с аутентификацией. Каждый шаг показан целиком.</div>
  <div class="badges" id="badges"></div>
</header>

<div class="tabs">
  <button class="tab active" data-tab="enc">Шифрование</button>
  <button class="tab" data-tab="dec">Расшифровка</button>
</div>

<!-- ---------------- ШИФРОВАНИЕ ---------------- -->
<section id="tab-enc">
  <div class="panel">
    <div class="field">
      <label for="e-pw">Пароль</label>
      <div class="pw-wrap">
        <input type="password" id="e-pw" value="correct horse battery staple" autocomplete="off" spellcheck="false">
        <button class="pw-toggle" data-for="e-pw">показать</button>
      </div>
    </div>
    <div class="field">
      <label for="e-text">Открытый текст</label>
      <textarea id="e-text" spellcheck="false">Dedalyan-96/256 demo. Шифр учебный, Argon2 настоящий. The quick brown fox jumps over the lazy dog. 0123456789</textarea>
    </div>
    <details class="params">
      <summary>Параметры Argon2id</summary>
      <div class="row" style="margin-top:10px">
        <div><label for="e-t">Проходы (t)</label><input type="number" id="e-t" value="3" min="1" max="255"></div>
        <div><label for="e-m">Память, КиБ (m)</label><input type="number" id="e-m" value="65536" min="8"></div>
        <div><label for="e-p">Потоки (p)</label><input type="number" id="e-p" value="4" min="1" max="255"></div>
      </div>
      <p class="note">Значения по умолчанию — второй рекомендованный набор RFC 9106.
      Память здесь важнее проходов: именно она лишает GPU преимущества.</p>
    </details>
    <div class="actions">
      <button class="go" id="e-go">Зашифровать</button>
      <div class="spinner" id="e-spin"></div>
      <span class="note" id="e-status"></span>
    </div>
  </div>
  <div id="e-out"></div>
</section>

<!-- ---------------- РАСШИФРОВКА ---------------- -->
<section id="tab-dec" class="hidden">
  <div class="panel">
    <div class="field">
      <label for="d-pw">Пароль</label>
      <div class="pw-wrap">
        <input type="password" id="d-pw" autocomplete="off" spellcheck="false">
        <button class="pw-toggle" data-for="d-pw">показать</button>
      </div>
    </div>
    <div class="field">
      <label for="d-env">Конверт (base64)</label>
      <textarea id="d-env" spellcheck="false" placeholder="вставьте конверт, или зашифруйте что-нибудь на соседней вкладке"></textarea>
    </div>
    <div class="actions">
      <button class="go" id="d-go">Расшифровать</button>
      <button class="ghost" id="d-tamper">Подделать один бит и попробовать</button>
      <div class="spinner" id="d-spin"></div>
      <span class="note" id="d-status"></span>
    </div>
    <p class="note">Кнопка подделки переворачивает один бит шифротекста. Тег проверяется
    <b>до</b> расшифровки, поэтому конверт будет отвергнут, а не расшифрован в мусор.</p>
  </div>
  <div id="d-out"></div>
</section>

<footer>
  <b>Argon2id и HMAC-SHA256 — настоящие, промышленного уровня. Сам шифр Dedalyan — нет:</b>
  учебная конструкция без независимого криптоанализа. Для реальных данных нужен
  AES-GCM или ChaCha20-Poly1305.<br>
  Сервер слушает только <code>127.0.0.1</code>; страница не делает ни одного внешнего запроса.
  Пароли передаются по обычному HTTP внутри машины и нигде не сохраняются.
</footer>

</div>
<script>
const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[&<>"']/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

document.querySelectorAll('.tab').forEach(t => t.onclick = () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  t.classList.add('active');
  $('#tab-enc').classList.toggle('hidden', t.dataset.tab !== 'enc');
  $('#tab-dec').classList.toggle('hidden', t.dataset.tab !== 'dec');
});

document.querySelectorAll('.pw-toggle').forEach(b => b.onclick = () => {
  const el = $('#' + b.dataset.for);
  const show = el.type === 'password';
  el.type = show ? 'text' : 'password';
  b.textContent = show ? 'скрыть' : 'показать';
});

async function api(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  });
  return await r.json();
}

function copyBtn(text) {
  return `<button class="copy" onclick="navigator.clipboard.writeText('${esc(text)}');this.textContent='ok';setTimeout(()=>this.textContent='copy',900)">copy</button>`;
}

function stage(n, title, inner) {
  return `<div class="stage"><h3><span class="num">${n}</span>${esc(title)}</h3>
          <div class="body">${inner}</div></div>`;
}

function segbar(sizes) {
  const total = sizes.reduce((a, s) => a + s.n, 0);
  const bars = sizes.map(s =>
    `<div style="width:${(100 * s.n / total).toFixed(3)}%;background:${s.c}"
          title="${esc(s.name)}: ${s.n} B">${s.n >= total * 0.07 ? s.n : ''}</div>`).join('');
  const leg = sizes.map(s =>
    `<span><i style="background:${s.c}"></i>${esc(s.name)} — ${s.n} B</span>`).join('');
  return `<div class="segbar">${bars}</div><div class="legend">${leg}</div>`;
}

// ---------------- шифрование ----------------
$('#e-go').onclick = async () => {
  const btn = $('#e-go'), spin = $('#e-spin'), st = $('#e-status');
  btn.disabled = true; spin.classList.add('on'); st.textContent = 'Argon2id считает…';
  $('#e-out').innerHTML = '';
  try {
    const r = await api('/api/encrypt', {
      password: $('#e-pw').value,
      text: $('#e-text').value,
      t: +$('#e-t').value, m: +$('#e-m').value, p: +$('#e-p').value
    });
    if (!r.ok) { st.textContent = ''; $('#e-out').innerHTML =
      `<div class="panel"><div class="verdict bad"><b>Ошибка</b>${esc(r.error)}</div></div>`; return; }
    st.textContent = '';
    renderEncrypt(r);
    $('#d-env').value = r.envelope_b64;
    $('#d-pw').value = $('#e-pw').value;
  } catch (e) {
    st.textContent = 'сбой запроса: ' + e;
  } finally { btn.disabled = false; spin.classList.remove('on'); }
};

function renderEncrypt(r) {
  let h = '';

  h += stage(1, 'Вход', `<dl class="kv">
    <dt>открытый текст</dt><dd>${esc(r.plaintext_preview)}</dd>
    <dt>размер</dt><dd>${r.sizes.plaintext} байт</dd>
    <dt>hex</dt><dd class="mono scroll">${esc(r.plaintext_hex)}</dd></dl>`);

  h += stage(2, 'Argon2id: пароль → два ключа', `<dl class="kv">
    <dt>соль</dt><dd class="mono">${esc(r.salt)}${copyBtn(r.salt)}</dd>
    <dt>параметры</dt><dd class="mono">t=${r.params.t}, m=${r.params.m} КиБ, p=${r.params.p}</dd>
    <dt>время</dt><dd>${r.ms} мс</dd></dl>
    <div class="keybox"><div class="lbl">КЛЮЧ ШИФРА (256 бит)</div>
      <div class="mono">${esc(r.enc_key)}${copyBtn(r.enc_key)}</div></div>
    <div class="keybox"><div class="lbl">КЛЮЧ MAC (256 бит)</div>
      <div class="mono">${esc(r.mac_key)}${copyBtn(r.mac_key)}</div></div>
    <p class="note">Argon2 выдаёт 64 байта одним вызовом, они режутся пополам. Один и тот же
    ключ нельзя отдавать двум разным примитивам — их взаимодействие не анализировалось.
    Оба ключа воспроизводимы из пары (пароль, соль), поэтому соль хранится открыто, а
    стойкость держится на пароле и на цене Argon2.</p>`);

  h += stage(3, 'Подключи Dedalyan из ключа шифра', `<div class="subkeys">` +
    r.subkeys.map((k, i) => `<span>k[<b>${String(i).padStart(2,' ')}</b>] = <b>${k}</b></span>`).join('') +
    `</div><p class="note">16 подключей по 48 бит, порождены расписанием на «лабиринтах».</p>`);

  h += stage(4, 'Шифрование в режиме CTR', `<dl class="kv">
    <dt>nonce</dt><dd class="mono">${esc(r.nonce)}</dd>
    <dt>старт счётчика</dt><dd class="mono">${esc(r.ctr_start)}</dd>
    <dt>шифротекст</dt><dd class="mono scroll">${esc(r.ciphertext_hex)}${copyBtn(r.ciphertext_hex)}</dd>
    </dl><p class="note">Счётчик собран как nonce (64 бита) ‖ номер блока (32 бита):
    уникальность гаммы гарантируется уникальностью nonce, а не вероятностью.</p>`);

  h += stage(5, 'Аутентификация: encrypt-then-MAC', `<dl class="kv">
    <dt>тег</dt><dd class="mono">${esc(r.tag)}${copyBtn(r.tag)}</dd></dl>
    <p class="note">HMAC-SHA256(mac_key, заголовок ‖ шифротекст), усечённый до 16 байт.
    Тег покрывает и заголовок, поэтому соль, nonce и параметры Argon2 подменить тоже нельзя.</p>`);

  h += stage(6, 'Конверт', segbar([
      {name: 'версия+параметры', n: r.sizes.meta, c: 'var(--seg-hdr)'},
      {name: 'соль', n: r.sizes.salt, c: 'var(--seg-salt)'},
      {name: 'nonce', n: r.sizes.nonce, c: 'var(--seg-nonce)'},
      {name: 'шифротекст', n: r.sizes.ciphertext, c: 'var(--seg-ct)'},
      {name: 'тег', n: r.sizes.tag, c: 'var(--seg-tag)'}]) +
    `<div style="margin-top:12px"><label>base64 ${copyBtn(r.envelope_b64)}</label>
     <div class="mono scroll">${esc(r.envelope_b64)}</div></div>
     <p class="note">Всего ${r.sizes.total} байт: ${r.sizes.header} заголовка +
     ${r.sizes.ciphertext} шифротекста + ${r.sizes.tag} тега. Секретен только пароль.</p>`);

  h += stage(7, 'Проверка кругового прохода', r.roundtrip
    ? `<div class="verdict ok"><b>OK</b>Расшифровка вернула исходный текст байт в байт.</div>`
    : `<div class="verdict bad"><b>СБОЙ</b>Расшифровка не совпала с исходным текстом.</div>`);

  $('#e-out').innerHTML = h;
}

// ---------------- расшифровка ----------------
async function runDecrypt(tamper) {
  const btn = $('#d-go'), spin = $('#d-spin'), st = $('#d-status');
  btn.disabled = true; spin.classList.add('on'); st.textContent = 'Argon2id считает…';
  $('#d-out').innerHTML = '';
  try {
    const r = await api('/api/decrypt', {
      password: $('#d-pw').value,
      envelope: $('#d-env').value.trim(),
      tamper: !!tamper
    });
    st.textContent = '';
    renderDecrypt(r, tamper);
  } catch (e) {
    st.textContent = 'сбой запроса: ' + e;
  } finally { btn.disabled = false; spin.classList.remove('on'); }
}
$('#d-go').onclick = () => runDecrypt(false);
$('#d-tamper').onclick = () => runDecrypt(true);

function renderDecrypt(r, tamper) {
  let h = '';
  if (!r.ok) {
    h += stage(1, tamper ? 'Подделанный конверт отвергнут' : 'Конверт отвергнут',
      `<div class="verdict bad"><b>REJECTED</b>${esc(r.error)}</div>
       <p class="note">${tamper
         ? 'Перевёрнут один бит шифротекста. В чистом CTR это перевернуло бы ровно тот же бит открытого текста, молча. Тег превращает подделку в обнаруженную ошибку.'
         : 'Тег проверяется до расшифровки, поэтому ничего не расшифровывалось вовсе. Причина — либо неверный пароль, либо изменённый конверт; отличить их нельзя, и это правильно.'}</p>`);
    $('#d-out').innerHTML = h;
    return;
  }
  h += stage(1, 'Заголовок конверта', `<dl class="kv">
    <dt>версия</dt><dd class="mono">${r.version}</dd>
    <dt>параметры Argon2</dt><dd class="mono">t=${r.params.t}, m=${r.params.m} КиБ, p=${r.params.p}</dd>
    <dt>соль</dt><dd class="mono">${esc(r.salt)}</dd>
    <dt>nonce</dt><dd class="mono">${esc(r.nonce)}</dd></dl>
    <p class="note">Параметры Argon2 лежат в конверте, поэтому старые конверты читаются
    и после смены настроек по умолчанию.</p>`);

  h += stage(2, 'Проверка тега', `<dl class="kv">
    <dt>тег</dt><dd class="mono">${esc(r.tag)}</dd></dl>
    <div class="verdict ok"><b>VERIFIED</b>Сравнение выполнено за постоянное время
    (<code>hmac.compare_digest</code>): обычное сравнение выходило бы на первом
    несовпавшем байте и выдавало бы по времени, сколько байт угадано.</div>`);

  h += stage(3, 'Ключ и расшифровка', `<div class="keybox">
    <div class="lbl">КЛЮЧ ШИФРА, ВОССТАНОВЛЕННЫЙ ИЗ ПАРОЛЯ + СОЛИ</div>
    <div class="mono">${esc(r.enc_key)}${copyBtn(r.enc_key)}</div></div>
    <dl class="kv" style="margin-top:12px">
    <dt>открытый текст</dt><dd>${esc(r.plaintext_preview)}</dd>
    <dt>размер</dt><dd>${r.size} байт</dd>
    <dt>hex</dt><dd class="mono scroll">${esc(r.plaintext_hex)}</dd></dl>`);

  $('#d-out').innerHTML = h;
}

// ---------------- шапка ----------------
fetch('/api/info').then(r => r.json()).then(i => {
  $('#badges').innerHTML =
    `<span class="badge ok">бэкенд: ${esc(i.backend)}</span>` +
    `<span class="badge">${esc(i.crosscheck)}</span>` +
    `<span class="badge">конверт v${i.version}</span>` +
    `<span class="badge warn">учебный шифр — не для реальных данных</span>`;
});
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------
# Сервер
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "DedalyanDemo/2"
    port = 0

    # -- защита ------------------------------------------------------------

    def _origin_ok(self) -> bool:
        """Host обязателен и должен быть локальным; Origin, если есть, -- наш."""
        allowed = {f"127.0.0.1:{self.port}", f"localhost:{self.port}",
                   f"[::1]:{self.port}"}
        host = (self.headers.get("Host") or "").strip()
        if host not in allowed:
            return False
        origin = self.headers.get("Origin")
        if origin is not None:
            ok = {f"http://127.0.0.1:{self.port}", f"http://localhost:{self.port}",
                  f"http://[::1]:{self.port}"}
            if origin not in ok:
                return False
        return True

    # -- вывод -------------------------------------------------------------

    def log_message(self, fmt, *a):
        """Журнал отключён: в запросах ходят пароли."""
        return

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        # Страница самодостаточна, поэтому политику можно затянуть до предела.
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; connect-src 'self'; "
                         "form-action 'none'; base-uri 'none'")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionAbortedError):
            pass

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    # -- маршруты ----------------------------------------------------------

    def do_GET(self):
        if not self._origin_ok():
            self._send(403, b"forbidden", "text/plain; charset=utf-8")
            return
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        elif self.path == "/api/info":
            engine, _ = demo.get_engine()
            self._json(200, {
                "backend": engine,
                "crosscheck": demo.cross_check_backends(),
                "version": demo.VERSION,
            })
        else:
            self._send(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self):
        if not self._origin_ok():
            self._json(403, {"ok": False, "error": "forbidden origin"})
            return
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if ctype != "application/json":
            self._json(415, {"ok": False, "error": "expected application/json"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._json(400, {"ok": False, "error": "bad Content-Length"})
            return
        if length <= 0 or length > MAX_BODY:
            self._json(413, {"ok": False, "error": "body too large"})
            return
        try:
            req = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self._json(400, {"ok": False, "error": "malformed JSON"})
            return

        try:
            if self.path == "/api/encrypt":
                self._json(200, api_encrypt(req))
            elif self.path == "/api/decrypt":
                self._json(200, api_decrypt(req))
            else:
                self._json(404, {"ok": False, "error": "unknown endpoint"})
        except Exception as exc:                 # наружу -- без трассировки
            self._json(200, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})


# --------------------------------------------------------------------------
# Обработчики API
# --------------------------------------------------------------------------

def _preview(data: bytes, limit: int = 400) -> str:
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        return f"<двоичные данные, {len(data)} байт>"
    return s if len(s) <= limit else s[:limit] + " …"


def _hex(data: bytes, limit: int = 4096) -> str:
    h = data[:limit].hex()
    return h if len(data) <= limit else h + f" … (+{len(data) - limit} байт)"


def api_encrypt(req):
    password = str(req.get("password", ""))
    text = str(req.get("text", ""))
    plaintext = text.encode("utf-8")

    if not password:
        return {"ok": False, "error": "пароль пуст"}
    if len(plaintext) > MAX_TEXT_BYTES:
        return {"ok": False,
                "error": f"текст длиннее {MAX_TEXT_BYTES} байт (это демонстрация)"}

    try:
        t = int(req.get("t", demo.ARGON2_TIME))
        m = int(req.get("m", demo.ARGON2_MEMORY_KIB))
        p = int(req.get("p", demo.ARGON2_LANES))
    except (TypeError, ValueError):
        return {"ok": False, "error": "параметры Argon2 должны быть числами"}
    if not (1 <= t <= 255 and 1 <= p <= 255):
        return {"ok": False, "error": "t и p должны укладываться в один байт"}
    if not (8 <= m < (1 << 32)):
        return {"ok": False, "error": "память вне допустимого диапазона"}
    # Верхняя граница на память: иначе вкладка браузера подвесит машину.
    if m > 2 * 1024 * 1024:
        return {"ok": False, "error": "память ограничена 2 ГиБ в этом интерфейсе"}

    t0 = time.perf_counter()
    envelope, salt, nonce, enc_key, mac_key, ciphertext, tag = \
        demo.encrypt(password, plaintext, t, m, p)
    ms = int((time.perf_counter() - t0) * 1000)

    # Круговой проход считаем здесь же: показывать «зашифровано» без проверки
    # расшифровки -- значит показывать необоснованное.
    back, *_ = demo.decrypt(password, envelope)

    ks = D.key_schedule(D.key_from_bytes(enc_key))

    return {
        "ok": True,
        "ms": ms,
        "params": {"t": t, "m": m, "p": p},
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ctr_start": f"{demo._ctr_start(nonce):024x}",
        "enc_key": enc_key.hex(),
        "mac_key": mac_key.hex(),
        "subkeys": [f"{k:012x}" for k in ks],
        "plaintext_preview": _preview(plaintext),
        "plaintext_hex": _hex(plaintext),
        "ciphertext_hex": _hex(ciphertext),
        "tag": tag.hex(),
        "envelope_b64": base64.b64encode(envelope).decode(),
        "roundtrip": back == plaintext,
        "sizes": {
            "plaintext": len(plaintext),
            "meta": demo.HEADER_BYTES - demo.SALT_BYTES - demo.NONCE_BYTES,
            "salt": demo.SALT_BYTES,
            "nonce": demo.NONCE_BYTES,
            "header": demo.HEADER_BYTES,
            "ciphertext": len(ciphertext),
            "tag": demo.TAG_BYTES,
            "total": len(envelope),
        },
    }


def api_decrypt(req):
    password = str(req.get("password", ""))
    raw = str(req.get("envelope", "")).strip()
    tamper = bool(req.get("tamper", False))

    if not raw:
        return {"ok": False, "error": "конверт пуст"}
    try:
        envelope = base64.b64decode(raw, validate=True)
    except Exception:
        return {"ok": False, "error": "конверт не является корректным base64"}
    if len(envelope) < demo.HEADER_BYTES + demo.TAG_BYTES:
        return {"ok": False, "error": "конверт короче заголовка с тегом"}

    if tamper:
        if len(envelope) <= demo.HEADER_BYTES + demo.TAG_BYTES:
            return {"ok": False,
                    "error": "в конверте нет шифротекста, нечего подделывать"}
        forged = bytearray(envelope)
        forged[demo.HEADER_BYTES] ^= 0x01
        envelope = bytes(forged)

    if envelope[0] != demo.VERSION:
        return {"ok": False,
                "error": f"версия конверта {envelope[0]} не поддерживается "
                         f"(ожидается {demo.VERSION})"}

    try:
        plaintext, salt, nonce, enc_key, _mac, _ct, tag = \
            demo.decrypt(password, envelope)
    except demo.AuthenticationError as exc:
        return {"ok": False, "error": str(exc)}

    t, m, p, _, _ = demo._unpack_header(envelope[:demo.HEADER_BYTES])
    return {
        "ok": True,
        "version": envelope[0],
        "params": {"t": t, "m": m, "p": p},
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "enc_key": enc_key.hex(),
        "plaintext_preview": _preview(plaintext),
        "plaintext_hex": _hex(plaintext),
        "size": len(plaintext),
    }


# --------------------------------------------------------------------------

def serve(port: int = 8765, open_browser: bool = True) -> int:
    """Поднимает сервер на 127.0.0.1:port. Возвращает код завершения."""
    Handler.port = port
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError as exc:
        print(f"ERROR: cannot bind 127.0.0.1:{port} -- {exc}", file=sys.stderr)
        print("       try another port: python demo.py --serve --port 8800",
              file=sys.stderr)
        return 1

    url = f"http://127.0.0.1:{port}/"
    engine, _ = demo.get_engine()
    print("=" * 66)
    print("Dedalyan demo web UI")
    print("=" * 66)
    print(f"  URL            : {url}")
    print(f"  cipher backend : {engine}")
    print(f"  bound to       : 127.0.0.1 only (not reachable from the network)")
    print(f"  request log    : disabled (passwords travel in request bodies)")
    print()
    print("  Press Ctrl+C to stop.")
    print("=" * 66)

    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Dedalyan demo web UI")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    sys.exit(serve(a.port, not a.no_browser))
