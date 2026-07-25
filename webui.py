"""Локальный веб-интерфейс к Dedalyan: GCM, файлы, демонстрация, обозреватель шифра.

Запускается из demo.py::

    python demo.py --serve
    python demo.py --serve --port 8800 --no-browser

Четыре режима:

* **Текст (GCM)** — сырой Dedalyan-GCM-96 с пользовательским AAD. Показывает
  подключ хеша H, nonce, тег и структуру конверта целиком: это режим, в
  котором видно, как работает схема.
* **Файлы** — кадрированный формат ``dedalyan_file``. Он нужен там, где
  сообщение не помещается в память: один тег на весь файл проверялся бы
  только после дочитывания до конца.
* **Демонстрация** — цепочка Argon2id → encrypt-then-MAC из ``demo.py``.
* **Шифр** — обозреватель: подключи, таблицы лабиринта, пораундовая
  трассировка одного блока (формат раздела 8.5 спецификации).

Сервер поднимается на стандартной библиотеке — никаких зависимостей сверх
уже нужных. Страница самодостаточна: ни одного внешнего запроса, весь CSS и
JS встроены. Это не украшательство, а требование: инструмент, который
показывает пароли и ключи, не должен ходить в чужие CDN.

Защита. Сервер слушает ТОЛЬКО 127.0.0.1, но этого мало: любая открытая в
браузере страница может отправить запрос на localhost. Поэтому дополнительно
проверяются три вещи.

* Заголовок Host обязан быть 127.0.0.1 или localhost с нашим портом. Это
  закрывает DNS rebinding, когда чужой домен резолвится в 127.0.0.1.
* Заголовок Origin, если он есть, обязан совпадать с нашим. Браузер шлёт
  Origin при кросс-сайтовых запросах, так что это отсекает CSRF.
* POST принимается только с Content-Type ``application/json`` либо
  ``application/octet-stream``. Ни тот, ни другой обычная HTML-форма
  выставить не может, а значит CSRF формой невозможен.

Пароли не пишутся в лог: журнал запросов отключён, тела не логируются.
"""

from __future__ import annotations

import base64
import io
import json
import os
import secrets
import struct
import sys
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dedalyan as D
import dedalyan_file as DF
import dedalyan_gcm as DG
import demo

#: Тела запросов держатся в памяти целиком, поэтому предел явный.
MAX_JSON_BODY = 8 * 1024 * 1024
MAX_FILE_BODY = 128 * 1024 * 1024
MAX_TEXT_BYTES = 1024 * 1024

# --- конверт текстового режима -------------------------------------------
# Формат уровня интерфейса, а не библиотеки: он нужен только чтобы уместить
# соль и nonce рядом с шифротекстом. Для файлов используется настоящий
# кадрированный формат из dedalyan_file.
TEXT_MAGIC = b"DEDGCM1"
TEXT_HDR = struct.Struct(">7sBBBI16s8s")      # magic, kdf, t, lanes, mem, salt, nonce
TEXT_HEADER_BYTES = TEXT_HDR.size             # 38
KDF_RAW, KDF_ARGON2ID = 0, 1


# --------------------------------------------------------------------------
# Страница
# --------------------------------------------------------------------------

PAGE = r"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dedalyan-96/256 — GCM, файлы, обозреватель</title>
<style>
:root {
  --bg:#0f1115; --panel:#171a21; --panel-2:#1d212a; --line:#2a2f3a;
  --fg:#e6e9ef; --fg-dim:#98a0b0; --accent:#6aa9ff; --ok:#4ec9a0;
  --bad:#ff6b6b; --warn:#e0b050;
  --s-hdr:#6aa9ff; --s-salt:#b98cff; --s-nonce:#4ec9a0; --s-ct:#5a6272; --s-tag:#e0b050;
  --radius:10px;
}
@media (prefers-color-scheme: light) {
  :root { --bg:#f4f6fa; --panel:#fff; --panel-2:#f0f2f7; --line:#dde1e9;
    --fg:#1a1d24; --fg-dim:#616a7d; --accent:#2563eb; --ok:#0f9d76;
    --bad:#d92d20; --warn:#b45309; --s-ct:#98a0b0; }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:15px/1.55 ui-sans-serif,system-ui,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:26px 20px 80px}
h1{font-size:22px;margin:0 0 6px;letter-spacing:-.01em}
.sub{color:var(--fg-dim);font-size:13.5px}
.badges{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.badge{font-size:12px;padding:3px 9px;border-radius:999px;
  border:1px solid var(--line);background:var(--panel);color:var(--fg-dim)}
.badge.warn{border-color:var(--warn);color:var(--warn)}
.badge.ok{border-color:var(--ok);color:var(--ok)}

.tabs{display:flex;gap:2px;margin:22px 0 0;border-bottom:1px solid var(--line);
  flex-wrap:wrap}
.tab{padding:9px 15px;cursor:pointer;border:none;background:none;
  color:var(--fg-dim);font:inherit;font-size:14px;
  border-bottom:2px solid transparent;margin-bottom:-1px}
.tab:hover{color:var(--fg)}
.tab.active{color:var(--fg);border-bottom-color:var(--accent)}

.panel{background:var(--panel);border:1px solid var(--line);
  border-radius:var(--radius);padding:18px;margin-top:18px}
label{display:block;font-size:13px;color:var(--fg-dim);margin:0 0 5px}
input[type=text],input[type=password],textarea,input[type=number],select{
  width:100%;background:var(--panel-2);color:var(--fg);border:1px solid var(--line);
  border-radius:7px;padding:9px 11px;font:inherit;outline:none}
input:focus,textarea:focus,select:focus{border-color:var(--accent)}
textarea{resize:vertical;min-height:88px;
  font-family:ui-monospace,Consolas,monospace;font-size:13px}
.row{display:flex;gap:12px;flex-wrap:wrap}
.row>*{flex:1;min-width:140px}
.field{margin-bottom:14px}
.pw-wrap{position:relative}
.pw-toggle{position:absolute;right:8px;top:50%;transform:translateY(-50%);
  background:none;border:none;color:var(--fg-dim);cursor:pointer;font-size:12px;padding:4px 6px}
button.go{background:var(--accent);color:#fff;border:none;border-radius:7px;
  padding:10px 20px;font:inherit;font-weight:500;cursor:pointer}
button.go:hover{filter:brightness(1.1)}
button.go:disabled{opacity:.55;cursor:default}
button.ghost{background:none;color:var(--fg-dim);border:1px solid var(--line);
  border-radius:7px;padding:9px 15px;font:inherit;cursor:pointer}
button.ghost:hover{color:var(--fg);border-color:var(--accent)}
.actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:4px}

.seg{display:inline-flex;border:1px solid var(--line);border-radius:7px;overflow:hidden;
  margin-bottom:14px}
.seg button{background:none;border:none;color:var(--fg-dim);font:inherit;font-size:13px;
  padding:7px 14px;cursor:pointer}
.seg button.on{background:var(--accent);color:#fff}

details.params{margin-bottom:14px}
details.params summary{cursor:pointer;color:var(--fg-dim);font-size:13px;padding:4px 0}

.stage{border:1px solid var(--line);border-radius:var(--radius);
  background:var(--panel);margin-top:14px;overflow:hidden}
.stage>h3{margin:0;padding:11px 16px;font-size:13.5px;font-weight:600;
  background:var(--panel-2);border-bottom:1px solid var(--line);
  display:flex;align-items:center;gap:9px}
.num{display:inline-flex;align-items:center;justify-content:center;width:21px;height:21px;
  border-radius:50%;background:var(--accent);color:#fff;font-size:11.5px;font-weight:700;flex:none}
.stage>.body{padding:14px 16px}
.note{color:var(--fg-dim);font-size:13px;margin:9px 0 0}

.kv{display:grid;grid-template-columns:max-content 1fr;gap:7px 14px;align-items:start}
.kv dt{color:var(--fg-dim);font-size:13px;white-space:nowrap}
.kv dd{margin:0;min-width:0}
.mono{font-family:ui-monospace,Consolas,"Cascadia Mono",monospace;
  font-size:12.5px;word-break:break-all;line-height:1.5}
.copy{background:none;color:var(--fg-dim);cursor:pointer;font-size:11px;
  padding:1px 5px;border-radius:4px;margin-left:6px;border:1px solid var(--line)}
.copy:hover{color:var(--accent);border-color:var(--accent)}
.scroll{max-height:190px;overflow:auto}

.keybox{background:var(--panel-2);border:1px solid var(--line);border-radius:7px;
  padding:10px 12px;margin:6px 0 0}
.keybox .lbl{font-size:11.5px;color:var(--fg-dim);margin-bottom:3px;letter-spacing:.04em}

.subkeys{display:grid;grid-template-columns:repeat(auto-fill,minmax(158px,1fr));gap:5px 12px}
.subkeys span{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:var(--fg-dim)}
.subkeys b{color:var(--fg);font-weight:500}

.segbar{display:flex;height:26px;border-radius:6px;overflow:hidden;margin:4px 0 9px}
.segbar div{display:flex;align-items:center;justify-content:center;font-size:10.5px;
  color:#0f1115;font-weight:600;min-width:2px}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--fg-dim)}
.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px}

.verdict{padding:13px 15px;border-radius:8px;font-size:14px;margin-top:4px}
.verdict.ok{background:color-mix(in srgb,var(--ok) 14%,transparent);border:1px solid var(--ok)}
.verdict.bad{background:color-mix(in srgb,var(--bad) 14%,transparent);border:1px solid var(--bad)}
.verdict b{display:block;margin-bottom:3px}

.spinner{display:none;width:15px;height:15px;border:2px solid var(--line);
  border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite}
.spinner.on{display:inline-block}
@keyframes spin{to{transform:rotate(360deg)}}

.drop{border:2px dashed var(--line);border-radius:var(--radius);padding:30px 20px;
  text-align:center;color:var(--fg-dim);cursor:pointer;transition:.15s;font-size:14px}
.drop:hover,.drop.over{border-color:var(--accent);color:var(--fg);
  background:color-mix(in srgb,var(--accent) 6%,transparent)}
.drop b{color:var(--fg);display:block;margin-bottom:4px;font-size:15px}

table.trace{width:100%;border-collapse:collapse;font-family:ui-monospace,Consolas,monospace;
  font-size:12px}
table.trace th,table.trace td{padding:4px 8px;text-align:left;
  border-bottom:1px solid var(--line);white-space:nowrap}
table.trace th{color:var(--fg-dim);font-weight:600;font-size:11.5px}
table.trace td:first-child{color:var(--fg-dim)}
.tblwrap{overflow-x:auto}

.tbl16{display:grid;grid-template-columns:repeat(16,1fr);gap:3px;
  font-family:ui-monospace,Consolas,monospace;font-size:11.5px;text-align:center}
.tbl16 span{padding:3px 0;background:var(--panel-2);border-radius:3px}
.tbl16 span.fix{background:color-mix(in srgb,var(--warn) 30%,transparent);color:var(--fg)}

footer{margin-top:34px;color:var(--fg-dim);font-size:12.5px;line-height:1.7}
footer code{background:var(--panel-2);padding:1px 5px;border-radius:4px}
.hidden{display:none}
</style>
</head>
<body>
<div class="wrap">

<header>
  <h1>Dedalyan-96/256</h1>
  <div class="sub">GCM-96, шифрование файлов и обозреватель шифра. Каждый шаг показан целиком.</div>
  <div class="badges" id="badges"></div>
</header>

<div class="tabs">
  <button class="tab active" data-tab="text">Текст (GCM)</button>
  <button class="tab" data-tab="file">Файлы</button>
  <button class="tab" data-tab="demo">Демонстрация</button>
  <button class="tab" data-tab="cipher">Шифр</button>
</div>

<!-- ============ общий блок ключа (клонируется в JS) ============ -->
<template id="keytpl">
  <div class="seg keymode">
    <button type="button" data-m="password" class="on">Пароль</button>
    <button type="button" data-m="raw">Готовый ключ</button>
  </div>
  <div class="field f-pw">
    <label>Пароль <span style="opacity:.7">— из него Argon2id выводит ключ</span></label>
    <div class="pw-wrap">
      <input type="password" class="i-pw" autocomplete="off" spellcheck="false">
      <button type="button" class="pw-toggle">показать</button>
    </div>
  </div>
  <div class="field f-raw hidden">
    <label>Ключ, 64 hex-символа (256 бит)</label>
    <div class="row">
      <input type="text" class="i-key mono" spellcheck="false" placeholder="00112233…">
      <button type="button" class="ghost b-gen" style="flex:0 0 auto">Сгенерировать</button>
    </div>
  </div>
  <details class="params f-argon">
    <summary>Параметры Argon2id</summary>
    <div class="row" style="margin-top:10px">
      <div><label>Проходы (t)</label><input type="number" class="i-t" value="3" min="1" max="255"></div>
      <div><label>Память, КиБ (m)</label><input type="number" class="i-m" value="65536" min="8"></div>
      <div><label>Потоки (p)</label><input type="number" class="i-p" value="4" min="1" max="255"></div>
    </div>
    <p class="note">По умолчанию — второй рекомендованный набор RFC 9106. Память
    важнее проходов: именно она лишает GPU преимущества.</p>
  </details>
</template>

<!-- ==================== ТЕКСТ (GCM) ==================== -->
<section id="tab-text">
  <div class="panel">
    <div id="k-text"></div>
    <div class="field">
      <label>Открытый текст</label>
      <textarea id="t-pt" spellcheck="false">Dedalyan-GCM-96. Шифр учебный, поле GF(2^96) проверено.</textarea>
    </div>
    <div class="field">
      <label>AAD — данные, которые аутентифицируются, но не шифруются</label>
      <input type="text" id="t-aad" spellcheck="false" placeholder="например, имя получателя или версия протокола">
    </div>
    <div class="actions">
      <button class="go" id="t-seal">Зашифровать</button>
      <div class="spinner" id="t-spin"></div>
      <span class="note" id="t-status"></span>
    </div>
  </div>

  <div class="panel">
    <div class="field">
      <label>Конверт для расшифровки (base64)</label>
      <textarea id="t-env" spellcheck="false" placeholder="вставьте конверт, или зашифруйте что-нибудь выше"></textarea>
    </div>
    <div class="field">
      <label>AAD при расшифровке — обязан совпадать в точности</label>
      <input type="text" id="t-aad2" spellcheck="false">
    </div>
    <div class="actions">
      <button class="go" id="t-open">Расшифровать</button>
      <button class="ghost" id="t-tamper">Подделать один бит</button>
      <div class="spinner" id="t-spin2"></div>
      <span class="note" id="t-status2"></span>
    </div>
  </div>
  <div id="t-out"></div>
</section>

<!-- ==================== ФАЙЛЫ ==================== -->
<section id="tab-file" class="hidden">
  <div class="panel">
    <div id="k-file"></div>
    <div class="field">
      <div class="drop" id="f-drop">
        <b>Перетащите файл или нажмите</b>
        Шифрование — любой файл; расшифровка — контейнер .ded
      </div>
      <input type="file" id="f-input" class="hidden">
    </div>
    <div id="f-info" class="hidden" style="margin-bottom:14px"></div>
    <details class="params">
      <summary>Размер кадра</summary>
      <div class="row" style="margin-top:10px">
        <div><label>Байт на кадр</label><input type="number" id="f-chunk" value="262144" min="1024" max="67108864" step="1024"></div>
      </div>
      <p class="note">Файл режется на кадры, каждый аутентифицируется отдельно. Один тег
      на весь файл потребовал бы держать файл в памяти либо отдавать расшифрованное
      до проверки.</p>
    </details>
    <div class="actions">
      <button class="go" id="f-seal">Зашифровать</button>
      <button class="go" id="f-open">Расшифровать</button>
      <div class="spinner" id="f-spin"></div>
      <span class="note" id="f-status"></span>
    </div>
  </div>
  <div id="f-out"></div>
</section>

<!-- ==================== ДЕМОНСТРАЦИЯ ==================== -->
<section id="tab-demo" class="hidden">
  <div class="panel">
    <p class="note" style="margin-top:0">Цепочка из <code>demo.py</code>: Argon2id →
    два независимых ключа → CTR → encrypt-then-MAC на HMAC-SHA256. Отличается от
    вкладки «Текст» тем, что аутентификация здесь внешняя (HMAC), а не встроенная в режим.</p>
    <div class="field">
      <label>Пароль</label>
      <div class="pw-wrap">
        <input type="password" id="d-pw" value="correct horse battery staple" autocomplete="off" spellcheck="false">
        <button class="pw-toggle" data-for="d-pw">показать</button>
      </div>
    </div>
    <div class="field">
      <label>Открытый текст</label>
      <textarea id="d-text" spellcheck="false">Dedalyan-96/256 demo. Шифр учебный, Argon2 настоящий.</textarea>
    </div>
    <div class="actions">
      <button class="go" id="d-go">Прогнать цепочку</button>
      <div class="spinner" id="d-spin"></div>
      <span class="note" id="d-status"></span>
    </div>
  </div>
  <div id="d-out"></div>
</section>

<!-- ==================== ШИФР ==================== -->
<section id="tab-cipher" class="hidden">
  <div class="panel">
    <p class="note" style="margin-top:0">Обозреватель самого шифра: расписание ключей,
    таблицы лабиринта и пораундовая трассировка одного 96-битного блока —
    в формате раздела 8.5 спецификации.</p>
    <div class="field">
      <label>Ключ, 64 hex-символа</label>
      <div class="row">
        <input type="text" id="c-key" class="mono" spellcheck="false"
               value="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f">
        <button class="ghost" id="c-gen" style="flex:0 0 auto">Сгенерировать</button>
      </div>
    </div>
    <div class="row">
      <div class="field">
        <label>Блок, 24 hex-символа (96 бит)</label>
        <input type="text" id="c-pt" class="mono" spellcheck="false" value="0123456789abcdef01234567">
      </div>
      <div class="field" style="flex:0 0 130px">
        <label>Раундов</label>
        <input type="number" id="c-rounds" value="16" min="1" max="16">
      </div>
    </div>
    <div class="actions">
      <button class="go" id="c-go">Показать</button>
      <div class="spinner" id="c-spin"></div>
      <span class="note" id="c-status"></span>
    </div>
  </div>
  <div id="c-out"></div>
</section>

<footer>
  <b>Шифр Dedalyan не проверялся независимыми криптоаналитиками, а GCM-96 —
  адаптация, а не стандарт NIST.</b> Argon2id и HMAC-SHA256 здесь настоящие.
  Для реальных данных нужен AES-GCM или ChaCha20-Poly1305 из проверенной библиотеки.<br>
  Сервер слушает только <code>127.0.0.1</code>; страница не делает ни одного внешнего
  запроса. Пароли нигде не сохраняются и не пишутся в журнал.
</footer>

</div>
<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const b64e=s=>btoa(String.fromCharCode(...new TextEncoder().encode(s)));

$$('.tab').forEach(t=>t.onclick=()=>{
  $$('.tab').forEach(x=>x.classList.remove('active')); t.classList.add('active');
  ['text','file','demo','cipher'].forEach(n=>
    $('#tab-'+n).classList.toggle('hidden', t.dataset.tab!==n));
});
document.addEventListener('click',e=>{
  const b=e.target.closest('.pw-toggle'); if(!b) return;
  const el = b.dataset.for ? $('#'+b.dataset.for) : b.previousElementSibling;
  const show = el.type==='password'; el.type = show?'text':'password';
  b.textContent = show?'скрыть':'показать';
});

// ---- блок выбора ключа ----
function mountKey(host){
  host.appendChild($('#keytpl').content.cloneNode(true));
  const seg=host.querySelector('.keymode');
  seg.querySelectorAll('button').forEach(b=>b.onclick=()=>{
    seg.querySelectorAll('button').forEach(x=>x.classList.remove('on'));
    b.classList.add('on');
    const raw=b.dataset.m==='raw';
    host.querySelector('.f-pw').classList.toggle('hidden',raw);
    host.querySelector('.f-raw').classList.toggle('hidden',!raw);
    host.querySelector('.f-argon').classList.toggle('hidden',raw);
  });
  host.querySelector('.b-gen').onclick=()=>{
    const a=new Uint8Array(32); crypto.getRandomValues(a);
    host.querySelector('.i-key').value=hex(a.buffer);
  };
}
function keyParams(host){
  const raw = host.querySelector('.keymode button.on').dataset.m==='raw';
  return raw
    ? {keyMode:'raw', keyHex:host.querySelector('.i-key').value.trim()}
    : {keyMode:'password', password:host.querySelector('.i-pw').value,
       t:+host.querySelector('.i-t').value, m:+host.querySelector('.i-m').value,
       p:+host.querySelector('.i-p').value};
}
mountKey($('#k-text')); mountKey($('#k-file'));

async function api(path,body){
  const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body)});
  return await r.json();
}
function busy(btns,spin,status,on,msg){
  btns.forEach(b=>b.disabled=on); spin.classList.toggle('on',on);
  status.textContent = on?(msg||'считаем…'):'';
}
function copyBtn(t){return `<button class="copy" onclick="navigator.clipboard.writeText('${esc(t)}');this.textContent='ok';setTimeout(()=>this.textContent='copy',900)">copy</button>`;}
function stage(n,title,inner){return `<div class="stage"><h3><span class="num">${n}</span>${esc(title)}</h3><div class="body">${inner}</div></div>`;}
function errBox(m){return `<div class="panel"><div class="verdict bad"><b>Ошибка</b>${esc(m)}</div></div>`;}
function segbar(parts){
  const tot=parts.reduce((a,s)=>a+s.n,0);
  return `<div class="segbar">${parts.map(s=>`<div style="width:${(100*s.n/tot).toFixed(3)}%;background:${s.c}" title="${esc(s.name)}: ${s.n} B">${s.n>=tot*.07?s.n:''}</div>`).join('')}</div>`+
    `<div class="legend">${parts.map(s=>`<span><i style="background:${s.c}"></i>${esc(s.name)} — ${s.n} B</span>`).join('')}</div>`;
}

// ==================== ТЕКСТ ====================
$('#t-seal').onclick=async()=>{
  const btn=[$('#t-seal')],sp=$('#t-spin'),st=$('#t-status');
  busy(btn,sp,st,true,'Argon2id считает…'); $('#t-out').innerHTML='';
  try{
    const r=await api('/api/gcm/seal',{...keyParams($('#k-text')),
      text:$('#t-pt').value, aad:$('#t-aad').value});
    if(!r.ok){$('#t-out').innerHTML=errBox(r.error);return;}
    renderSeal(r); $('#t-env').value=r.envelope_b64; $('#t-aad2').value=$('#t-aad').value;
  }catch(e){st.textContent='сбой: '+e;}
  finally{busy(btn,sp,st,false);}
};
function renderSeal(r){
  let h=stage(1,'Ключ и подключ хеша',`<dl class="kv">
    <dt>режим ключа</dt><dd>${esc(r.key_mode)}</dd>
    ${r.salt?`<dt>соль Argon2id</dt><dd class="mono">${esc(r.salt)}</dd>
    <dt>параметры</dt><dd class="mono">t=${r.params.t}, m=${r.params.m} КиБ, p=${r.params.p}</dd>
    <dt>время KDF</dt><dd>${r.ms} мс</dd>`:''}
    </dl>
    <div class="keybox"><div class="lbl">КЛЮЧ ШИФРА (256 бит)</div>
      <div class="mono">${esc(r.key)}${copyBtn(r.key)}</div></div>
    <div class="keybox"><div class="lbl">H = E_K(0) — ПОДКЛЮЧ ХЕША GHASH</div>
      <div class="mono">${esc(r.h)}</div></div>
    <p class="note">H — это шифрование нулевого блока. На нём строится GHASH:
    универсальный хеш в GF(2^96) по многочлену x^96 + x^10 + x^9 + x^6 + 1.</p>`);

  h+=stage(2,'Шифрование GCM',`<dl class="kv">
    <dt>nonce</dt><dd class="mono">${esc(r.nonce)}</dd>
    <dt>AAD</dt><dd class="mono">${r.aad_len?esc(r.aad_hex):'<span style="opacity:.6">пусто</span>'} (${r.aad_len} B)</dd>
    <dt>шифротекст</dt><dd class="mono scroll">${esc(r.ciphertext_hex)}${copyBtn(r.ciphertext_hex)}</dd>
    <dt>тег</dt><dd class="mono">${esc(r.tag)}${copyBtn(r.tag)}</dd></dl>
    <p class="note">Тег покрывает и AAD, и шифротекст, и их длины. AAD аутентифицируется,
    но не шифруется — туда кладут то, что должно быть видно, но не подменяемо.</p>`);

  h+=stage(3,'Конверт',segbar([
      {name:'magic+параметры',n:r.sizes.meta,c:'var(--s-hdr)'},
      {name:'соль',n:r.sizes.salt,c:'var(--s-salt)'},
      {name:'nonce',n:r.sizes.nonce,c:'var(--s-nonce)'},
      {name:'шифротекст',n:r.sizes.ciphertext,c:'var(--s-ct)'},
      {name:'тег',n:r.sizes.tag,c:'var(--s-tag)'}])+
    `<div style="margin-top:12px"><label>base64 ${copyBtn(r.envelope_b64)}</label>
     <div class="mono scroll">${esc(r.envelope_b64)}</div></div>
     <p class="note">Всего ${r.sizes.total} байт на ${r.sizes.plaintext} байт открытого текста.</p>`);

  h+=stage(4,'Самопроверка',r.roundtrip
    ?`<div class="verdict ok"><b>OK</b>Сервер расшифровал собственный вывод и сверил байт в байт.</div>`
    :`<div class="verdict bad"><b>СБОЙ</b>Расшифровка не совпала.</div>`);
  $('#t-out').innerHTML=h;
}

async function textOpen(tamper){
  const btns=[$('#t-open'),$('#t-tamper')],sp=$('#t-spin2'),st=$('#t-status2');
  busy(btns,sp,st,true,'считаем…'); $('#t-out').innerHTML='';
  try{
    const r=await api('/api/gcm/open',{...keyParams($('#k-text')),
      envelope:$('#t-env').value.trim(), aad:$('#t-aad2').value, tamper:!!tamper});
    if(!r.ok){
      $('#t-out').innerHTML=stage(1,tamper?'Подделанный конверт отвергнут':'Конверт отвергнут',
        `<div class="verdict bad"><b>REJECTED</b>${esc(r.error)}</div>
         <p class="note">${tamper
           ?'Перевёрнут один бит шифротекста. Тег проверяется до расшифровки, поэтому ничего не расшифровывалось.'
           :'Причина — неверный ключ/пароль, несовпадающий AAD либо изменённый конверт. Отличить их нельзя, и это правильно: иначе схема подсказывала бы атакующему.'}</p>`);
      return;
    }
    $('#t-out').innerHTML=stage(1,'Заголовок конверта',`<dl class="kv">
        <dt>режим ключа</dt><dd>${esc(r.key_mode)}</dd>
        ${r.salt?`<dt>соль</dt><dd class="mono">${esc(r.salt)}</dd>`:''}
        <dt>nonce</dt><dd class="mono">${esc(r.nonce)}</dd>
        <dt>тег</dt><dd class="mono">${esc(r.tag)}</dd></dl>`)
      +stage(2,'Тег проверен',`<div class="verdict ok"><b>VERIFIED</b>
        Сравнение за постоянное время: обычное сравнение выходило бы на первом
        несовпавшем байте и выдавало бы по времени, сколько байт угадано.</div>`)
      +stage(3,'Открытый текст',`<dl class="kv">
        <dt>текст</dt><dd>${esc(r.plaintext_preview)}</dd>
        <dt>размер</dt><dd>${r.size} байт</dd>
        <dt>hex</dt><dd class="mono scroll">${esc(r.plaintext_hex)}</dd></dl>`);
  }catch(e){st.textContent='сбой: '+e;}
  finally{busy(btns,sp,st,false);}
}
$('#t-open').onclick=()=>textOpen(false);
$('#t-tamper').onclick=()=>textOpen(true);

// ==================== ФАЙЛЫ ====================
let chosen=null;
const drop=$('#f-drop'), finput=$('#f-input');
drop.onclick=()=>finput.click();
drop.ondragover=e=>{e.preventDefault();drop.classList.add('over');};
drop.ondragleave=()=>drop.classList.remove('over');
drop.ondrop=e=>{e.preventDefault();drop.classList.remove('over');
  if(e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);};
finput.onchange=()=>{if(finput.files.length) setFile(finput.files[0]);};
function setFile(f){
  chosen=f;
  const looksSealed=f.name.endsWith('.ded');
  $('#f-info').classList.remove('hidden');
  $('#f-info').innerHTML=`<div class="keybox"><div class="lbl">ВЫБРАН ФАЙЛ</div>
    <div>${esc(f.name)} — ${f.size.toLocaleString('ru')} байт${
      looksSealed?' <span style="color:var(--accent)">(похоже на контейнер .ded)</span>':''}</div></div>`;
}

async function fileOp(op){
  if(!chosen){$('#f-out').innerHTML=errBox('Файл не выбран');return;}
  const btns=[$('#f-seal'),$('#f-open')],sp=$('#f-spin'),st=$('#f-status');
  busy(btns,sp,st,true, chosen.size>4e6?'обрабатываем файл…':'Argon2id считает…');
  $('#f-out').innerHTML='';
  const t0=performance.now();
  try{
    const kp=keyParams($('#k-file'));
    const hdrs={'Content-Type':'application/octet-stream'};
    if(kp.keyMode==='raw'){hdrs['X-Ded-Key']=kp.keyHex;}
    else{hdrs['X-Ded-Password']=b64e(kp.password);
         hdrs['X-Ded-Argon']=`${kp.t},${kp.m},${kp.p}`;}
    if(op==='seal') hdrs['X-Ded-Chunk']=String(+$('#f-chunk').value);

    const buf=await chosen.arrayBuffer();
    const resp=await fetch('/api/file/'+op,{method:'POST',headers:hdrs,body:buf});
    const ct=resp.headers.get('content-type')||'';
    if(ct.includes('application/json')){
      const j=await resp.json();
      $('#f-out').innerHTML=stage(1,op==='seal'?'Не удалось зашифровать':'Контейнер отвергнут',
        `<div class="verdict bad"><b>${op==='seal'?'Ошибка':'REJECTED'}</b>${esc(j.error)}</div>`+
        (op==='open'?`<p class="note">Кадр отдаётся только после проверки его тега, поэтому
         частично расшифрованного файла не остаётся. Причина — неверный ключ, изменённый
         контейнер либо усечение.</p>`:''));
      return;
    }
    const blob=await resp.blob();
    const ms=Math.round(performance.now()-t0);
    const name = op==='seal' ? chosen.name+'.ded'
               : (chosen.name.endsWith('.ded')?chosen.name.slice(0,-4):chosen.name+'.out');
    const url=URL.createObjectURL(blob);
    const speed=(chosen.size/1048576)/(ms/1000);
    const frames=resp.headers.get('X-Ded-Frames')||'?';
    $('#f-out').innerHTML=stage(1,op==='seal'?'Файл зашифрован':'Файл расшифрован и проверен',
      `<dl class="kv">
        <dt>вход</dt><dd>${esc(chosen.name)} — ${chosen.size.toLocaleString('ru')} байт</dd>
        <dt>выход</dt><dd>${esc(name)} — ${blob.size.toLocaleString('ru')} байт</dd>
        <dt>кадров</dt><dd>${esc(frames)}</dd>
        <dt>накладные</dt><dd>${op==='seal'?(blob.size-chosen.size)+' байт ('+
          (100*(blob.size-chosen.size)/Math.max(chosen.size,1)).toFixed(4)+'%)':'—'}</dd>
        <dt>время</dt><dd>${ms} мс${chosen.size>1e6?` (${speed.toFixed(1)} МиБ/с)`:''}</dd>
       </dl>
       <div class="actions"><a class="go" style="text-decoration:none" download="${esc(name)}" href="${url}">Скачать ${esc(name)}</a></div>
       ${op==='open'?`<p class="note">Все кадры прошли проверку тега. Перестановка,
         усечение и склейка кадров из другого файла были бы отвергнуты: индекс кадра,
         флаг последнего и заголовок входят в аутентифицируемые данные.</p>`:
        `<p class="note">Имя файла в контейнере не сохраняется — это метаданные,
         и их утечка была бы лишней. При расшифровке имя восстанавливается отбрасыванием
         расширения .ded.</p>`}`);
  }catch(e){st.textContent='сбой: '+e; $('#f-out').innerHTML=errBox(String(e));}
  finally{busy(btns,sp,st,false);}
}
$('#f-seal').onclick=()=>fileOp('seal');
$('#f-open').onclick=()=>fileOp('open');

// ==================== ДЕМОНСТРАЦИЯ ====================
$('#d-go').onclick=async()=>{
  const btn=[$('#d-go')],sp=$('#d-spin'),st=$('#d-status');
  busy(btn,sp,st,true,'Argon2id считает…'); $('#d-out').innerHTML='';
  try{
    const r=await api('/api/demo/run',{password:$('#d-pw').value,text:$('#d-text').value});
    if(!r.ok){$('#d-out').innerHTML=errBox(r.error);return;}
    let h=stage(1,'Argon2id → два независимых ключа',`<dl class="kv">
      <dt>соль</dt><dd class="mono">${esc(r.salt)}</dd>
      <dt>время</dt><dd>${r.ms} мс</dd></dl>
      <div class="keybox"><div class="lbl">КЛЮЧ ШИФРА</div><div class="mono">${esc(r.enc_key)}</div></div>
      <div class="keybox"><div class="lbl">КЛЮЧ MAC</div><div class="mono">${esc(r.mac_key)}</div></div>
      <p class="note">Argon2 выдаёт 64 байта одним вызовом, они режутся пополам. Один
      ключ нельзя отдавать двум примитивам: их взаимодействие не анализировалось.</p>`);
    h+=stage(2,'Подключи Dedalyan',`<div class="subkeys">`+
      r.subkeys.map((k,i)=>`<span>k[<b>${String(i).padStart(2,' ')}</b>] = <b>${k}</b></span>`).join('')+`</div>`);
    h+=stage(3,'CTR + encrypt-then-MAC',`<dl class="kv">
      <dt>nonce</dt><dd class="mono">${esc(r.nonce)}</dd>
      <dt>шифротекст</dt><dd class="mono scroll">${esc(r.ciphertext_hex)}</dd>
      <dt>тег HMAC</dt><dd class="mono">${esc(r.tag)}</dd></dl>
      <div style="margin-top:12px"><label>конверт base64 ${copyBtn(r.envelope_b64)}</label>
      <div class="mono scroll">${esc(r.envelope_b64)}</div></div>`);
    h+=stage(4,'Проверки',`
      <div class="verdict ${r.roundtrip?'ok':'bad'}"><b>${r.roundtrip?'OK':'СБОЙ'}</b>
        Круговой проход: расшифровка совпала с исходным текстом.</div>
      <div class="verdict ${r.wrong_pw_rejected?'ok':'bad'}" style="margin-top:8px">
        <b>${r.wrong_pw_rejected?'OK':'СБОЙ'}</b>Неверный пароль отвергнут тегом.</div>
      <div class="verdict ${r.tamper_rejected?'ok':'bad'}" style="margin-top:8px">
        <b>${r.tamper_rejected?'OK':'СБОЙ'}</b>Переворот одного бита шифротекста отвергнут.</div>`);
    $('#d-out').innerHTML=h;
  }catch(e){st.textContent='сбой: '+e;}
  finally{busy(btn,sp,st,false);}
};

// ==================== ШИФР ====================
$('#c-gen').onclick=()=>{const a=new Uint8Array(32);crypto.getRandomValues(a);$('#c-key').value=hex(a.buffer);};
$('#c-go').onclick=async()=>{
  const btn=[$('#c-go')],sp=$('#c-spin'),st=$('#c-status');
  busy(btn,sp,st,true,'считаем…'); $('#c-out').innerHTML='';
  try{
    const r=await api('/api/cipher/trace',{keyHex:$('#c-key').value.trim(),
      plaintext:$('#c-pt').value.trim(), rounds:+$('#c-rounds').value});
    if(!r.ok){$('#c-out').innerHTML=errBox(r.error);return;}
    const t16=(t,name)=>`<div style="margin-bottom:10px"><div class="lbl" style="font-size:11.5px;color:var(--fg-dim);margin-bottom:4px">${name}</div>
      <div class="tbl16">${t.map((v,i)=>`<span class="${v===i?'fix':''}" title="${i} → ${v}">${v.toString(16)}</span>`).join('')}</div></div>`;
    let h=stage(1,'Расписание ключей',`<div class="subkeys">`+
      r.subkeys.map((k,i)=>`<span>k[<b>${String(i).padStart(2,' ')}</b>] = <b>${k}</b></span>`).join('')+
      `</div><p class="note">16 подключей по 48 бит. Прогрев из 4 шагов не выдаёт подключей,
      но без него лавина для k[0] падает до 17% вместо 50%.</p>`);
    h+=stage(2,'Лабиринт',t16(r.T0,'T0')+t16(r.T1,'T1')+
      `<p class="note">Две перестановки 16 элементов из K_L. Подсвечены неподвижные точки:
      ${r.fixpoints} из 32 (в среднем по всем ключам 1.68). Ветвь выбирается по данным:
      для ниббла j селектор берётся из ниббла (j+6) mod 12.</p>`);
    h+=stage(3,`Пораундовая трассировка (${r.trace.length} раундов)`,
      `<div class="tblwrap"><table class="trace"><thead><tr><th>раунд</th><th>F</th><th>L</th><th>R</th></tr></thead>
       <tbody><tr><td>вход</td><td>—</td><td>${esc(r.in_l)}</td><td>${esc(r.in_r)}</td></tr>`+
      r.trace.map((t,i)=>`<tr><td>${i}</td><td>${esc(t[0])}</td><td>${esc(t[1])}</td><td>${esc(t[2])}</td></tr>`).join('')+
      `</tbody></table></div>
       <dl class="kv" style="margin-top:12px"><dt>шифротекст</dt>
       <dd class="mono">${esc(r.ciphertext)}${copyBtn(r.ciphertext)}</dd>
       <dt>обратимость</dt><dd>${r.roundtrip?'расшифровка вернула исходный блок':'<span style="color:var(--bad)">СБОЙ</span>'}</dd></dl>`);
    $('#c-out').innerHTML=h;
  }catch(e){st.textContent='сбой: '+e;}
  finally{busy(btn,sp,st,false);}
};

// ---- шапка ----
fetch('/api/info').then(r=>r.json()).then(i=>{
  $('#badges').innerHTML=
    `<span class="badge ok">бэкенд: ${esc(i.backend)}</span>`+
    `<span class="badge">${esc(i.crosscheck)}</span>`+
    `<span class="badge">GCM-96 · GF(2^96)</span>`+
    `<span class="badge">кадр ${(i.default_chunk/1024)|0} КиБ</span>`+
    `<span class="badge warn">учебный шифр — не для реальных данных</span>`;
});
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------
# Вспомогательное
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


def _argon2(password: str, salt: bytes, t: int, m: int, p: int) -> bytes:
    from argon2.low_level import Type, hash_secret_raw
    return hash_secret_raw(secret=password.encode("utf-8"), salt=salt,
                           time_cost=t, memory_cost=m, parallelism=p,
                           hash_len=D.KEY_BYTES, type=Type.ID)


def _check_argon_params(t: int, m: int, p: int) -> None:
    if not (1 <= t <= 255 and 1 <= p <= 255):
        raise ValueError("t и p должны укладываться в один байт")
    if not (8 <= m <= 2 * 1024 * 1024):
        raise ValueError("память Argon2 ограничена диапазоном 8 КиБ … 2 ГиБ")


def _key_from_request(req) -> tuple:
    """-> (key, kdf, salt, params). Общая логика для текстовых запросов."""
    mode = req.get("keyMode", "password")
    if mode == "raw":
        h = str(req.get("keyHex", "")).strip().replace(" ", "")
        try:
            key = bytes.fromhex(h)
        except ValueError:
            raise ValueError("ключ не является корректным hex")
        if len(key) != D.KEY_BYTES:
            raise ValueError(f"ключ должен быть {D.KEY_BYTES * 2} hex-символов, "
                             f"получено {len(h)}")
        return key, KDF_RAW, bytes(16), (0, 0, 0)

    password = str(req.get("password", ""))
    if not password:
        raise ValueError("пароль пуст")
    t = int(req.get("t", DF.ARGON2_TIME))
    m = int(req.get("m", DF.ARGON2_MEMORY_KIB))
    p = int(req.get("p", DF.ARGON2_LANES))
    _check_argon_params(t, m, p)
    salt = os.urandom(16)
    return _argon2(password, salt, t, m, p), KDF_ARGON2ID, salt, (t, m, p)


# --------------------------------------------------------------------------
# Обработчики API
# --------------------------------------------------------------------------

def api_gcm_seal(req):
    text = str(req.get("text", ""))
    aad = str(req.get("aad", "")).encode("utf-8")
    pt = text.encode("utf-8")
    if len(pt) > MAX_TEXT_BYTES:
        return {"ok": False,
                "error": f"текст длиннее {MAX_TEXT_BYTES} байт — используйте вкладку «Файлы»"}

    t0 = time.perf_counter()
    key, kdf, salt, (t, m, p) = _key_from_request(req)
    ms = int((time.perf_counter() - t0) * 1000)

    nonce = os.urandom(DG.NONCE_BYTES)
    ctx = DG.GcmContext(key)
    sealed = ctx.seal(nonce, pt, aad)
    header = TEXT_HDR.pack(TEXT_MAGIC, kdf, t, p, m, salt, nonce)
    envelope = header + sealed

    # Сервер расшифровывает собственный вывод: показывать «зашифровано» без
    # проверки -- значит показывать необоснованное.
    roundtrip = ctx.open_(nonce, sealed, aad) == pt

    return {
        "ok": True, "ms": ms,
        "key_mode": "готовый ключ" if kdf == KDF_RAW else "пароль → Argon2id",
        "key": key.hex(),
        "h": f"{ctx.h:024x}",
        "salt": salt.hex() if kdf == KDF_ARGON2ID else None,
        "params": {"t": t, "m": m, "p": p},
        "nonce": nonce.hex(),
        "aad_hex": _hex(aad), "aad_len": len(aad),
        "ciphertext_hex": _hex(sealed[:-DG.TAG_BYTES]),
        "tag": sealed[-DG.TAG_BYTES:].hex(),
        "envelope_b64": base64.b64encode(envelope).decode(),
        "roundtrip": roundtrip,
        "sizes": {
            "plaintext": len(pt),
            "meta": TEXT_HEADER_BYTES - 16 - DG.NONCE_BYTES,
            "salt": 16, "nonce": DG.NONCE_BYTES,
            "ciphertext": len(sealed) - DG.TAG_BYTES,
            "tag": DG.TAG_BYTES, "total": len(envelope),
        },
    }


def api_gcm_open(req):
    raw = str(req.get("envelope", "")).strip()
    aad = str(req.get("aad", "")).encode("utf-8")
    if not raw:
        return {"ok": False, "error": "конверт пуст"}
    try:
        envelope = base64.b64decode(raw, validate=True)
    except Exception:
        return {"ok": False, "error": "конверт не является корректным base64"}
    if len(envelope) < TEXT_HEADER_BYTES + DG.TAG_BYTES:
        return {"ok": False, "error": "конверт короче заголовка с тегом"}

    magic, kdf, t, p, m, salt, nonce = TEXT_HDR.unpack(
        envelope[:TEXT_HEADER_BYTES])
    if magic != TEXT_MAGIC:
        return {"ok": False,
                "error": "это не конверт текстового режима; для файлов "
                         "используйте вкладку «Файлы»"}
    body = envelope[TEXT_HEADER_BYTES:]

    if req.get("tamper"):
        if len(body) <= DG.TAG_BYTES:
            return {"ok": False, "error": "нечего подделывать: шифротекст пуст"}
        b = bytearray(body)
        b[0] ^= 0x01
        body = bytes(b)

    if kdf == KDF_ARGON2ID:
        password = str(req.get("password", ""))
        if not password:
            return {"ok": False,
                    "error": "конверт защищён паролем — переключитесь в режим «Пароль»"}
        try:
            _check_argon_params(t, m, p)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        key = _argon2(password, salt, t, m, p)
    else:
        try:
            key, _, _, _ = _key_from_request({**req, "keyMode": "raw"})
        except ValueError as exc:
            return {"ok": False,
                    "error": f"конверт на готовом ключе: {exc}"}

    ctx = DG.GcmContext(key)
    try:
        pt = ctx.open_(nonce, body, aad)
    except DG.AuthenticationError as exc:
        return {"ok": False, "error": str(exc)}

    return {
        "ok": True,
        "key_mode": "готовый ключ" if kdf == KDF_RAW else "пароль → Argon2id",
        "salt": salt.hex() if kdf == KDF_ARGON2ID else None,
        "nonce": nonce.hex(),
        "tag": body[-DG.TAG_BYTES:].hex(),
        "plaintext_preview": _preview(pt),
        "plaintext_hex": _hex(pt),
        "size": len(pt),
    }


def api_demo_run(req):
    password = str(req.get("password", ""))
    text = str(req.get("text", ""))
    if not password:
        return {"ok": False, "error": "пароль пуст"}
    pt = text.encode("utf-8")
    if len(pt) > MAX_TEXT_BYTES:
        return {"ok": False, "error": "текст слишком длинный"}

    t0 = time.perf_counter()
    envelope, salt, nonce, enc_key, mac_key, ct, tag = demo.encrypt(
        password, pt, demo.ARGON2_TIME, demo.ARGON2_MEMORY_KIB,
        demo.ARGON2_LANES)
    ms = int((time.perf_counter() - t0) * 1000)

    roundtrip = demo.decrypt(password, envelope)[0] == pt

    def rejected(pw, env):
        try:
            demo.decrypt(pw, env)
            return False
        except demo.AuthenticationError:
            return True

    forged = bytearray(envelope)
    forged[demo.HEADER_BYTES] ^= 0x01

    return {
        "ok": True, "ms": ms,
        "salt": salt.hex(), "nonce": nonce.hex(),
        "enc_key": enc_key.hex(), "mac_key": mac_key.hex(),
        "subkeys": [f"{k:012x}"
                    for k in D.key_schedule(D.key_from_bytes(enc_key))],
        "ciphertext_hex": _hex(ct), "tag": tag.hex(),
        "envelope_b64": base64.b64encode(envelope).decode(),
        "roundtrip": roundtrip,
        "wrong_pw_rejected": rejected(password + "!", envelope),
        "tamper_rejected": rejected(password, bytes(forged)),
    }


def api_cipher_trace(req):
    h = str(req.get("keyHex", "")).strip().replace(" ", "")
    try:
        key = bytes.fromhex(h)
    except ValueError:
        return {"ok": False, "error": "ключ не является корректным hex"}
    if len(key) != D.KEY_BYTES:
        return {"ok": False,
                "error": f"ключ должен быть {D.KEY_BYTES * 2} hex-символов"}

    ph = str(req.get("plaintext", "")).strip().replace(" ", "")
    try:
        block = int(ph, 16)
    except ValueError:
        return {"ok": False, "error": "блок не является корректным hex"}
    if len(ph) > 24 or block >> 96:
        return {"ok": False, "error": "блок должен быть не длиннее 24 hex-символов"}

    rounds = int(req.get("rounds", D.N))
    if not 1 <= rounds <= D.N:
        return {"ok": False, "error": f"раундов должно быть 1..{D.N}"}

    ki = D.key_from_bytes(key)
    kl = D.split_key(ki)[0]
    T0, T1 = D.build_labyrinth(kl)
    trace = D.encrypt_block_trace(block, ki, rounds)
    ct = D.encrypt_block(block, ki, rounds)

    return {
        "ok": True,
        "subkeys": [f"{k:012x}" for k in D.key_schedule(ki)],
        "T0": list(T0), "T1": list(T1),
        "fixpoints": sum(1 for t in (T0, T1) for i, v in enumerate(t) if v == i),
        "in_l": f"{(block >> 48) & D.M:012x}", "in_r": f"{block & D.M:012x}",
        "trace": [[f"{f:012x}", f"{l:012x}", f"{r:012x}"] for f, l, r in trace],
        "ciphertext": f"{ct:024x}",
        "roundtrip": D.decrypt_block(ct, ki, rounds) == block,
    }


# --------------------------------------------------------------------------
# Сервер
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "DedalyanUI/2"
    port = 0

    # -- защита ------------------------------------------------------------

    def _origin_ok(self) -> bool:
        allowed = {f"127.0.0.1:{self.port}", f"localhost:{self.port}",
                   f"[::1]:{self.port}"}
        if (self.headers.get("Host") or "").strip() not in allowed:
            return False
        origin = self.headers.get("Origin")
        if origin is not None:
            ok = {f"http://127.0.0.1:{self.port}",
                  f"http://localhost:{self.port}", f"http://[::1]:{self.port}"}
            if origin not in ok:
                return False
        return True

    def log_message(self, fmt, *a):
        """Журнал отключён: в запросах ходят пароли."""
        return

    def _send(self, code, body: bytes, ctype: str, extra=None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        # blob: разрешён только для connect-src: результат шифрования
        # отдаётся пользователю как Blob, созданный самой страницей, и без
        # этого его нельзя ни скачать программно, ни проверить.
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; "
                         "connect-src 'self' blob:; img-src blob:; "
                         "form-action 'none'; base-uri 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionAbortedError):
            pass

    def _json(self, code, obj) -> None:
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
                "default_chunk": DF.DEFAULT_CHUNK,
            })
        else:
            self._send(404, b"not found", "text/plain; charset=utf-8")

    def _read_body(self, limit: int):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None, "bad Content-Length"
        if length <= 0:
            return None, "empty body"
        if length > limit:
            return None, f"body exceeds {limit} bytes"
        data = bytearray()
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 1 << 20))
            if not chunk:
                return None, "connection closed early"
            data += chunk
            remaining -= len(chunk)
        return bytes(data), None

    def do_POST(self):
        if not self._origin_ok():
            self._json(403, {"ok": False, "error": "forbidden origin"})
            return
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()

        if self.path.startswith("/api/file/"):
            if ctype != "application/octet-stream":
                self._json(415, {"ok": False,
                                 "error": "expected application/octet-stream"})
                return
            self._handle_file()
            return

        if ctype != "application/json":
            self._json(415, {"ok": False, "error": "expected application/json"})
            return
        body, err = self._read_body(MAX_JSON_BODY)
        if err:
            self._json(413, {"ok": False, "error": err})
            return
        try:
            req = json.loads(body.decode("utf-8"))
        except Exception:
            self._json(400, {"ok": False, "error": "malformed JSON"})
            return

        routes = {
            "/api/gcm/seal": api_gcm_seal,
            "/api/gcm/open": api_gcm_open,
            "/api/demo/run": api_demo_run,
            "/api/cipher/trace": api_cipher_trace,
        }
        fn = routes.get(self.path)
        if fn is None:
            self._json(404, {"ok": False, "error": "unknown endpoint"})
            return
        try:
            self._json(200, fn(req))
        except ValueError as exc:
            self._json(200, {"ok": False, "error": str(exc)})
        except Exception as exc:                 # наружу -- без трассировки
            self._json(200, {"ok": False,
                             "error": f"{type(exc).__name__}: {exc}"})

    # -- файлы -------------------------------------------------------------

    def _handle_file(self):
        op = self.path.rsplit("/", 1)[-1]
        if op not in ("seal", "open"):
            self._json(404, {"ok": False, "error": "unknown endpoint"})
            return

        # Параметры едут в заголовках: тело занято самим файлом.
        try:
            kw = {}
            key_hex = self.headers.get("X-Ded-Key")
            pw_b64 = self.headers.get("X-Ded-Password")
            if key_hex:
                key = bytes.fromhex(key_hex.strip())
                if len(key) != D.KEY_BYTES:
                    raise ValueError("ключ должен быть 64 hex-символа")
                kw["key"] = key
            elif pw_b64:
                kw["password"] = base64.b64decode(pw_b64).decode("utf-8")
                if not kw["password"]:
                    raise ValueError("пароль пуст")
                if op == "seal":
                    t, m, p = (int(x) for x in
                               (self.headers.get("X-Ded-Argon") or "3,65536,4")
                               .split(","))
                    _check_argon_params(t, m, p)
                    kw.update(time_cost=t, memory_kib=m, lanes=p)
            else:
                raise ValueError("не задан ни ключ, ни пароль")

            if op == "seal":
                chunk = int(self.headers.get("X-Ded-Chunk") or DF.DEFAULT_CHUNK)
                if not DF.MIN_CHUNK <= chunk <= DF.MAX_CHUNK:
                    raise ValueError(
                        f"размер кадра должен быть {DF.MIN_CHUNK}..{DF.MAX_CHUNK}")
                kw["chunk_size"] = chunk
        except ValueError as exc:
            self._json(200, {"ok": False, "error": str(exc)})
            return
        except Exception:
            self._json(200, {"ok": False, "error": "некорректные параметры запроса"})
            return

        body, err = self._read_body(MAX_FILE_BODY)
        if err:
            self._json(413, {"ok": False, "error": err})
            return

        out = io.BytesIO()
        try:
            if op == "seal":
                DF.encrypt_stream(io.BytesIO(body), out, **kw)
            else:
                DF.decrypt_stream(io.BytesIO(body), out, **kw)
        except DF.AuthenticationError as exc:
            self._json(200, {"ok": False, "error": str(exc)})
            return
        except DF.FileFormatError as exc:
            self._json(200, {"ok": False, "error": str(exc)})
            return
        except ValueError as exc:
            self._json(200, {"ok": False, "error": str(exc)})
            return
        except Exception as exc:
            self._json(200, {"ok": False,
                             "error": f"{type(exc).__name__}: {exc}"})
            return

        blob = out.getvalue()
        # Число кадров считается по заголовку контейнера, а не угадывается.
        try:
            container = blob if op == "seal" else body
            chunk = DF._unpack_header(container[:DF.HEADER_BYTES])[4]
            payload = len(container) - DF.HEADER_BYTES
            frames = max(1, -(-payload // (chunk + DG.TAG_BYTES)))
        except Exception:
            frames = "?"

        self._send(200, blob, "application/octet-stream",
                   {"X-Ded-Frames": str(frames),
                    "Content-Disposition": "attachment"})


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
    print("Dedalyan web UI -- GCM, files, cipher explorer")
    print("=" * 66)
    print(f"  URL            : {url}")
    print(f"  cipher backend : {engine}")
    print(f"  bound to       : 127.0.0.1 only (not reachable from the network)")
    print(f"  request log    : disabled (passwords travel in request bodies)")
    print(f"  file limit     : {MAX_FILE_BODY // (1024 * 1024)} MiB per request")
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
    ap = argparse.ArgumentParser(description="Dedalyan web UI")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    sys.exit(serve(a.port, not a.no_browser))
