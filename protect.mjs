// Usage: node protect.mjs   (it asks for a username and password)
// Encrypts source/app.html into index.html (AES-256-GCM, key from PBKDF2 of username+password).
// The username and password are NOT stored anywhere; the page source is only unreadable ciphertext.
import { readFileSync, writeFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';
import { createInterface } from 'node:readline';

// ---- Session settings (change these if you like) ----
const IDLE_MINUTES = 30;   // signed out after this long with no activity
const MAX_HOURS = 8;       // signed out after this long no matter what
// -----------------------------------------------------

const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
const ask = async q => { process.stdout.write(q); return (await lines.next()).value || ''; };
const user = (process.env.PROTECT_USER || await ask('Username you want to use to log in: ')).trim().toLowerCase();
const password = process.env.PROTECT_PASSWORD || await ask('Password you want to use (8+ characters): ');
if (!user || password.length < 8) { console.error('Username is required and password needs 8+ characters. Run again.'); process.exit(1); }

const ITER = 600000;
const b64 = u8 => Buffer.from(u8).toString('base64');
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(user + '\n' + password), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(readFileSync('source/app.html', 'utf8'))));

const DATA = JSON.stringify({ s: b64(salt), i: b64(iv), c: b64(ct), n: ITER, idle: IDLE_MINUTES * 60000, max: MAX_HOURS * 3600000 });

// NOTE: this page code avoids backticks and dollar-brace so it can sit inside this template.
const page = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow"><title>Crestline Operations AI · Sign in</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Manrope:wght@600;700;800&display=swap">
<style>
:root{--bg:#f5f7f6;--surface:#fff;--surface-2:#f0f3f2;--fg:#16211d;--muted:#5d6b66;--line:#e2e7e5;--accent:#17594a;--accent-ink:#fff;--accent-soft:#e3efeb;--red:#c0392b;--red-soft:#fbe9e7;--amber:#b26a00;--amber-soft:#fdf1dc;--shadow:0 1px 2px rgba(20,40,30,.05),0 2px 8px rgba(20,40,30,.04);--display:"Manrope",system-ui,sans-serif;--body:"Inter",system-ui,-apple-system,"Segoe UI",sans-serif}
@media (prefers-color-scheme:dark){:root{--bg:#0f1513;--surface:#161e1b;--surface-2:#1c2622;--fg:#e7eeeb;--muted:#9aaba4;--line:#26322e;--accent:#5cc0a4;--accent-ink:#0b1411;--accent-soft:#1a332c;--red:#ef8577;--red-soft:#3a1f1c;--amber:#e7b25a;--amber-soft:#35291a;--shadow:none;color-scheme:dark}}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%}
body{font:14px/1.5 var(--body);color:var(--fg);min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:28px;padding:48px 16px;background:radial-gradient(1200px 600px at 10% 0%,var(--accent-soft),transparent 60%),var(--bg)}
h1{font-family:var(--display);font-weight:800;margin:0}
.crest{width:104px;height:104px;border-radius:24px;background:var(--accent);display:grid;place-items:center;box-shadow:0 8px 30px rgba(23,89,74,.25)}
.brand{text-align:center;display:flex;flex-direction:column;gap:6px}
.brand h1{font-size:28px;line-height:1.2}.brand p{margin:0;color:var(--muted)}
form{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:24px;width:min(380px,100%);box-shadow:var(--shadow)}
label{display:block;font-weight:600;font-size:12.5px;margin:0 0 6px}
.f{margin-bottom:14px}
input[type=text],input[type=password]{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:var(--surface);color:var(--fg);font:inherit}
input:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.r{display:flex;gap:8px;align-items:center;font-weight:500;color:var(--muted);margin:2px 0 4px}
.btn{border:1px solid var(--accent);background:var(--accent);color:var(--accent-ink);border-radius:8px;padding:10px 14px;font:600 13px var(--body);cursor:pointer}
.btn:disabled{opacity:.5;cursor:not-allowed}
form .btn{width:100%;margin-top:12px}
.msg{border-radius:8px;padding:9px 12px;font-size:12.5px;margin-bottom:14px;display:none}
.msg.err{display:block;background:var(--red-soft);color:var(--red)}
.msg.info{display:block;background:var(--amber-soft);color:var(--amber)}
.foot{max-width:380px;text-align:center;color:var(--muted);font-size:12px}
</style></head><body>
<div class="crest" aria-hidden="true"><svg width="56" height="56" viewBox="0 0 64 64" fill="none"><path d="M32 6l22 8v16c0 14-9.5 24-22 28C19.5 54 10 44 10 30V14l22-8z" fill="#f4c64e" stroke="#fff" stroke-width="2.5"/><path d="M22 32l7 7 13-15" stroke="#17594a" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
<div class="brand"><h1>Crestline Institute of Safety &amp; Quality</h1><p>Operations AI · sign in to continue</p></div>
<form id="f">
<div id="m" class="msg" role="alert"></div>
<div class="f"><label for="em">Username</label><input id="em" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" required></div>
<div class="f"><label for="pw">Password</label><input id="pw" type="password" autocomplete="current-password" required></div>
<label class="r"><input id="rm" type="checkbox" checked> Keep me signed in on this device</label>
<button id="b" class="btn">Sign in</button>
</form>
<div class="foot">Private access. Sessions end after inactivity. Built by AURMAK.</div>
<script>
var D=${DATA},SK='crestline-session';
var u8=function(s){return Uint8Array.from(atob(s),function(c){return c.charCodeAt(0)})};
var $=function(id){return document.getElementById(id)};
function store(remember){return remember?localStorage:sessionStorage}
function readSession(){
  var out=null;
  [localStorage,sessionStorage].forEach(function(st){try{var v=st.getItem(SK);if(v&&!out){var s=JSON.parse(v);s.st=st;out=s}}catch(e){}});
  return out;
}
function clearSession(){[localStorage,sessionStorage].forEach(function(st){try{st.removeItem(SK)}catch(e){}})}
function expired(s){var n=Date.now();return n-s.start>D.max||n-s.last>D.idle}
function say(t,k){var m=$('m');m.textContent=t;m.className='msg '+k}
function aesKey(raw,usage){return crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt'])}
function decryptWith(key){return crypto.subtle.decrypt({name:'AES-GCM',iv:u8(D.i)},key,u8(D.c)).then(function(b){return new TextDecoder().decode(b)})}

// Runs inside the app page after sign-in: idle timeout, hard limit, warning banner.
function watch(cfg){
  var SK=cfg.sk,warned=false,lastWrite=0,box=null,tick=null;
  function find(){var r=null;[localStorage,sessionStorage].forEach(function(st){try{var v=st.getItem(SK);if(v&&!r){r={st:st,s:JSON.parse(v)}}}catch(e){}});return r}
  function out(msg){try{localStorage.removeItem(SK);sessionStorage.removeItem(SK);sessionStorage.setItem('crestline-msg',msg)}catch(e){}location.reload()}
  function touch(){
    if(warned)return;var n=Date.now();if(n-lastWrite<5000)return;lastWrite=n;
    var f=find();if(!f)return;f.s.last=n;try{f.st.setItem(SK,JSON.stringify(f.s))}catch(e){}
  }
  ['mousemove','mousedown','keydown','scroll','touchstart','click'].forEach(function(ev){addEventListener(ev,touch,{passive:true,capture:true})});
  function banner(secs){
    if(!box){
      box=document.createElement('div');
      box.setAttribute('role','alertdialog');
      box.style.cssText='position:fixed;left:50%;bottom:24px;transform:translateX(-50%);z-index:2147483647;background:#fdf1dc;color:#4a2f00;border:1px solid #e7b25a;border-radius:12px;padding:12px 16px;box-shadow:0 8px 30px rgba(0,0,0,.2);font:600 13px Inter,system-ui,sans-serif;display:flex;gap:14px;align-items:center;max-width:92vw';
      var t=document.createElement('span');t.id='cl-t';box.appendChild(t);
      var b=document.createElement('button');b.textContent='Stay signed in';
      b.style.cssText='border:1px solid #17594a;background:#17594a;color:#fff;border-radius:8px;padding:7px 12px;font:600 12.5px Inter,system-ui,sans-serif;cursor:pointer;white-space:nowrap';
      b.onclick=function(e){e.stopPropagation();warned=false;lastWrite=0;touch();box.remove();box=null};
      box.appendChild(b);document.body.appendChild(box);
    }
    box.firstChild.textContent='Your session will expire in '+secs+'s due to inactivity.';
  }
  tick=setInterval(function(){
    var f=find();if(!f){out('You have been signed out.');return}
    var n=Date.now(),idleLeft=cfg.idle-(n-f.s.last),maxLeft=cfg.max-(n-f.s.start);
    if(maxLeft<=0){out('Your session has ended. Please sign in again.');return}
    if(idleLeft<=0){out('You were signed out after '+Math.round(cfg.idle/60000)+' minutes of inactivity.');return}
    if(idleLeft<=60000){warned=true;banner(Math.ceil(idleLeft/1000))}
    else if(warned){warned=false;if(box){box.remove();box=null}}
  },1000);
}
function show(html){
  var w='<scr'+'ipt>('+watch.toString()+')('+JSON.stringify({sk:SK,idle:D.idle,max:D.max})+')</scr'+'ipt>';
  var i=html.lastIndexOf('</body>');
  document.open();document.write(i<0?html+w:html.slice(0,i)+w+html.slice(i));document.close();
}
$('f').addEventListener('submit',function(e){
  e.preventDefault();$('b').disabled=true;say('','');
  var name=$('em').value.trim().toLowerCase(),pw=$('pw').value,remember=$('rm').checked;
  crypto.subtle.importKey('raw',new TextEncoder().encode(name+'\\n'+pw),'PBKDF2',false,['deriveKey'])
  .then(function(b){return crypto.subtle.deriveKey({name:'PBKDF2',salt:u8(D.s),iterations:D.n,hash:'SHA-256'},b,{name:'AES-GCM',length:256},true,['decrypt'])})
  .then(function(k){return decryptWith(k).then(function(html){
    return crypto.subtle.exportKey('raw',k).then(function(raw){
      var now=Date.now();
      try{store(remember).setItem(SK,JSON.stringify({k:btoa(String.fromCharCode.apply(null,new Uint8Array(raw))),start:now,last:now}))}catch(x){}
      show(html);
    });
  })})
  .catch(function(){say('Incorrect username or password.','err');$('b').disabled=false;$('pw').value='';$('pw').focus()});
});
// Resume an existing, unexpired session; otherwise show the form.
(function(){
  try{var m=sessionStorage.getItem('crestline-msg');if(m){say(m,'info');sessionStorage.removeItem('crestline-msg')}}catch(e){}
  var s=readSession();if(!s)return;
  if(expired(s)){clearSession();say('Your session has expired. Please sign in again.','info');return}
  aesKey(u8(s.k)).then(decryptWith).then(show).catch(function(){clearSession()});
})();
</script></body></html>`;
writeFileSync('index.html', page);
console.log('Wrote index.html (' + Math.round(page.length / 1024) + ' KB). Deploy only this file.');
console.log('Session: signed out after ' + IDLE_MINUTES + ' min idle or ' + MAX_HOURS + ' h total.');
process.exit(0);
