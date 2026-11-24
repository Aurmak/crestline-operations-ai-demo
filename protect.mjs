// Usage: PROTECT_USER=you@example.com PROTECT_PASSWORD='secret' node protect.mjs
// Encrypts source/app.html into index.html (AES-256-GCM, key from PBKDF2 of username+password).
// The username and password are NOT stored anywhere; the page source is only unreadable ciphertext.
import { readFileSync, writeFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

import { createInterface } from 'node:readline';
const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
const ask = async q => { process.stdout.write(q); return (await lines.next()).value || ''; };
const email = (process.env.PROTECT_USER || await ask('Username you want to use to log in: ')).trim().toLowerCase();
const password = process.env.PROTECT_PASSWORD || await ask('Password you want to use (8+ characters): ');
if (!email || password.length < 8) { console.error('Username is required and password needs 8+ characters. Run again.'); process.exit(1); }

const ITER = 600000;
const b64 = u8 => Buffer.from(u8).toString('base64');
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(email + '\n' + password), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(readFileSync('source/app.html', 'utf8'))));

const page = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Crestline Operations AI · Sign in</title>
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f5f7f6;color:#16211d;font:14px -apple-system,BlinkMacSystemFont,"Inter",sans-serif}
form{background:#fff;border:1px solid #e2e7e5;border-radius:14px;padding:32px;width:min(380px,92vw);box-shadow:0 8px 30px rgba(0,0,0,.06)}
h1{margin:0 0 4px;font-size:20px}p{margin:0 0 20px;color:#5d6b66}label{display:block;font-weight:600;margin:14px 0 6px}
input[type=text],input[type=password]{width:100%;padding:11px 12px;border:1px solid #cfd8d4;border-radius:8px;font:inherit}
.r{display:flex;gap:8px;align-items:center;margin-top:14px;color:#5d6b66}
button{margin-top:20px;width:100%;padding:12px;border:0;border-radius:8px;background:#17594a;color:#fff;font:600 14px inherit;cursor:pointer}
button:disabled{opacity:.6}#e{color:#c0392b;margin-top:12px;min-height:18px}
</style></head><body>
<form id="f"><h1>Crestline Operations AI</h1><p>Sign in to continue.</p>
<label for="em">Username</label><input id="em" type="text" autocomplete="username" autocapitalize="none" required>
<label for="pw">Password</label><input id="pw" type="password" autocomplete="current-password" required>
<label class="r"><input id="rm" type="checkbox" checked> Remember me on this device</label>
<div id="e" role="alert"></div><button id="b">Sign in</button></form>
<script>
const D=${JSON.stringify({ s: b64(salt), i: b64(iv), c: b64(ct), n: ITER })};
const u8=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0)),$=id=>document.getElementById(id);
async function open(email,pw){
  const base=await crypto.subtle.importKey('raw',new TextEncoder().encode(email.trim().toLowerCase()+'\\n'+pw),'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:u8(D.s),iterations:D.n,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['decrypt']);
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:u8(D.i)},key,u8(D.c));
  return new TextDecoder().decode(pt);
}
function show(html){document.open();document.write(html);document.close()}
async function go(email,pw,remember){
  $('b').disabled=true;$('e').textContent='';
  try{const html=await open(email,pw);
    if(remember){try{localStorage.setItem('crestline-auth',JSON.stringify([email,pw]))}catch(_){}}
    show(html);return true}
  catch(_){$('e').textContent='Incorrect username or password.';$('b').disabled=false;return false}
}
$('f').addEventListener('submit',e=>{e.preventDefault();go($('em').value,$('pw').value,$('rm').checked)});
try{const a=JSON.parse(localStorage.getItem('crestline-auth')||'null');
  if(a)go(a[0],a[1],false).then(ok=>{if(!ok)localStorage.removeItem('crestline-auth')})}catch(_){}
</script></body></html>`;
writeFileSync('index.html', page);
console.log('Wrote index.html (' + Math.round(page.length / 1024) + ' KB). Deploy only this file.');
