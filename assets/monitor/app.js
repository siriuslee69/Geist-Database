/* The browser renders only. Every request enters the local Nim Geist client. */
let busy=false,ready=false,lastMessages='',lastEvents='';
const $=id=>document.getElementById(id);
// {.role: orchestrator.}
async function nativeCall(q){
  const text=JSON.stringify(q);
  if(window.GeistNative)return JSON.parse(window.GeistNative.request(text));
  return JSON.parse(await window.webui.geistRequest(text));
}
// {.role: helper.}
function time(at){return new Date(at*1000).toLocaleTimeString();}
// {.role: dataWriter.}
function renderMessages(rows){
  const stamp=JSON.stringify(rows);if(stamp===lastMessages)return;lastMessages=stamp;
  const box=$('conversation');box.replaceChildren();
  for(const row of rows){const item=document.createElement('article'),meta=document.createElement('span'),body=document.createElement('div');item.className='message '+row.direction;meta.className='meta';meta.textContent=`${row.sender} · ${row.channel} · ${time(row.at)}`;body.textContent=row.body;item.append(meta,body);box.append(item);}
  box.scrollTop=box.scrollHeight;
}
// {.role: dataWriter.}
function renderEvents(rows){
  const visible=rows.filter(e=>e.step!=='reply.received'),stamp=JSON.stringify(visible);if(stamp===lastEvents)return;lastEvents=stamp;
  const box=$('events');box.replaceChildren();
  for(const e of visible.slice(-80).reverse()){const item=document.createElement('li');item.className=e.error?'failed':e.step.includes('accepted')||e.step.includes('confirmed')?'accepted':'';item.textContent=`${time(e.at)} ${e.step}\n${e.subject||e.peer} · ${e.mode} · ${e.tier}\nKEM ${e.masks.kem} / SIG ${e.masks.signature} · #${e.session}${e.error?'\n'+e.error:''}`;box.append(item);}
}
// {.role: orchestrator.}
async function perform(q){
  if(busy)return false;busy=true;$('send').disabled=true;
  if(q.op!=='status'&&q.op!=='poll')$('connection').textContent='Geist arbeitet …';
  try{const r=await nativeCall(q);$('error').textContent=r.error||'';if(r.subject)$('device').textContent=r.subject;if(r.messages)renderMessages(r.messages);if(r.events)renderEvents(r.events);$('connection').textContent=r.ok?(r.relay&&r.store?'Relay + VPS verbunden':'Bereit'):'Verbindungsfehler';return r.ok;}catch(e){$('error').textContent=String(e);return false;}finally{busy=false;$('send').disabled=false;}
}
// {.role: orchestrator.}
async function send(){const input=$('body'),body=input.value;if(!body.trim())return;if(await perform({op:'send',channel:$('channel').value,body}))input.value='';}
$('send').onclick=send;$('body').onkeydown=e=>{if(e.key==='Enter')send();};$('clear').onclick=()=>{$('body').value='';$('body').focus();};$('handshake').onclick=()=>perform({op:'handshake'});$('showTrace').onclick=()=>$('trace').classList.toggle('open');
document.addEventListener('pointerdown',e=>{if(!e.target.closest('#trace,#showTrace'))$('trace').classList.remove('open');if(!e.target.closest('.compose'))$('body').blur();});
// {.role: orchestrator.}
async function start(){ready=true;await perform({op:'status'});setInterval(()=>{if(ready&&!document.hidden)perform({op:'poll'});},1500);}
if(window.GeistNative)start();else{const connected=setInterval(()=>{if(window.webui&&window.webui.isConnected()){clearInterval(connected);start();}},50);}
if(window.visualViewport)window.visualViewport.addEventListener('resize',()=>{document.body.style.height=window.visualViewport.height+'px';document.querySelector('footer').style.bottom=Math.max(12,window.innerHeight-window.visualViewport.height)+'px';});
