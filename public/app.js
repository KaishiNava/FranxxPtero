const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
let token=localStorage.getItem("fx_token"),mode="login",servers=[],current=null,cwd="",ws=null,editing="",selected=new Set(),statsTimer=null,me=null;

const api=async(url,opt={})=>{
  opt.headers={
    ...(opt.headers||{}),
    Authorization:`Bearer ${token}`
  };

  if(opt.body&&!(opt.body instanceof FormData)){
    opt.headers["Content-Type"]="application/json";
    opt.body=JSON.stringify(opt.body);
  }

  const r=await fetch(url,opt);
  const d=await r.json().catch(()=>({}));

  if(!r.ok)throw Error(d.error||"Request failed");
  return d;
};

function toast(msg,err=false){
  const x=document.createElement("div");
  x.className="toast"+(err?" err":"");
  x.textContent=msg;
  $("#toast").append(x);
  setTimeout(()=>x.remove(),2800);
}

function showPage(id){
  if((id==='profile'||id==='apiKeys')&&!me?.root){
    toast('Akses root/admin diperlukan',true);
    return;
  }

  $$('.page').forEach(x=>x.classList.add('hidden'));
  $("#"+id).classList.remove('hidden');

  $$('.nav').forEach(x=>
    x.classList.toggle('active',x.dataset.page===id)
  );

  if(id==='servers')loadServers();
  if(id==='profile')loadProfile();
  if(id==='apiKeys')loadApiKeys();

  if(id!=='serverDetail'){
    if(ws)try{ws.close()}catch{}
    if(statsTimer)clearInterval(statsTimer);
    ws=null;
    statsTimer=null;
  }

  if(window.innerWidth<=800){
    $("#side").classList.remove('open');
    document.body.classList.remove('menu-open');
  }
}

function openCreate(){
  $("#modal").classList.remove("hidden");
  document.body.classList.add('modal-open');
  setTimeout(()=>$("#newName").focus(),50);
}

function closeModal(){
  $("#modal").classList.add("hidden");
  document.body.classList.remove('modal-open');
}

function esc(x){
  return String(x).replace(/[&<>"']/g,c=>({
    "&":"&amp;",
    "<":"&lt;",
    ">":"&gt;",
    '"':"&quot;",
    "'":"&#39;"
  }[c]));
}

function card(s){
  return `
    <div class="server-card">
      <div class="server-row">
        <h3>${esc(s.name)}</h3>
        <span class="status ${s.status}">
          ${s.status.toUpperCase()}
        </span>
      </div>

      <div class="server-meta">
        ${esc(s.runtime)} · ${esc(s.entry)} · ${fmtMB(s.memoryLimit||512)} RAM
      </div>

      <button class="ghost" onclick="openServer('${esc(s.id)}')">
        MANAGE →
      </button>
    </div>
  `;
}

async function loadServers(){
  try{
    servers=await api('/api/servers');

    $("#serverCount").textContent=servers.length;
    $("#onlineCount").textContent=
      servers.filter(s=>s.status==='online').length;

    $("#serverGrid").innerHTML=
      servers.length
      ?servers.map(card).join('')
      :`<div class="card">Belum ada server.</div>`;

    $("#recent").innerHTML=
      servers.slice(0,4).map(card).join('')
      ||`<div class="card">Belum ada server.</div>`;
  }catch(e){
    toast(e.message,true);
  }
}

async function createServer(){
  try{
    const memory=Math.max(
      64,
      Math.min(
        32768,
        Number($("#newMemory").value)||512
      )
    );

    const s=await api('/api/servers',{
      method:'POST',
      body:{
        name:$("#newName").value,
        runtime:$("#newRuntime").value,
        entry:$("#newEntry").value,
        command:$("#newCommand").value,
        memoryLimit:memory,
        webUrl:$("#newWebUrl").value.trim(),
        webPort:Number($("#newWebPort").value)||0
      }
    });

    closeModal();
    toast('Server berhasil dibuat');

    $("#newName").value='';
    $("#newWebUrl").value='';
    $("#newWebPort").value='';

    await loadServers();
    openServer(s.id);
  }catch(e){
    toast(e.message,true);
  }
}

async function openServer(id){
  current=
    servers.find(x=>x.id===id)
    ||
    await api('/api/servers').then(a=>a.find(x=>x.id===id));

  if(!current)return;

  $("#detailName").textContent=current.name;
  $("#detailBannerName").textContent=current.name;
  $("#detailRuntime").textContent=current.runtime.toUpperCase();
  $("#detailStatus").textContent=current.status.toUpperCase();
  $("#detailStatus").className='status '+current.status;

  $("#commandInput").value=current.command;
  $("#entryInput").value=current.entry;
  $("#memoryInput").value=current.memoryLimit||512;

  $("#console").innerHTML=
    '<div class="console-welcome">FRANXX RUNTIME<br><span>Waiting for process...</span></div>';

  cwd='';
  editing='';
  selected.clear();

  $("#editing").textContent='No file selected';
  $("#editor").value='';

  showPage('serverDetail');
  switchTab('console');
  connectWS();
  loadFiles();
  refreshStats();
}

function connectWS(){
  if(ws)try{ws.close()}catch{}

  ws=new WebSocket(
    `${location.protocol==='https:'?'wss':'ws'}://${location.host}/ws?token=${encodeURIComponent(token)}&server=${encodeURIComponent(current.id)}`
  );

  ws.onopen=()=>
    $("#runtimeInfo").textContent='WebSocket connected';

  ws.onclose=()=>{
    if(
      current &&
      $("#serverDetail") &&
      !$("#serverDetail").classList.contains('hidden')
    ){
      $("#runtimeInfo").textContent='Console disconnected';
    }
  };

  ws.onerror=()=>{};

  ws.onmessage=e=>{
    try{
      const d=JSON.parse(e.data);

      if(d.type==='log'){
        const c=$("#console");

        if(c.querySelector('.console-welcome'))
          c.innerHTML='';

        const text=String(d.data||'');
        const span=document.createElement('span');

        span.className=
          /error|failed|exception/i.test(text)
          ?'log-error'
          :/success|ready|connected|online/i.test(text)
          ?'log-ok'
          :'';

        span.textContent=text;
        c.append(span);
        c.scrollTop=c.scrollHeight;

      }else if(d.type==='status'){
        current.status=d.status;

        $("#detailStatus").textContent=
          d.status.toUpperCase();

        $("#detailStatus").className=
          'status '+d.status;

        $("#runtimeInfo").textContent=
          d.status==='online'
          ?'Process running'
          :`Process stopped${d.code!==undefined?' · exit '+d.code:''}`;

        refreshStats();
        loadServers();
      }
    }catch{}
  };

  if(statsTimer)clearInterval(statsTimer);
  statsTimer=setInterval(refreshStats,2500);
}

async function refreshStats(){
  if(!current)return;

  try{
    const s=await api(`/api/servers/${current.id}/stats`);

    const ram=fmt(s.memory);
    const limit=fmt(s.memoryLimit);

    const ramPct=
      s.memoryLimit
      ?Math.min(100,(s.memory/s.memoryLimit)*100)
      :0;

    $("#ramValue").textContent=`${ram} / ${limit}`;
    $("#ramBar").style.width=`${ramPct}%`;
    $("#ramPct").textContent=`${Math.round(ramPct)}%`;

    $("#cpuValue").textContent=
      `${Number(s.cpu||0).toFixed(1)}%`;

    $("#cpuBar").style.width=
      `${Math.min(100,Number(s.cpu||0))}%`;

    $("#storageValue").textContent=fmt(s.storage);

    $("#storageBar").style.width=
      `${Math.min(
        100,
        (s.storage/
          Math.max(s.storageLimit||1073741824,1)
        )*100
      )}%`;

    $("#uptimeValue").textContent=
      s.status==='online'
      ?fmtUptime(s.uptime)
      :'OFFLINE';

    $("#runtimeInfo").textContent=
      s.status==='online'
      ?`Running · ${fmtUptime(s.uptime)}`
      :'Process offline';

  }catch{}
}

function fmtUptime(sec){
  sec=Number(sec)||0;

  const h=Math.floor(sec/3600);
  const m=Math.floor(sec%3600/60);
  const s=sec%60;

  return `${h}h ${m}m ${s}s`;
}

function fmt(n){
  n=Number(n)||0;

  return n<1024
    ?n+' B'
    :n<1048576
    ?(n/1024).toFixed(1)+' KB'
    :n<1073741824
    ?(n/1048576).toFixed(1)+' MB'
    :(n/1073741824).toFixed(2)+' GB';
}

function fmtMB(n){
  return Number(n)>=1024
    ?(Number(n)/1024).toFixed(Number(n)%1024?'1':'0')+' GB'
    :Number(n)+' MB';
}

async function action(type){
  try{
    await api(`/api/servers/${current.id}/${type}`,{
      method:'POST'
    });

    toast(type.toUpperCase()+' sent');

    setTimeout(loadServers,800);
    setTimeout(refreshStats,800);
  }catch(e){
    toast(e.message,true);
  }
}

$("#startBtn").onclick=()=>action('start');
$("#stopBtn").onclick=()=>action('stop');
$("#restartBtn").onclick=()=>action('restart');

$("#stdin").addEventListener('keydown',e=>{
  if(
    e.key==='Enter' &&
    ws &&
    ws.readyState===1
  ){
    ws.send(JSON.stringify({
      type:'stdin',
      data:e.target.value
    }));

    e.target.value='';
  }
});

function pathToken(p){
  return encodeURIComponent(p).replace(/'/g,'%27');
}

function renderFilePath(){
  const parts=cwd.split('/').filter(Boolean);

  let html=
    '<button class="path-root" onclick="enter(&quot;&quot;)">ROOT</button>';

  let built='';

  parts.forEach((part)=>{
    built=built?built+'/'+part:part;

    const token=pathToken(built);

    html+=
      `<span class="path-sep">/</span>
       <button class="path-part" onclick="enterEncoded('${token}')">
         ${esc(part)}
       </button>`;
  });

  $("#cwd").innerHTML=html;
}

async function loadFiles(){
  try{
    const a=await api(
      `/api/servers/${current.id}/files?path=${encodeURIComponent(cwd)}`
    );

    renderFilePath();

    const head=cwd
      ?`<div class="file file-up" onclick="goUp()">
          <span class="file-icon">↩</span>
          <span class="name">.. <small>UP ONE LEVEL</small></span>
        </div>`
      :'';

    const rows=a.map(f=>{
      const p=cwd?cwd+'/'+f.name:f.name;
      const ep=pathToken(p);
      const checked=selected.has(p)?'checked':'';

      const openButton=
        f.type==='dir'
        ?`<button class="ghost file-action file-open"
             aria-label="Open ${esc(f.name)}"
             title="Open folder"
             onclick="event.stopPropagation();enterEncoded('${ep}')">
             →
           </button>`
        :'';

      const unzipButton=
        f.type==='file' &&
        f.name.toLowerCase().endsWith('.zip')
        ?`<button class="ghost file-action file-unzip"
             aria-label="Unzip ${esc(f.name)}"
             title="Unzip"
             onclick="event.stopPropagation();unzipEncoded('${ep}')">
             UNZIP
           </button>`
        :'';

      return `
        <div class="file"
          ondblclick="${f.type==='dir'
            ?`enterEncoded('${ep}')`
            :`editEncoded('${ep}')`}">

          <input
            class="file-check"
            type="checkbox"
            ${checked}
            onclick="event.stopPropagation();toggleSelected('${ep}',this.checked)"
          >

          <span class="file-icon ${
            f.name.toLowerCase().endsWith('.zip')?'zip':''
          }">
            ${
              f.type==='dir'
              ?'▣'
              :f.name.toLowerCase().endsWith('.zip')
              ?'ZIP'
              :'□'
            }
          </span>

          <span class="name">${esc(f.name)}</span>

          <span class="size">
            ${f.type==='dir'?'DIR':fmt(f.size)}
          </span>

          ${openButton}
          ${unzipButton}

          <button
            class="ghost file-action file-delete"
            aria-label="Delete ${esc(f.name)}"
            title="Delete"
            onclick="event.stopPropagation();removeEncoded('${ep}')">
            ×
          </button>
        </div>
      `;
    }).join('');

    $("#files").innerHTML=
      (head+rows)
      ||
      `<div class="empty">Folder kosong</div>`;

    updateSelectionUI();

  }catch(e){
    toast(e.message,true);
  }
}

function enter(p){
  cwd=String(p||'').replace(/^\/+|\/+$/g,'');
  selected.clear();
  loadFiles();
}

function goUp(){
  cwd=cwd.split('/').slice(0,-1).join('/');
  selected.clear();
  loadFiles();
}

function decodePath(v){
  return decodeURIComponent(v);
}

function enterEncoded(v){
  enter(decodePath(v));
}

function editEncoded(v){
  editFile(decodePath(v));
}

function removeEncoded(v){
  removeFile(decodePath(v));
}

async function editFile(p){
  try{
    const d=await api(
      `/api/servers/${current.id}/file?path=${encodeURIComponent(p)}`
    );

    editing=p;
    $("#editing").textContent=p;
    $("#editor").value=d.content;

    switchTab('editor');
  }catch(e){
    toast(e.message,true);
  }
}

async function saveFile(){
  if(!editing)
    return toast('Pilih file dulu',true);

  try{
    await api(
      `/api/servers/${current.id}/file`,
      {
        method:'PUT',
        body:{
          path:editing,
          content:$("#editor").value
        }
      }
    );

    toast('File tersimpan');
  }catch(e){
    toast(e.message,true);
  }
}

async function unzipEncoded(v){
  const p=decodePath(v);

  try{
    await api(
      `/api/servers/${current.id}/unzip`,
      {
        method:'POST',
        body:{path:p}
      }
    );

    toast('ZIP berhasil di-unzip');
    loadFiles();
  }catch(e){
    toast(e.message,true);
  }
}

function clearConsole(){
  $("#console").innerHTML='';
  $("#runtimeInfo").textContent='Console cleared';
}

function uploadFiles(){
  $("#fileInput").click();
}

$("#fileInput").onchange=async e=>{
  const files=[...e.target.files];

  if(!files.length)return;

  const fd=new FormData();

  files.forEach(f=>
    fd.append('files',f)
  );

  try{
    await api(
      `/api/servers/${current.id}/upload?path=${encodeURIComponent(cwd)}`,
      {
        method:'POST',
        body:fd
      }
    );

    toast(`${files.length} file berhasil diupload`);
    loadFiles();
  }catch(e){
    toast(e.message,true);
  }

  e.target.value='';
};

async function newFolder(){
  const n=prompt('Nama folder:');

  if(!n)return;

  try{
    await api(
      `/api/servers/${current.id}/mkdir`,
      {
        method:'POST',
        body:{
          path:cwd?cwd+'/'+n:n
        }
      }
    );

    loadFiles();
  }catch(e){
    toast(e.message,true);
  }
}

async function removeFile(p){
  if(!confirm('Hapus '+p+'?'))return;

  try{
    await api(
      `/api/servers/${current.id}/file`,
      {
        method:'DELETE',
        body:{path:p}
      }
    );

    selected.delete(p);
    loadFiles();
  }catch(e){
    toast(e.message,true);
  }
}

function toggleSelected(encoded,checked){
  const p=decodePath(encoded);

  if(checked)
    selected.add(p);
  else
    selected.delete(p);

  updateSelectionUI();
}

function updateSelectionUI(){
  $("#selectedCount").textContent=selected.size;
  $("#deleteSelected").disabled=!selected.size;
  $("#zipSelected").disabled=!selected.size;
  $("#downloadSelected").disabled=!selected.size;

  $("#moveRootSelected").disabled=
    !selected.size ||
    !selected.some(p=>p.includes('/'));
}

function selectAllFiles(){
  $$('#files .file')
    .filter(x=>x.querySelector('.file-check'))
    .forEach(row=>{
      const c=row.querySelector('.file-check');
      c.checked=true;

      const name=row.querySelector('.name')?.textContent;

      if(name&&name!=='..')
        selected.add(
          cwd?cwd+'/'+name:name
        );
    });

  updateSelectionUI();
}

function clearSelection(){
  selected.clear();

  $$('.file-check').forEach(
    c=>c.checked=false
  );

  updateSelectionUI();
}

async function deleteSelected(){
  const paths=[...selected];

  if(!paths.length)return;

  if(!confirm(`Hapus ${paths.length} item terpilih?`))
    return;

  try{
    await api(
      `/api/servers/${current.id}/files/bulk`,
      {
        method:'DELETE',
        body:{paths}
      }
    );

    toast(`${paths.length} item dihapus`);
    clearSelection();
    loadFiles();
  }catch(e){
    toast(e.message,true);
  }
}

async function moveSelectedToRoot(){
  const paths=[...selected];

  if(!paths.length)return;

  const nested=paths.filter(p=>p.includes('/'));

  if(!nested.length)return;

  if(!confirm(
    `Pindahkan ${nested.length} item terpilih ke root server? Seluruh isi folder akan ikut dipindahkan.`
  ))return;

  try{
    const r=await api(
      `/api/servers/${current.id}/move-to-root`,
      {
        method:'POST',
        body:{paths:nested}
      }
    );

    toast(
      `${r.moved?.length||nested.length} item dipindahkan ke root`
    );

    clearSelection();
    cwd='';
    loadFiles();
  }catch(e){
    toast(e.message,true);
  }
}

async function downloadZip(){
  const paths=[...selected];

  if(!paths.length)return;

  try{
    toast('Membuat ZIP...');

    const r=await fetch(
      `/api/servers/${current.id}/archive`,
      {
        method:'POST',
        headers:{
          Authorization:`Bearer ${token}`,
          'Content-Type':'application/json'
        },
        body:JSON.stringify({paths})
      }
    );

    if(!r.ok){
      const d=await r.json().catch(()=>({}));
      throw Error(d.error||'Gagal membuat ZIP');
    }

    const blob=await r.blob();

    const cd=r.headers.get('Content-Disposition')||'';
    const m=cd.match(/filename="?([^";]+)"?/i);

    const name=
      m
      ?m[1]
      :'fx-download.zip';

    const a=document.createElement('a');

    a.href=URL.createObjectURL(blob);
    a.download=name;

    document.body.appendChild(a);
    a.click();
    a.remove();

    setTimeout(
      ()=>URL.revokeObjectURL(a.href),
      1000
    );

    toast('ZIP berhasil didownload');

  }catch(e){
    toast(e.message,true);
  }
}

async function zipSelected(){
  await downloadZip();
}

async function saveSettings(){
  try{
    const memory=Math.max(
      64,
      Math.min(
        32768,
        Number($("#memoryInput").value)||512
      )
    );

    await api(
      `/api/servers/${current.id}/settings`,
      {
        method:'PUT',
        body:{
          command:$("#commandInput").value,
          entry:$("#entryInput").value,
          memoryLimit:memory
        }
      }
    );

    current.memoryLimit=memory;

    toast('Settings tersimpan');
    refreshStats();

  }catch(e){
    toast(e.message,true);
  }
}

async function deleteServer(){
  if(!confirm('Hapus server beserta seluruh file?'))
    return;

  try{
    await api(
      `/api/servers/${current.id}`,
      {
        method:'DELETE'
      }
    );

    toast('Server dihapus');
    showPage('servers');

  }catch(e){
    toast(e.message,true);
  }
}

function switchTab(t){
  $$('.stab').forEach(x=>
    x.classList.toggle(
      'active',
      x.dataset.tab===t
    )
  );

  $$('.tabpage').forEach(
    x=>x.classList.add('hidden')
  );

  $("#"+t+"Tab").classList.remove('hidden');

  if(t==='files')
    loadFiles();

  if(t==='console')
    refreshStats();
}

$$('.stab').forEach(
  x=>x.onclick=()=>switchTab(x.dataset.tab)
);

$$('.nav').forEach(
  x=>x.onclick=()=>showPage(x.dataset.page)
);

$("#mobileMenu").onclick=()=>{
  const side=$("#side");

  side.classList.toggle('open');
  document.body.classList.toggle(
    'menu-open',
    side.classList.contains('open')
  );
};


/* =========================
   LOGOUT
========================= */

$("#logout").onclick=()=>{
  localStorage.removeItem('fx_token');
  localStorage.removeItem('fx_root');
  location.reload();
};


/* =========================
   ROOT PROFILE
========================= */

async function loadProfile(){
  try{
    const d=await api('/api/root/profile');

    $("#profileUsername").textContent=
      '@'+d.account.username;

    $("#profileId").textContent=
      d.account.id;

    $("#profileCreated").textContent=
      new Date(d.account.createdAt).toLocaleString();

    $("#userList").innerHTML=
      d.users.map(u=>`
        <div class="admin-row">
          <div>
            <b>@${esc(u.username)}</b>
            <small>
              ${esc(u.id)} ·
              ${u.root?'ROOT / ADMIN':'USER'} ·
              ${new Date(u.createdAt).toLocaleDateString()}
            </small>
          </div>

          <span class="status ${u.root?'online':''}">
            ${u.root?'ROOT':'USER'}
          </span>
        </div>
      `).join('')
      ||
      '<div class="card">Belum ada user.</div>';

  }catch(e){
    toast(e.message,true);
  }
}

async function createPanelUser(){
  try{
    const username=
      $("#newUserUsername").value.trim();

    const password=
      $("#newUserPassword").value;

    const root=
      $("#newUserRoot").checked;

    await api(
      '/api/root/users',
      {
        method:'POST',
        body:{
          username,
          password,
          root
        }
      }
    );

    $("#newUserUsername").value='';
    $("#newUserPassword").value='';
    $("#newUserRoot").checked=false;

    toast('User berhasil dibuat');
    loadProfile();

  }catch(e){
    toast(e.message,true);
  }
}


/* =========================
   API ACCESS KEYS
========================= */

async function loadApiKeys(){
  try{
    const keys=
      await api('/api/root/access-keys');

    $("#keyList").innerHTML=
      keys.map(k=>`
        <div class="admin-row key-row">
          <div>
            <b>${esc(k.name)}</b>

            <small>
              ${esc(k.prefix)} ·
              ${esc(k.scopes.join(', '))} ·
              ${new Date(k.createdAt).toLocaleString()}
            </small>
          </div>

          <div class="key-actions">
            <span class="status ${k.revokedAt?'':'online'}">
              ${k.revokedAt?'REVOKED':'ACTIVE'}
            </span>

            ${
              k.revokedAt
              ?''
              :`
                <button
                  class="danger tiny"
                  onclick="revokeAccessKey('${esc(k.id)}')">
                  REVOKE
                </button>
              `
            }
          </div>
        </div>
      `).join('')
      ||
      '<div class="card">Belum ada access key.</div>';

  }catch(e){
    toast(e.message,true);
  }
}

async function createAccessKey(){
  try{
    const scopes=[];

    const scopeMap=[
      ['scopeUsers','users:create'],
      ['scopeUsersRead','users:read'],
      ['scopeUsersDelete','users:delete'],

      ['scopeServers','servers:create'],
      ['scopeServersRead','servers:read'],
      ['scopeServersManage','servers:manage'],
      ['scopeServersDelete','servers:delete'],

      ['scopeStats','stats:read'],
      ['scopeWeb','web:ping']
    ];

    scopeMap.forEach(([id,scope])=>{
      if($("#"+id)?.checked)
        scopes.push(scope);
    });

    const d=
      await api(
        '/api/root/access-keys',
        {
          method:'POST',
          body:{
            name:$("#keyName").value.trim(),
            scopes
          }
        }
      );

    $("#keyName").value='';
    $("#newSecret").textContent=d.secret;
    $("#newSecretBox").classList.remove('hidden');

    toast(
      'Access key dibuat. Secret ditampilkan sekali.'
    );

    loadApiKeys();

  }catch(e){
    toast(e.message,true);
  }
}

async function revokeAccessKey(id){
  if(!confirm('Revoke access key ini?'))
    return;

  try{
    await api(
      '/api/root/access-keys/'+
      encodeURIComponent(id)+
      '/revoke',
      {
        method:'POST'
      }
    );

    toast('Access key direvoke');
    loadApiKeys();

  }catch(e){
    toast(e.message,true);
  }
}

async function copySecret(){
  const v=$("#newSecret").textContent;

  if(!v)return;

  try{
    await navigator.clipboard.writeText(v);
    toast('Key disalin');
  }catch{
    toast('Clipboard tidak tersedia',true);
  }
}


/* =========================
   AUTH MODE
========================= */

$$('.tabs button').forEach(b=>
  b.onclick=()=>{
    mode=b.dataset.mode;

    $$('.tabs button').forEach(
      x=>x.classList.toggle(
        'active',
        x===b
      )
    );

    $("#authBtn").textContent=
      mode.toUpperCase();
  }
);

$$('.preset-row button').forEach(b=>
  b.onclick=>
    $("#newMemory").value=b.dataset.memory
);

$("#newRuntime").onchange=()=>{
  const r=$("#newRuntime").value;

  if(r==='python'){
    $("#newEntry").value='main.py';
    $("#newCommand").value='python main.py';
  }else if(r==='node'){
    $("#newEntry").value='index.js';
    $("#newCommand").value='node index.js';
  }
};

$("#modal").addEventListener('click',e=>{
  if(e.target.id==='modal')
    closeModal();
});

document.addEventListener('keydown',e=>{
  if(
    e.key==='Escape' &&
    !$("#modal").classList.contains('hidden')
  ){
    closeModal();
  }
});


/* =========================
   LOGIN
========================= */

$("#authForm").onsubmit=async e=>{
  e.preventDefault();

  try{
    const r=await fetch(
      '/api/auth/login',
      {
        method:'POST',
        headers:{
          'Content-Type':'application/json'
        },
        body:JSON.stringify({
          username:$("#username").value,
          password:$("#password").value
        })
      }
    );

    const d=await r.json();

    if(!r.ok)
      throw Error(d.error||'Gagal login');

    localStorage.setItem(
      'fx_token',
      d.token
    );

    /*
     * SIMPAN STATUS ROOT DARI RESPONSE LOGIN.
     * Ini digunakan agar menu root tidak hilang
     * hanya karena /api/me mengembalikan data root
     * yang belum sinkron.
     */
    localStorage.setItem(
      'fx_root',
      d.user?.root ? '1' : '0'
    );

    location.reload();

  }catch(e){
    toast(e.message,true);
  }
};


/* =========================
   BOOT
========================= */

async function boot(){

  if(!token){
    $("#auth").classList.remove('hidden');
    return;
  }

  try{

    /*
     * Root yang diberikan server saat LOGIN
     * menjadi fallback untuk tampilan UI.
     */
    const cachedRoot=
      localStorage.getItem('fx_root')==='1';

    me=await api('/api/me');

    /*
     * Kalau login sebelumnya sudah memberikan
     * root:true tetapi /api/me belum sinkron,
     * jangan sembunyikan menu root.
     *
     * Ini hanya untuk UI.
     * Endpoint root tetap dilindungi server.js.
     */
    if(cachedRoot && !me.root){
      me={
        ...me,
        root:true
      };
    }

    $("#who").textContent=
      '@'+me.username;

    $("#rootNav").classList.toggle(
      'hidden',
      !me.root
    );

    $("#auth").classList.add('hidden');
    $("#app").classList.remove('hidden');

    await loadServers();

  }catch(e){

    $("#auth").classList.remove('hidden');

    localStorage.removeItem('fx_token');
    localStorage.removeItem('fx_root');

    token=null;
    me=null;
  }
}

boot();