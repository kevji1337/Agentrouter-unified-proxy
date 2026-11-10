// Offline browser smoke check, no packages or real credentials required.
// CHROME_BIN overrides the browser; output stays in DELTA_SCRATCH_DIR or the
// supplied output directory. Example: node scripts/admin-smoke.cjs .admin-smoke
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { pathToFileURL } = require('node:url');
const vm = require('node:vm');

const output = process.env.DELTA_SCRATCH_DIR || process.argv[2];
if (!output) throw Error('Set DELTA_SCRATCH_DIR or supply a temporary output directory');
fs.mkdirSync(output, { recursive: true });
const chrome = process.env.CHROME_BIN || [
  path.join(process.env.PROGRAMFILES || '', 'Google/Chrome/Application/chrome.exe'),
  path.join(process.env['PROGRAMFILES(X86)'] || '', 'Microsoft/Edge/Application/msedge.exe'),
  '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
].find(p => fs.existsSync(p));
if (!chrome) throw Error('Chrome/Chromium is required (set CHROME_BIN)');

const fixture = String.raw`
sessionStorage.setItem('ar_admin_session', 'fixture');
const requests = [];
let browserAuthenticated=true;
const providers = [
 {id:'provider_a', name:'Provider A', base_url:'https://api-a.example/v1', api_protocol:'chat-completions', spoof_profile:'generic', enabled:true, models:['model-a','model-shared'], keys:2},
 {id:'provider_b', name:'Provider B', base_url:'https://api-b.example/api/v1', api_protocol:'responses', spoof_profile:'generic', enabled:true, models:['model-b','model-shared'], keys:1},
];
const keys = Array.from({length:25}, (_,i) => ({id:'key_'+i, name:'Key '+i, provider_id:'provider_a', provider_name:'Provider A', base_url:providers[0].base_url, api_protocol:'chat-completions', proxy_mode:'auto', proxy_id:'proxy_1', enabled:true, mask:'sk-masked', uses:i, failures:0, models:['model-a']}));
const proxies = [{id:'proxy_1', name:'Outbound EU', url:'socks5://proxy.example:1080', enabled:true, has_auth:true, assigned_keys:25}];
let journalInstance = 'process-1';
const journal = [
 {seq:1,time:'2026-01-01T20:53:59Z',level:'info',category:'requests',message:'request_completed',summary:'POST /v1/chat/completions → HTTP 200 · 1250 мс',model:'model-a',provider:'Provider A',key_name:'Primary',key_mask:'sk-••••TEST',network_route:'Outbound EU',request_id:'req-a',status:200,duration_ms:1250},
 {seq:2,time:'2026-01-01T20:54:12Z',level:'info',category:'tools',background:true,message:'tool_call_emitted',summary:'Передан инструмент read_file',tool:'read_file',request_id:'req-a'},
 {seq:3,time:'2026-01-01T20:54:12Z',level:'warn',category:'tools',message:'parallel_tools_suppressed',summary:'Upstream прислал 3 инструмента, передан 1',returned:3,forwarded:1,request_id:'req-a'},
 {seq:4,time:'2026-01-01T20:54:13Z',level:'error',category:'requests',message:'request_completed',summary:'POST /v1/responses → HTTP 502 · ошибка соединения',provider:'Provider B',model:'model-b',error_code:'connection_error',request_id:'req-b',status:502},
 {seq:5,time:'2026-01-01T20:54:47Z',level:'info',category:'system',background:true,message:'key_health_completed',summary:'Проверка ключей: 25 проверено'},
 {seq:6,time:'2026-01-01T20:54:59Z',level:'info',category:'requests',message:'request_completed',summary:'<img src=x onerror="window.fixtureXss=true">',model:'model-safe',request_id:'req-safe',status:200},
];
window.confirm = () => true;
window.prompt = () => 'https://probe.example';
window.addEventListener('error', e => document.body.dataset.smokeError = e.message);
window.fetch = async (url, options = {}) => {
 requests.push([url, options]);
 const status = {upstream:'https://agentrouter.org', admin:{name:'owner',role:'admin',password_set:true}, store:{ready:true, available:25, total:25}, selection_mode:'pool-only', network_proxy_pool:true};
 let data = {};
 if(url==='/api/admin/logout'){browserAuthenticated=false;return {ok:true,status:204,json:async()=>({})};}
 if(url==='/api/admin/login'){browserAuthenticated=true;return {ok:true,status:200,json:async()=>({password_set:true,admin:{name:'owner',role:'admin'}})};}
 if(url==='/api/admin/password')return {ok:true,status:200,json:async()=>({password_set:true})};
 if(!browserAuthenticated)return {ok:false,status:401,json:async()=>({error:{code:'admin_auth_required',message:'Sign in'}})};
 if (url.includes('/logs')) {const after=Number(new URL(url,'http://fixture').searchParams.get('after'));const rows=after===0?journal:journal.filter(item=>item.seq>after);data={data:rows,instance:journalInstance,next_after:rows.length?rows[rows.length-1].seq:after,has_more:false};}
 else if (url.includes('/status')) data = status;
 else if (url.includes('/providers')) data = {data:providers};
 else if (url.includes('/network-proxies')) data = {data:proxies, ok:true, message:'Fixture proxy OK'};
 else if (url.includes('/keys')) data = {data:keys};
 else data = {data:[]};
 return {ok:true, status:200, json:async () => data};
};`;

async function smoke() {
 const pause = () => new Promise(resolve => setTimeout(resolve, 120));
 const assert = (value, message) => { if (!value) throw Error(message); };
 try {
  await pause();
  document.querySelector('[data-page="providers"]').click(); await pause();
  assert(document.querySelectorAll('#providerContent article').length === 2, 'provider cards');
  assert(document.querySelectorAll('.model-chip').length === 4, 'model chips');
  document.querySelector('[data-provider-edit="provider_a"]').click();
  assert(document.getElementById('providerDialog').open, 'provider editor');
  document.getElementById('providerModels').value = 'model-a\nnew-model';
  document.getElementById('providerForm').dispatchEvent(new Event('submit', {cancelable:true})); await pause();
  const update = requests.find(([p,o]) => p === '/api/admin/providers/provider_a' && o.method === 'PATCH');
  assert(JSON.parse(update[1].body).models.includes('new-model'), 'model update payload');

  document.querySelector('[data-page="credentials"]').click(); await pause();
  assert(document.querySelectorAll('#keyContent tbody tr').length === 12, 'pagination');
  document.getElementById('keyNext').click();
  assert(document.querySelectorAll('#keyContent tbody tr').length === 12, 'next page');
  document.getElementById('keySearch').value = 'Key 24';
  document.getElementById('keySearch').dispatchEvent(new Event('input'));
  assert(document.querySelectorAll('#keyContent tbody tr').length === 1, 'search');
  document.getElementById('addBtn').click();
  assert(document.getElementById('keyProvider').options.length === 2, 'provider select');
  document.getElementById('keyProvider').value = 'provider_b';
  document.getElementById('keyProvider').dispatchEvent(new Event('change'));
  assert(document.getElementById('keyBaseURL').disabled, 'shared URL field disabled');
  document.getElementById('keyName').value = 'New key';
  document.getElementById('keyValue').value = 'sk-fixture-only';
  document.getElementById('keyProxyRoute').value = 'proxy_1';
  document.getElementById('addForm').dispatchEvent(new Event('submit', {cancelable:true})); await pause();
  const create = requests.find(([p,o]) => p === '/api/admin/keys' && o.method === 'POST');
  const policy = JSON.parse(create[1].body).policy;
  assert(policy.provider_id === 'provider_b', 'key provider reference');
  assert(policy.proxy_mode === 'fixed' && policy.proxy_id === 'proxy_1', 'network binding');
  assert(document.getElementById('keyValue').value === '', 'key field cleared');

  document.querySelector('[data-edit-key="key_24"]').click();
  assert(document.getElementById('editKeyDialog').open, 'credential editor');
  assert(document.getElementById('editKeyValue').value === '', 'old key must not be revealed');
  document.getElementById('editKeyName').value = 'Renamed key';
  document.getElementById('editKeyValue').value = 'sk-replacement-fixture';
  document.getElementById('editKeyForm').dispatchEvent(new Event('submit', {cancelable:true})); await pause();
  const edited = requests.find(([p,o]) => p === '/api/admin/keys/key_24' && o.method === 'PATCH');
  assert(JSON.parse(edited[1].body).key === 'sk-replacement-fixture', 'replacement payload');
  assert(document.getElementById('editKeyValue').value === '', 'replacement field cleared');

  document.querySelector('[data-page="proxies"]').click(); await pause();
  assert(document.querySelectorAll('#proxyContent tbody tr').length === 1, 'proxy table');
  document.getElementById('addProxyBtn').click();
  document.getElementById('proxyName').value = 'New route';
  document.getElementById('proxyURL').value = 'socks5://fixture.example:1080';
  document.getElementById('proxyUsername').value = 'fixture-user';
  document.getElementById('proxyPassword').value = 'fixture-password';
  document.getElementById('proxyForm').dispatchEvent(new Event('submit', {cancelable:true})); await pause();
  assert(requests.some(([p,o]) => p === '/api/admin/network-proxies' && o.method === 'POST'), 'proxy creation');
  assert(document.getElementById('proxyPassword').value === '', 'proxy password cleared');
  assert(!requests.some(([p]) => p.includes('/logs')), 'hidden events fetched');
  document.querySelector('[data-page="providers"]').click(); await pause();
  assert(document.documentElement.scrollWidth <= innerWidth, 'page horizontal overflow');
  document.querySelector('[data-page="logs"]').click(); await pause();
  assert(document.querySelectorAll('.log-entry').length === 4, 'background hidden by default');
  assert(document.getElementById('logList').textContent.includes('Outbound EU'), 'route metadata');
  assert(!document.getElementById('logList').querySelector('img') && !window.fixtureXss, 'log HTML escaped');
  document.getElementById('logLevel').value = 'problems';
  document.getElementById('logLevel').dispatchEvent(new Event('change'));
  assert(document.querySelectorAll('.log-entry').length === 2, 'problem filter');
  document.getElementById('logLevel').value = '';
  document.getElementById('logSearch').value = 'Provider B';
  document.getElementById('logSearch').dispatchEvent(new Event('input'));
  assert(document.querySelectorAll('.log-entry').length === 1, 'log search');
  document.querySelector('[data-log-request="req-b"]').click();
  assert(document.querySelectorAll('.log-entry').length === 1, 'request grouping');
  document.getElementById('logClearRequest').click();
  assert(document.querySelectorAll('.log-entry').length === 6, 'background events toggle');
  document.querySelector('.log-entry').open = true;
  const opened = document.querySelector('.log-entry').dataset.seq;
  document.getElementById('logPause').click();
  assert(document.querySelector('[data-seq="'+opened+'"]').open, 'details stay expanded');
  document.getElementById('logPause').click(); await pause();
  journalInstance = 'process-2';
  document.getElementById('refreshBtn').click(); await pause();
  assert(document.getElementById('logState').textContent.includes('сменился'), 'rolling deploy cursor recovery');
  assert(document.querySelectorAll('.log-entry').length === 6, 'new process events visible');
  assert(document.documentElement.scrollWidth <= innerWidth, 'journal responsive layout');
  document.getElementById('lockBtn').click(); await pause();
  assert(!document.getElementById('login').classList.contains('hidden'), 'logout shows login');
  document.getElementById('adminName').value='owner';document.getElementById('adminPassword').value='fixture-password-long';
  document.getElementById('loginForm').dispatchEvent(new Event('submit',{cancelable:true}));await pause();
  assert(document.getElementById('login').classList.contains('hidden'), 'password login');
  const login=requests.filter(([p])=>p==='/api/admin/login').at(-1);
  assert(JSON.parse(login[1].body).browser===true && JSON.parse(login[1].body).remember===true,'remembered cookie login');
  assert(document.getElementById('adminPassword').value==='','login password cleared');
  assert(sessionStorage.getItem('ar_admin_session')===null,'no session bearer in browser storage');
  document.getElementById('adminAccessBtn').click();
  document.getElementById('currentAdminSecret').value='fixture-password-long';
  document.getElementById('newAdminPassword').value='new-fixture-password-long';document.getElementById('confirmAdminPassword').value='different';
  document.getElementById('adminPasswordForm').dispatchEvent(new Event('submit',{cancelable:true}));
  assert(document.getElementById('passwordSetupError').textContent.includes('не совпадают'),'password confirmation');
  document.getElementById('confirmAdminPassword').value='new-fixture-password-long';document.getElementById('adminPasswordForm').dispatchEvent(new Event('submit',{cancelable:true}));await pause();
  assert(requests.some(([p])=>p==='/api/admin/password'),'password settings submission');
  const mutation=requests.filter(([p])=>p==='/api/admin/password').at(-1);
  assert(mutation[1].headers['X-Admin-CSRF']==='1' && !mutation[1].headers['X-Admin-Session'],'cookie mutation CSRF, no JS bearer');
  document.getElementById('lockBtn').click();await pause();document.getElementById('tokenTab').click();
  assert(document.getElementById('adminPassword').disabled && !document.getElementById('adminToken').disabled,'token tab disables hidden password');
  document.getElementById('adminToken').value='fixture-admin-token';document.getElementById('initialPassword').value='bootstrap-fixture-password-long';document.getElementById('loginForm').dispatchEvent(new Event('submit',{cancelable:true}));await pause();
  assert(JSON.parse(requests.filter(([p])=>p==='/api/admin/login').at(-1)[1].body).new_password==='bootstrap-fixture-password-long','first-login password setup');
  assert(document.getElementById('adminToken').value==='','token cleared');
  document.querySelector('[data-page="overview"]').click();await pause();document.getElementById('modeButton').click();
  assert(document.getElementById('modeButton').getAttribute('aria-expanded')==='true','dropdown arrow state');
  assert(getComputedStyle(document.querySelector('#modeButton .chevron')).borderRadius==='7px','styled dropdown arrow');
  document.body.dataset.smokeResult = 'passed';
 } catch (error) {
  document.body.dataset.smokeResult = 'failed: ' + error.message;
 }
}

let html = fs.readFileSync(path.join(__dirname, '../internal/app/assets/admin.html'), 'utf8');
const appScript = html.match(/<script>([\s\S]*?)<\/script>/)[1];
new vm.Script(appScript);
new vm.Script(fixture);
new vm.Script(`(${smoke.toString()})()`);
html = html.replace('  <script>', `<script>${fixture}</script>  <script>`);
html = html.replace('</body>', `<script>window.addEventListener('load', ${smoke.toString()});</script></body>`);
const fixturePath = path.resolve(output, 'admin-smoke.html');
fs.writeFileSync(fixturePath, html);
for (const width of [1280, 390]) {
 const result = spawnSync(chrome, [
  '--headless=new', '--disable-gpu', '--no-first-run', '--disable-background-networking',
  '--disable-extensions', '--disable-sync', '--no-default-browser-check',
  `--user-data-dir=${path.resolve(output, 'chrome-'+width)}`,
  '--virtual-time-budget=8000', `--window-size=${width},1000`,
  `--screenshot=${path.resolve(output, 'admin-'+width+'.png')}`, '--dump-dom',
  pathToFileURL(fixturePath).href,
 ], {encoding:'utf8', timeout:45000, maxBuffer:8*1024*1024});
 fs.writeFileSync(path.join(output, 'admin-dom-'+width+'.html'), result.stdout || '');
 const outcome = (result.stdout || '').match(/data-smoke-result="([^"]*)"/);
 const runtimeError = (result.stdout || '').match(/data-smoke-error="([^"]*)"/);
 if (result.error || !outcome || outcome[1] !== 'passed' || runtimeError) {
  throw Error(`Chrome ${width}: ${result.error || (runtimeError && runtimeError[1]) || (outcome && outcome[1]) || 'smoke result missing'}`);
 }
 console.log(`Chrome ${width}px: provider models, credential editing, proxies, logs, password login and dropdown styling passed`);
}
