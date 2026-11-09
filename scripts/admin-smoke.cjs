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
const providers = [
 {id:'provider_a', name:'Provider A', base_url:'https://api-a.example/v1', api_protocol:'chat-completions', spoof_profile:'generic', enabled:true, models:['model-a','model-shared'], keys:2},
 {id:'provider_b', name:'Provider B', base_url:'https://api-b.example/api/v1', api_protocol:'responses', spoof_profile:'generic', enabled:true, models:['model-b','model-shared'], keys:1},
];
const keys = Array.from({length:25}, (_,i) => ({id:'key_'+i, name:'Key '+i, provider_id:'provider_a', provider_name:'Provider A', base_url:providers[0].base_url, api_protocol:'chat-completions', proxy_mode:'auto', proxy_id:'proxy_1', enabled:true, mask:'sk-masked', uses:i, failures:0, models:['model-a']}));
const proxies = [{id:'proxy_1', name:'Outbound EU', url:'socks5://proxy.example:1080', enabled:true, has_auth:true, assigned_keys:25}];
window.confirm = () => true;
window.prompt = () => 'https://probe.example';
window.addEventListener('error', e => document.body.dataset.smokeError = e.message);
window.fetch = async (url, options = {}) => {
 requests.push([url, options]);
 const status = {upstream:'https://agentrouter.org', admin:{role:'admin'}, store:{ready:true, available:25, total:25}, selection_mode:'pool-only', network_proxy_pool:true};
 let data = {};
 if (url.includes('/status')) data = status;
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
 console.log(`Chrome ${width}px: provider models, key selection, proxies, tabs and pagination passed`);
}
