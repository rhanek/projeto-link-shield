// ■■ Seletores: pegamos os elementos do HTML uma única vez ■■
const urlInput = document.getElementById('urlInput');
const checkBtn = document.getElementById('checkBtn');
const loadingEl = document.getElementById('loading');
const resultEl = document.getElementById('result');
const resultIcon = document.getElementById('resultIcon');
const resultTitle = document.getElementById('resultTitle');
const resultUrl = document.getElementById('resultUrl');
const scoreNum = document.getElementById('scoreNum');
const scoreBar = document.getElementById('scoreBar');
const checksList = document.getElementById('checksList');
const exportBtn = document.getElementById('exportBtn');
const historySection = document.getElementById('historySection');
const historyList = document.getElementById('historyList');
const clearHistory = document.getElementById('clearHistory');
// ■■ Sua chave da API (gratuita) — veja o Passo 5 ■■
const API_KEY = 'SUA_CHAVE_AQUI';
const SAFE_BROWSING_URL =
`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`;
// ■■ Guardamos o último resultado para o botão de exportar ■■
let lastResult = null;
// ■■ Eventos ■■
checkBtn.addEventListener('click', handleCheck);
urlInput.addEventListener('keydown', (e) => {
if (e.key === 'Enter') handleCheck();
});
exportBtn.addEventListener('click', exportReport);
clearHistory.addEventListener('click', clearHistoryFn);
// ■■ Função principal: orquestra tudo ■■
async function handleCheck() {
const raw = urlInput.value.trim();
if (!raw) { shake(urlInput); return; }
const url = normalizeUrl(raw);
if (!isValidUrl(url)) { showError('URL inválida. Inclua http:// ou https://');
return; }

showLoading(true);
hideResult();
// Rodamos todas as verificações em paralelo
const [localChecks, safeBrowsingResult] = await Promise.all([
runLocalChecks(url),
checkSafeBrowsing(url),
]);
const allChecks = [...localChecks, safeBrowsingResult];
const score = calcScore(allChecks);
lastResult = { url, score, checks: allChecks, date: new
Date().toLocaleString('pt-BR') };
showResult(lastResult);
saveHistory(lastResult);
renderHistory();
showLoading(false);
}
// ■■ Normalizar URL: adiciona https:// se o usuário não colocou ■■
function normalizeUrl(raw) {
if (!raw.startsWith('http://') && !raw.startsWith('https://')) {
return 'https://' + raw;
}
return raw;
}
// ■■ Validar URL com o construtor nativo do JS ■■
function isValidUrl(url) {
try { new URL(url); return true; }
catch { return false; }
}
// ■■ Verificações locais (sem API, i

function checkHttps(url) {
const ok = url.startsWith('https://');
return {
label: ok ? 'HTTPS ativo' : 'Sem HTTPS',
desc: ok ? 'Conexão criptografada — dados protegidos em trânsito.'
: 'Site sem criptografia. Evite inserir dados pessoais.',
pass: ok,
weight: 30,
};
}
function checkIpAddress(hostname) {
// Regex que detecta endereço IP no lugar de domínio
const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
return {
label: isIp ? 'IP no lugar de domínio' : 'Domínio normal',
desc: isIp ? 'Sites legítimos usam nomes de domínio, não IPs.'
: 'Nenhum endereço IP suspeito detectado.',
pass: !isIp,
weight: 20,
};
}
function checkSuspiciousKeywords(hostname) {
const keywords = ['paypal','bank','secure','login','verify','account',
'update','confirm','bitcoin','crypto','prize','free'];
const found = keywords.filter(k => hostname.includes(k));
return {
label: found.length ? `Palavras suspeitas: ${found.join(', ')}` : 'Sem palavrassuspeitas',
desc: found.length ? 'Phishing frequentemente usa essas palavras para enganar.'
: 'Nenhuma palavra-chave de phishing detectada.',
pass: found.length === 0,
weight: 20,
};
}
function checkExcessiveHyphens(hostname) {
const hyphens = (hostname.match(/-/g) || []).length;
const ok = hyphens <= 2;
return {
label: ok ? 'Poucos hífens no domínio' : `Excesso de hífens (${hyphens})`,
desc: ok ? 'Domínios com poucos hífens tendem a ser legítimos.'
: 'Domínios com muitos hífens são comuns em sites fraudulentos.',
pass: ok,
weight: 10,
};
}
function checkSubdomainDepth(hostname) {
const depth = hostname.split('.').length;
const ok = depth <= 3;
return {
label: ok ? 'Profundidade de subdomínio normal' : 'Muitos subdomínios',
desc: ok ? 'Estrutura de URL dentro do padrão esperado.'
: 'ex: login.banco.fake.com — subdomínios em excesso são suspeitos.',
pass: ok,
weight: 10,
};
}
function checkLongUrl(url) {
const ok = url.length <= 200;
return {
label: ok ? 'URL com tamanho normal' : 'URL muito longa',
desc: ok ? 'Tamanho de URL dentro do esperado.'
: 'URLs excessivamente longas podem esconder destinos maliciosos.',
pass: ok,
weight: 10,
};
}

// ■■ Verificação via Google Safe Browsing API ■■
async function checkSafeBrowsing(url) {
if (API_KEY === 'SUA_CHAVE_AQUI') {
return { label: 'Google Safe Browsing', desc: 'Configure sua API key noscript.js', pass: null, weight: 0 };
}

try {
const body = {
client: { clientId: 'link-shield', clientVersion: '1.0' },
threatInfo: {
threatTypes: ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],
platformTypes: ['ANY_PLATFORM'],
threatEntryTypes: ['URL'],
threatEntries: [{ url }],
},
};
const res = await fetch(SAFE_BROWSING_URL, { method: 'POST', body:
JSON.stringify(body) });
const data = await res.json();
const safe = !data.matches || data.matches.length === 0;
return {
label: safe ? 'Google Safe Browsing: Seguro' : '■ Detectado pelo Google comoPERIGOSO',
desc: safe ? 'Este URL não está na lista negra do Google.'
: 'Google sinalizou este site como malicioso!',
pass: safe,
weight: 40,
};
} catch {
return { label: 'Google Safe Browsing', desc: 'Erro ao consultar API.', pass:
null, weight: 0 };
}
}
// ■■ Calcular pontuação 0–100 ■■
function calcScore(checks) {
const valid = checks.filter(c => c.pass !== null);
const total = valid.reduce((sum, c) => sum + c.weight, 0);
const earned = valid.filter(c => c.pass).reduce((sum, c) => sum + c.weight, 0);
return total === 0 ? 0 : Math.round((earned / total) * 100);
}
// ■■ Mostrar resultado na tela ■■
function showResult({ url, score, checks }) {
const level = score >= 75 ? 'safe' : score >= 45 ? 'warn' : 'danger';
const icons = { safe: '■', warn: '■■', danger: '■' };
const titles = { safe: 'Link Provavelmente Seguro', warn: 'Atenção — Verifique comCuidado', danger: 'Link Suspeito — Evite Clicar' };
const barColors = { safe: '#3FB950', warn: '#D29922', danger: '#F85149' };
resultIcon.textContent = icons[level];
resultTitle.textContent = titles[level];
resultUrl.textContent = url;
scoreNum.textContent = `${score}/100`;
scoreBar.style.width = `${score}%`;
scoreBar.style.background = barColors[level];
checksList.innerHTML = checks.map(c => `
<li class='check-item'>
<span class='icon'>${c.pass === null ? '■' : c.pass ? '■' : '■'}</span>
<div><div class='label'>${c.label}</div><div class='desc'>${c.desc}</div></div>
</li> `).join('');
resultEl.classList.remove('hidden');
requestAnimationFrame(() => { scoreBar.style.width = `${score}%`; });
}
// ■■ Salvar e carregar histórico do localStorage ■■
function saveHistory(result) {
const history = getHistory();
history.unshift({ url: result.url, score: result.score, date: result.date });
const trimmed = history.slice(0, 10);
localStorage.setItem('linkShieldHistory', JSON.stringify(trimmed));
}
function getHistory() {
try { return JSON.parse(localStorage.getItem('linkShieldHistory') || '[]'); }
catch { return []; }
}
function renderHistory() {
const history = getHistory();
if (!history.length) { historySection.classList.add('hidden'); return; }
historySection.classList.remove('hidden');
historyList.innerHTML = history.map(item => `
<li class='history-item' onclick="urlInput.value='${item.url}';handleCheck()">
<span class='url-text'>${item.url}</span>
<span style='color:${item.score>=75?'#3FB950':item.score>=45?'#D29922':'#F85149'};
font-weight:700'>
${item.score}/100
</span>
</li>
`).join('');
}
function clearHistoryFn() {
localStorage.removeItem('linkShieldHistory');
historySection.classList.add('hidden');
}
// ■■ Exportar relatório como .txt ■■
function exportReport() {
if (!lastResult) return;
const { url, score, checks, date } = lastResult;
const lines = [
'=== RELATÓRIO LINK SHIELD ===',
`Data: ${date}`,
`URL analisada: ${url}`,`Pontuação de segurança: ${score}/100`,
'',
'--- VERIFICAÇÕES ---',
...checks.map(c => `${c.pass ? '[OK]' : '[FALHA]'} ${c.label}: ${c.desc}`),
'',
'Gerado por Link Shield',
];
const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
const a = document.createElement('a');
a.href = URL.createObjectURL(blob);
a.download = `relatorio-${Date.now()}.txt`;
a.click();
}
// ■■ Funções auxiliares de UI ■■
function showLoading(show) { loadingEl.classList.toggle('hidden', !show); }
function hideResult() { resultEl.classList.add('hidden'); }
function showError(msg) { alert(msg); }
function shake(el) {
el.style.animation = 'none';
el.offsetHeight; // força reflow
el.style.animation = 'shake 0.4s ease';
}
// ■■ Inicialização: carrega histórico ao abrir a página ■■
renderHistory();
