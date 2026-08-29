require('dotenv').config();
const express = require('express');
const axios = require('axios');
const fs = require('fs');
const crypto = require('crypto');
const app = express();
app.use(express.json());
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.LIGHTSPEED_API_KEY;
const API_SECRET = process.env.LIGHTSPEED_API_SECRET;
const SHOP = 'nl';

// --- Trunkrs-labelintegratie ---------------------------------------------
// TRUNKRS_BASE_URL staat standaard op productie, maar is overschrijfbaar
// (bv. naar de staging-omgeving van Trunkrs) zonder codewijziging.
const TRUNKRS_API_KEY = process.env.TRUNKRS_API_KEY;
const TRUNKRS_BASE_URL = process.env.TRUNKRS_BASE_URL || 'https://api.trunkrs.nl/api/v2';
const trunkrsHeaders = () => ({ 'x-api-key': TRUNKRS_API_KEY, 'Content-Type': 'application/json' });

// --- Toegangsbeveiliging -----------------------------------------------
// Deze app toonde tot nu toe klantgegevens en liet acties (o.a. het
// versturen van "klaar om op te halen"-mails) uitvoeren zonder enige
// login. Onderstaande middleware sluit de hele app af met HTTP Basic Auth.
// Vereist APP_USERNAME + APP_PASSWORD als environment variabelen (in
// Railway: Variables-tab). Zonder deze variabelen weigert de server elk
// verzoek in plaats van open te blijven staan (fail closed).
const APP_USERNAME = process.env.APP_USERNAME;
const APP_PASSWORD = process.env.APP_PASSWORD;

function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

app.use((req, res, next) => {
  if (!APP_USERNAME || !APP_PASSWORD) {
    console.error('APP_USERNAME/APP_PASSWORD zijn niet ingesteld: alle verzoeken worden geweigerd. Zet deze env vars in Railway.');
    return res.status(503).send('Server niet geconfigureerd: ontbrekende inloggegevens.');
  }
  const header = req.headers.authorization || '';
  const [scheme, encoded] = header.split(' ');
  if (scheme === 'Basic' && encoded) {
    const decoded = Buffer.from(encoded, 'base64').toString('utf8');
    const sep = decoded.indexOf(':');
    const user = sep >= 0 ? decoded.slice(0, sep) : decoded;
    const pass = sep >= 0 ? decoded.slice(sep + 1) : '';
    if (safeEqual(user, APP_USERNAME) && safeEqual(pass, APP_PASSWORD)) {
      return next();
    }
  }
  res.set('WWW-Authenticate', 'Basic realm="LJ Verzending"');
  return res.status(401).send('Inloggen vereist.');
});
// -------------------------------------------------------------------------

const getAuth = () => Buffer.from(API_KEY + ':' + API_SECRET).toString('base64');
const apiHeaders = () => ({ Authorization: 'Basic ' + getAuth() });

// Opslaglocatie voor de status-bestanden. Standaard naast de code (net als
// voorheen), maar via DATA_DIR is dit te verplaatsen naar een gekoppeld
// Railway Volume zodat de data een redeploy overleeft.
const DATA_DIR = process.env.DATA_DIR || __dirname;
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) { /* bestaat al of geen rechten, negeren */ }

const PRINT_STATUS_FILE = DATA_DIR + '/print-status.json';
function loadPrintStatus() {
  try { return JSON.parse(fs.readFileSync(PRINT_STATUS_FILE, 'utf8')); } catch(e) { return {}; }
}
function savePrintStatus(data) {
  try { fs.writeFileSync(PRINT_STATUS_FILE, JSON.stringify(data)); } catch(e) { console.error('savePrintStatus error:', e.message); }
}
let printStatusStore = loadPrintStatus();

const ORDER_STATUS_FILE = DATA_DIR + '/order-status.json';
function loadOrderStatus() {
try { return JSON.parse(fs.readFileSync(ORDER_STATUS_FILE, 'utf8')); } catch(e) { return {}; }
}
function saveOrderStatus(data) {
try { fs.writeFileSync(ORDER_STATUS_FILE, JSON.stringify(data)); } catch(e) { console.error('saveOrderStatus error:', e.message); }
}
let orderStatusStore = loadOrderStatus();

const VERZEND_COUNT_FILE = DATA_DIR + '/verzend-count.json';
function loadVerzendCounts() {
try { return JSON.parse(fs.readFileSync(VERZEND_COUNT_FILE, 'utf8')); } catch(e) { return {}; }
}
function saveVerzendCounts(data) {
try { fs.writeFileSync(VERZEND_COUNT_FILE, JSON.stringify(data)); } catch(e) { console.error('saveVerzendCounts error:', e.message); }
}
let verzendCountStore = loadVerzendCounts();

// Trunkrs-labels per order (keyed op ordernummer, bv. "ORD80406"): bewaart
// trunkrsNr, het label (pdf/zpl), de gebruikte service en de laatst bekende
// status, zodat we deze na een herstart/redeploy niet kwijtraken.
const TRUNKRS_LABELS_FILE = DATA_DIR + '/trunkrs-labels.json';
function loadTrunkrsLabels() {
try { return JSON.parse(fs.readFileSync(TRUNKRS_LABELS_FILE, 'utf8')); } catch(e) { return {}; }
}
function saveTrunkrsLabels(data) {
try { fs.writeFileSync(TRUNKRS_LABELS_FILE, JSON.stringify(data)); } catch(e) { console.error('saveTrunkrsLabels error:', e.message); }
}
let trunkrsLabelsStore = loadTrunkrsLabels();

// Voert fn uit over items met maximaal `limit` gelijktijdige API-calls,
// in plaats van alles in één keer (voorkomt rate-limit fouten bij Lightspeed
// wanneer er veel orders tegelijk verrijkt moeten worden).
async function mapWithConcurrency(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const idx = next++;
      results[idx] = await fn(items[idx], idx);
    }
  }
  const workers = Array.from({ length: Math.min(limit, items.length) }, worker);
  await Promise.all(workers);
  return results;
}

async function fetchOrders() {
const statuses = ['processing_awaiting_shipment', 'processing_awaiting_pickup'];
let all = [];
for (const status of statuses) {
let page = 1, more = true;
while (more) {
try {
const r = await axios.get('https://api.webshopapp.com/' + SHOP + '/orders.json', {
headers: apiHeaders(),
params: { status: status, limit: 250, page }
});
const orders = r.data.orders || [];
all = all.concat(orders);
more = orders.length >= 250;
page++;
} catch(e) { console.error('fetchOrders error (status ' + status + '):', e.message); more = false; }
}
}
return all;
}

async function fetchOrderProductsSummary(orderId) {
try {
const r = await axios.get('https://api.webshopapp.com/' + SHOP + '/orders/' + orderId + '/products.json', { headers: apiHeaders() });
const products = r.data.orderProducts || r.data.products || [];
const itemCount = products.length;
const quantityOrdered = products.reduce(function(s,p){ return s + (p.quantityOrdered || 0); }, 0);
return { itemCount: itemCount, quantityOrdered: quantityOrdered };
} catch(e) {
console.error('fetchOrderProductsSummary error:', e.message);
return { itemCount: null, quantityOrdered: null };
}
}

async function enrichOrders(orders) {
// Voorheen werd hier gefilterd op alleen DAGBEZORGING/afhaal-orders. De tool
// (nu LJ Verzending) dekt inmiddels alle verzendmethodes, dus alle orders
// met status "klaar voor verzending"/"klaar voor afhalen" worden verrijkt
// en getoond; de verzendmethode zelf blijft gewoon zichtbaar per order.
const enriched = await mapWithConcurrency(orders, 5, async (order) => {
const firstName = order.firstname || '';
const middleName = order.middlename || '';
const lastName = order.lastname || '';
const klant = [firstName, middleName, lastName].filter(Boolean).join(' ') || order.email || 'Onbekend';
let shippingMethod = order.shipmentTitle || order.shippingMethod || 'Onbekend';
const orderStr = JSON.stringify(order);
const dagMatch = orderStr.match(/"([^"]*[Dd][Aa][Gg][Bb][Ee][Zz][Oo][Rr][Gg][Ii][Nn][Gg][^"]*)"/);
if (dagMatch) shippingMethod = dagMatch[1];
const pickupMatch = orderStr.match(/"([^"]*[Aa][Ff][Hh][Aa][Ll][Ee][Nn]\s+[Bb][Ii][Jj]\s+[Ll][Ee][Jj][Ee][Aa][Nn][^"]*)"/);
if (pickupMatch) shippingMethod = pickupMatch[1];
const isPickup = !!(order.shipmentIsPickup || /AFHALEN BIJ LEJEAN/i.test(shippingMethod));
const ordNummer = String(order.number || '').toUpperCase().startsWith('ORD') ? String(order.number) : 'ORD' + order.number;
const printStatus = printStatusStore[String(order.number)] || 'geen';
const orderStatus = orderStatusStore[String(order.number)] || 'inkomend';
const summary = await fetchOrderProductsSummary(order.id);
const trunkrsLabel = trunkrsLabelsStore[String(order.number)] || null;
return { ...order, _klant: klant, _ordNummer: ordNummer, _shippingMethod: shippingMethod, _isPickup: isPickup, _printStatus: printStatus, _orderStatus: orderStatus, itemCount: summary.itemCount, quantityOrdered: summary.quantityOrdered, _trunkrsLabel: trunkrsLabel };
});
return enriched;
}

// --- Trunkrs: houdbaar/frozen-bepaling -----------------------------------
// Afspraak met Pieter (2026-08-28): artikelnummers 8000 t/m 9000 zijn
// "houdbaar". Een order is ALLEEN houdbaar (SAME_DAY) als ALLE producten in
// de order een artikelnummer in dat bereik hebben; zodra er ook maar 1
// product buiten dat bereik valt (of het artikelnummer niet numeriek is)
// wordt de veilige/conservatieve default gebruikt: SAME_DAY_FROZEN_FOOD.
// De gebruiker kan dit in de UI altijd handmatig overschrijven.
const HOUDBAAR_ARTIKEL_MIN = 8000;
const HOUDBAAR_ARTIKEL_MAX = 9000;

function isHoudbaarArticleCode(code) {
const n = parseInt(String(code == null ? '' : code).trim(), 10);
return !isNaN(n) && n >= HOUDBAAR_ARTIKEL_MIN && n <= HOUDBAAR_ARTIKEL_MAX;
}

function bepaalTrunkrsService(products) {
if (!Array.isArray(products) || products.length === 0) return 'SAME_DAY_FROZEN_FOOD';
const alleHoudbaar = products.every(function(p) {
return isHoudbaarArticleCode(p.articleCode || p.sku || p.itemNumber || p.ean || p.ean13 || p.code);
});
return alleHoudbaar ? 'SAME_DAY' : 'SAME_DAY_FROZEN_FOOD';
}

// --- Trunkrs: gewicht schatten uit producttitel ---------------------------
// Lightspeed/de webshop heeft geen apart gewichtsveld; het gewicht staat als
// vrije tekst in de producttitel, bv. "3750~3850 gram" of "2000 gram". We
// pakken de bovengrens van een range (conservatief: liever te zwaar
// ingeschat dan te licht). Trunkrs vereist een gewicht alleen bij
// BE-zendingen; voor NL laten we het weg (niet verplicht volgens de docs).
// LET OP: de eenheid ("kg" hieronder) is een aanname — nog niet bevestigd
// tegen een echte Trunkrs-response, zie project-notities.
function parseWeightGramsFromTitle(title) {
if (!title) return 0;
const m = String(title).match(/(\d+(?:[.,]\d+)?)\s*(?:~\s*(\d+(?:[.,]\d+)?))?\s*gram/i);
if (!m) return 0;
const a = parseFloat(m[1].replace(',', '.'));
const b = m[2] ? parseFloat(m[2].replace(',', '.')) : null;
return b != null ? Math.max(a, b) : a;
}

function estimateParcelWeightKg(products) {
const totalGrams = (products || []).reduce(function(sum, p) {
const title = (p.productTitle || p.title || p.fulltitle || p.name || '') + ' ' + (p.variantTitle || '');
const qty = p.quantityOrdered || p.quantity || p.amount || 1;
return sum + parseWeightGramsFromTitle(title) * qty;
}, 0);
return totalGrams > 0 ? Math.round((totalGrams / 1000) * 100) / 100 : null;
}

// --- Trunkrs: shipment-payload opbouwen -----------------------------------
function buildTrunkrsShipmentPayload(order, products, service) {
const naam = order.addressShippingName || [order.firstname, order.middlename, order.lastname].filter(Boolean).join(' ') || order._klant || order.email || '-';
const straatRegel = [order.addressShippingStreet, order.addressShippingNumber].filter(Boolean).join(' ') + (order.addressShippingExtension ? (' ' + order.addressShippingExtension) : '');
const countryCode = (order.addressShippingCountry && (order.addressShippingCountry.code || order.addressShippingCountry.code3)) || 'NL';
const parcel = {
description: 'LJ Verzending order ' + order.number,
reference: String(order.number)
};
// Trunkrs vereist 'weight' op elke parcel, niet alleen bij BE (empirisch
// vastgesteld op 2026-08-29: INVALID_REQUEST "the key 'weight' is required
// but was not present" op een NL-zending zonder gewicht). Als we niets
// kunnen schatten uit de variant-titel, nemen we een conservatieve
// minimum-waarde i.p.v. de aanvraag te laten mislukken.
const kg = estimateParcelWeightKg(products);
parcel.weight = { value: kg != null ? kg : 1, unit: 'kg' };
return {
orderReference: 'LJ-' + order.number,
recipient: {
name: naam,
emailAddress: order.email || '',
phoneNumber: order.telephone || order.addressShippingPhone || '',
address: straatRegel,
postalCode: order.addressShippingZipcode || '',
city: order.addressShippingCity || '',
country: String(countryCode).toUpperCase()
},
parcel: [parcel],
service: service
};
}

app.get('/', (req, res) => res.sendFile(__dirname + '/index.html'));

app.get('/api/orders', async (req, res) => {
try {
const orders = await fetchOrders();
const enriched = await enrichOrders(orders);
const methods = [...new Set(enriched.map(o => o._shippingMethod).filter(Boolean))].sort();
res.json({ orders: enriched, total: enriched.length, shippingMethods: methods });
} catch(e) {
console.error('API error:', e.message);
res.status(500).json({ error: e.message });
}
});

app.get('/api/orders/:id/products', async (req, res) => {
try {
const r = await axios.get('https://api.webshopapp.com/' + SHOP + '/orders/' + req.params.id + '/products.json', { headers: apiHeaders() });
const products = r.data.orderProducts || r.data.products || [];
res.json({ products, raw: Object.keys(r.data) });
} catch(e) {
console.error('order products error:', e.message);
res.status(500).json({ error: e.message });
}
});

app.post('/api/print-status', (req, res) => {
const { orderNumbers, status } = req.body || {};
if (!Array.isArray(orderNumbers) || !status) return res.status(400).json({ error: 'orderNumbers en status verplicht' });
orderNumbers.forEach(n => {
const key = String(n);
const current = printStatusStore[key] || 'geen';
if (status === 'pakbon' && current === 'beide') return;
printStatusStore[key] = status;
});
savePrintStatus(printStatusStore);
res.json({ ok: true, printStatus: printStatusStore });
});

app.post('/api/order-status', (req, res) => {
const { orderNumbers, status } = req.body || {};
const allowedStatuses = ['inkomend', 'label', 'verzonden', 'geannuleerd'];
if (!Array.isArray(orderNumbers) || !allowedStatuses.includes(status)) return res.status(400).json({ error: 'orderNumbers en een geldige status (inkomend, label, verzonden, geannuleerd) zijn verplicht' });
orderNumbers.forEach(n => {
orderStatusStore[String(n)] = status;
});
saveOrderStatus(orderStatusStore);
res.json({ ok: true, orderStatus: orderStatusStore });
});

app.post('/api/mark-ready-pickup', async (req, res) => {
const { orderIds } = req.body || {};
if (!Array.isArray(orderIds) || !orderIds.length) return res.status(400).json({ error: 'orderIds verplicht' });
const results = [];
for (const id of orderIds) {
try {
const check = await axios.get('https://api.webshopapp.com/' + SHOP + '/orders/' + id + '.json', { headers: apiHeaders() });
const already = check.data.order && check.data.order.isReadyForPickup;
if (already) { results.push({ id, skipped: true }); continue; }
// Status bijwerken naar "Klaar om opgehaald te worden" (verstuurt zelf geen mail)
await axios.put('https://api.webshopapp.com/' + SHOP + '/orders/' + id + '.json', { order: { isReadyForPickup: true } }, { headers: apiHeaders() });
// De juiste "klaar om op te halen" mail versturen via het shipment-niveau veld
const shipRes = await axios.get('https://api.webshopapp.com/' + SHOP + '/shipments.json', { headers: apiHeaders(), params: { order: id } });
const shipment = shipRes.data.shipments && shipRes.data.shipments[0];
if (shipment) {
await axios.put('https://api.webshopapp.com/' + SHOP + '/shipments/' + shipment.id + '.json', { shipment: { doNotifyReadyForPickup: true } }, { headers: apiHeaders() });
}
results.push({ id, ok: true });
} catch(e) {
console.error('mark-ready-pickup error for order ' + id + ':', e.message);
results.push({ id, ok: false, error: e.message });
}
}
res.json({ results });
});

// Beste-poging: schrijft trunkrsNr/tracking terug naar de Lightspeed-order
// (zichtbaar bij "Verzending" in de Back Office) en zet de shipment op
// "verzonden". De exacte veldnamen (status/trackingCode) zijn nog niet
// empirisch bevestigd tegen de echte Lightspeed-API (zie project-notities) —
// dit mag dus falen zonder de labelaanmaak zelf te laten mislukken; de
// aanroeper krijgt lightspeedSync:false + de foutmelding terug om dit zelf
// te kunnen controleren/corrigeren.
async function syncTrunkrsToLightspeed(orderId, trunkrsNr) {
try {
const shipRes = await axios.get('https://api.webshopapp.com/' + SHOP + '/shipments.json', { headers: apiHeaders(), params: { order: orderId } });
const shipment = shipRes.data.shipments && shipRes.data.shipments[0];
if (!shipment) return { ok: false, error: 'geen shipment gevonden voor order ' + orderId };
await axios.put('https://api.webshopapp.com/' + SHOP + '/shipments/' + shipment.id + '.json', {
shipment: { status: 'shipped', trackingCode: String(trunkrsNr) }
}, { headers: apiHeaders() });
return { ok: true };
} catch(e) {
console.error('syncTrunkrsToLightspeed error for order ' + orderId + ':', e.response ? JSON.stringify(e.response.data) : e.message);
return { ok: false, error: e.message };
}
}

app.post('/api/trunkrs/label', async (req, res) => {
if (!TRUNKRS_API_KEY) return res.status(503).json({ error: 'TRUNKRS_API_KEY is niet ingesteld (Railway env var).' });
const { orderId, serviceOverride } = req.body || {};
if (!orderId) return res.status(400).json({ error: 'orderId verplicht' });
try {
const orderRes = await axios.get('https://api.webshopapp.com/' + SHOP + '/orders/' + orderId + '.json', { headers: apiHeaders() });
const order = orderRes.data.order;
if (!order) return res.status(404).json({ error: 'Order niet gevonden' });
const productsRes = await axios.get('https://api.webshopapp.com/' + SHOP + '/orders/' + orderId + '/products.json', { headers: apiHeaders() });
const products = productsRes.data.orderProducts || productsRes.data.products || [];

const autoService = bepaalTrunkrsService(products);
const service = (serviceOverride === 'SAME_DAY' || serviceOverride === 'SAME_DAY_FROZEN_FOOD') ? serviceOverride : autoService;
const payload = buildTrunkrsShipmentPayload(order, products, service);

const trunkrsRes = await axios.post(TRUNKRS_BASE_URL + '/shipments', payload, { headers: trunkrsHeaders() });
const shipment = trunkrsRes.data.data && trunkrsRes.data.data[0] ? trunkrsRes.data.data[0] : trunkrsRes.data.data;

const orderKey = String(order.number);
trunkrsLabelsStore[orderKey] = {
trunkrsNr: shipment.trunkrsNr,
label: shipment.label,
service: service,
autoService: autoService,
serviceOverride: serviceOverride || null,
state: shipment.state,
createdAt: new Date().toISOString()
};
saveTrunkrsLabels(trunkrsLabelsStore);

// Lokaal automatisch verplaatsen naar "Labels aangemaakt"
orderStatusStore[orderKey] = 'label';
saveOrderStatus(orderStatusStore);

const lightspeedSync = await syncTrunkrsToLightspeed(orderId, shipment.trunkrsNr);

res.json({
ok: true,
trunkrsNr: shipment.trunkrsNr,
label: shipment.label,
service: service,
autoService: autoService,
lightspeedSync: lightspeedSync.ok,
lightspeedSyncError: lightspeedSync.ok ? null : lightspeedSync.error
});
} catch(e) {
const detail = e.response ? JSON.stringify(e.response.data) : e.message;
console.error('trunkrs/label error for order ' + orderId + ':', detail);
res.status(500).json({ error: 'Trunkrs-label aanmaken mislukt: ' + detail });
}
});

app.get('/api/trunkrs/labels', (req, res) => {
res.json({ labels: trunkrsLabelsStore });
});

app.post('/api/verzend-print-count', (req, res) => {
const { shippingMethod } = req.body || {};
if (!shippingMethod) return res.status(400).json({ error: 'shippingMethod verplicht' });
const current = (verzendCountStore[shippingMethod] || 0) + 1;
verzendCountStore[shippingMethod] = current;
saveVerzendCounts(verzendCountStore);
res.json({ ok: true, count: current });
});

app.listen(PORT, () => console.log('LJ Verzending running on port ' + PORT));
