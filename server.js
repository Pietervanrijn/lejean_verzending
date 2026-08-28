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
return { ...order, _klant: klant, _ordNummer: ordNummer, _shippingMethod: shippingMethod, _isPickup: isPickup, _printStatus: printStatus, _orderStatus: orderStatus, itemCount: summary.itemCount, quantityOrdered: summary.quantityOrdered };
});
return enriched;
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

app.post('/api/verzend-print-count', (req, res) => {
const { shippingMethod } = req.body || {};
if (!shippingMethod) return res.status(400).json({ error: 'shippingMethod verplicht' });
const current = (verzendCountStore[shippingMethod] || 0) + 1;
verzendCountStore[shippingMethod] = current;
saveVerzendCounts(verzendCountStore);
res.json({ ok: true, count: current });
});

app.listen(PORT, () => console.log('LJ Verzending running on port ' + PORT));
