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

// Volledige, officiële lijst van Trunkrs state.code-waarden (uit hun v2 API-
// schema, https://github.com/Trunkrs/v2-api-documentation) - ter referentie
// en voor de auto-transitie hieronder. DATA_RECEIVED/DATA_PROCESSED zijn
// zuiver administratief (label aangemaakt, nog niets fysiek gebeurd).
// SHIPMENT_SORTED is de eerste fysieke scan: de zending is binnengekomen en
// gesorteerd op het Trunkrs-warehouse. Alles daarna (sub-depot, bij de
// bezorger, bezorgd) impliceert dat die eerste warehouse-scan al heeft
// plaatsgevonden. Op verzoek van Pieter (2026-08-29) is dít het moment
// waarop een order automatisch van "Gecreëerde labels" naar "Verzonden"
// overgaat.
const TRUNKRS_WAREHOUSE_SCAN_OR_LATER_CODES = [
  'SHIPMENT_SORTED',
  'SHIPMENT_SORTED_AT_SUB_DEPOT',
  'SHIPMENT_ACCEPTED_BY_DRIVER',
  'SHIPMENT_DELIVERED',
  'SHIPMENT_DELIVERED_TO_NEIGHBOR',
  'SHIPMENT_NOT_DELIVERED'
];
// Uitzonderingscodes worden bewust NIET automatisch als "verzonden" geteld:
// EXCEPTION_SHIPMENT_NOT_ARRIVED betekent expliciet dat de warehouse-scan nog
// niet heeft plaatsgevonden, en de overige EXCEPTION_*/RETURN_*-codes vragen
// om aparte aandacht i.p.v. stilzwijgend als "verzonden" te tellen. Zulke
// orders blijven in "Gecreëerde labels" staan, met hun eigen statusbadge.

// --- Pack & Go: aparte PIN-beveiliging (wie heeft een label geprint?) ----
// Op verzoek van Pieter (2026-08-29): geen volledige gebruikersaccounts,
// alleen een lichte PIN-check specifiek voor het Pack & Go-scherm, zodat
// duidelijk is wie een label heeft aangemaakt/geprint. Medewerkers (naam +
// PIN) worden beheerd via het instellingenpaneel in de app zelf (rechter
// zijbalk, tandwiel-icoon) en persistent opgeslagen op DATA_DIR — zie
// packgoMedewerkersStore verderop, samen met de andere status-bestanden.

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

// De print-agent (het kleine programmaatje dat op elk inpakstation draait,
// zie print-stations verderop) heeft geen kantoor-Basic-Auth-wachtwoord -
// die draait onbeheerd op een gedeelde pc. Elk station krijgt in plaats
// daarvan een eigen smal token (alleen bruikbaar voor zijn eigen printjobs).
// Daarom slaan deze paden de Basic Auth hieronder over en hebben ze hun
// eigen requirePrintAgentToken-check (zie bij de print-station routes).
app.use((req, res, next) => {
  if (req.path.indexOf('/api/print-agent/') === 0) return next();
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

// Koppelt ordernummer -> Lightspeed-order-id (bv. "80442" -> 12345678).
// Nodig om orders die lokaal als "label"/"verzonden"/"geannuleerd" staan
// gericht te kunnen opzoeken zodra ze buiten fetchOrders()'s statusfilter
// vallen (zie fetchLocallyTrackedMissingOrders hieronder).
const ORDER_ID_MAP_FILE = DATA_DIR + '/order-id-map.json';
function loadOrderIdMap() {
try { return JSON.parse(fs.readFileSync(ORDER_ID_MAP_FILE, 'utf8')); } catch(e) { return {}; }
}
function saveOrderIdMap(data) {
try { fs.writeFileSync(ORDER_ID_MAP_FILE, JSON.stringify(data)); } catch(e) { console.error('saveOrderIdMap error:', e.message); }
}
let orderIdMapStore = loadOrderIdMap();

// Medewerkers (naam -> PIN) voor de Pack & Go PIN-check, beheerd via het
// instellingenpaneel (rechter zijbalk) i.p.v. een Railway env var die elke
// keer handmatig aangepast moet worden. Backwards compatible: als er nog
// geen opgeslagen medewerkers zijn maar wel een (oudere) Railway env var
// PACKGO_MEDEWERKERS staat ingesteld ("Naam1:1234,Naam2:5678"), wordt die
// eenmalig ingelezen als startpunt en meteen weggeschreven naar het bestand.
const PACKGO_MEDEWERKERS_FILE = DATA_DIR + '/packgo-medewerkers.json';
function loadPackgoMedewerkers() {
  try { return JSON.parse(fs.readFileSync(PACKGO_MEDEWERKERS_FILE, 'utf8')); } catch(e) { return null; }
}
function savePackgoMedewerkers(data) {
  try { fs.writeFileSync(PACKGO_MEDEWERKERS_FILE, JSON.stringify(data)); } catch(e) { console.error('savePackgoMedewerkers error:', e.message); }
}
// --- Afdrukopties: inpakstations + print-agent ---------------------------
// Elk inpakstation heeft zijn eigen (netwerk)labelprinter (Zebra/Intermec,
// aangesproken via IP - geen normale Windows/Mac-printerinstallatie). Omdat
// die printers alleen bereikbaar zijn vanaf het eigen lokale netwerk, en
// Railway in de cloud draait, kan de app een label niet rechtstreeks naar
// zo'n printer sturen. Elk station draait daarom een klein, zelf-
// gegenereerd Node-scriptje (de "print-agent", te downloaden vanuit het
// instellingenpaneel) dat naar deze app toe polt, en de rauwe ZPL-labeldata
// (die Trunkrs al meelevert naast de PDF, zie trunkrsLabelsStore) via een
// kale TCP-verbinding (poort 9100, standaard voor labelprinters) naar zijn
// eigen printer-IP doorstuurt. Dit is bewust dezelfde soort opzet als
// Sendcloud's eigen download-print-app.
const PRINT_STATIONS_FILE = DATA_DIR + '/print-stations.json';
function loadPrintStations() {
  try { return JSON.parse(fs.readFileSync(PRINT_STATIONS_FILE, 'utf8')); } catch(e) { return {}; }
}
function savePrintStations(data) {
  try { fs.writeFileSync(PRINT_STATIONS_FILE, JSON.stringify(data)); } catch(e) { console.error('savePrintStations error:', e.message); }
}
let printStationsStore = loadPrintStations();

const PRINT_JOBS_FILE = DATA_DIR + '/print-jobs.json';
function loadPrintJobs() {
  try { return JSON.parse(fs.readFileSync(PRINT_JOBS_FILE, 'utf8')); } catch(e) { return {}; }
}
function savePrintJobs(data) {
  try { fs.writeFileSync(PRINT_JOBS_FILE, JSON.stringify(data)); } catch(e) { console.error('savePrintJobs error:', e.message); }
}
let printJobsStore = loadPrintJobs();

// Zoekt het station dat bij dit Bearer-token hoort. Losse, lichte check t.o.v.
// de kantoor-Basic-Auth hierboven - een print-agent-token mag alleen zijn
// eigen printjobs ophalen/afvinken, verder niets in de app.
function findStationByToken(token) {
  if (!token) return null;
  for (const id in printStationsStore) {
    if (safeEqual(printStationsStore[id].token, token)) return printStationsStore[id];
  }
  return null;
}
function requirePrintAgentToken(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');
  const station = scheme === 'Bearer' && token ? findStationByToken(token) : null;
  if (!station) return res.status(401).json({ error: 'Onbekend of ongeldig station-token.' });
  req.printStation = station;
  next();
}

let packgoMedewerkersStore = loadPackgoMedewerkers();
if (!packgoMedewerkersStore) {
  packgoMedewerkersStore = {};
  (process.env.PACKGO_MEDEWERKERS || '').split(',').map(function(s){ return s.trim(); }).filter(Boolean).forEach(function(pair) {
    const idx = pair.indexOf(':');
    if (idx === -1) return;
    const naam = pair.slice(0, idx).trim();
    const pin = pair.slice(idx + 1).trim();
    if (naam && pin) packgoMedewerkersStore[naam] = pin;
  });
  savePackgoMedewerkers(packgoMedewerkersStore);
}

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

// Onthoud ordernummer -> order-id voor alles wat we nu zien, zodat we
// deze orders later (als ze uit bovenstaande statussen vallen) alsnog
// gericht kunnen opzoeken.
let idMapChanged = false;
for (const o of all) {
const key = String(o.number);
if (orderIdMapStore[key] !== o.id) { orderIdMapStore[key] = o.id; idMapChanged = true; }
}
if (idMapChanged) saveOrderIdMap(orderIdMapStore);

// Bug (ontdekt 2026-08-29): zodra een Trunkrs-label wordt aangemaakt, zet
// syncTrunkrsToLightspeed() de bijbehorende shipment op status 'shipped',
// waardoor de order zelf bij Lightspeed ook buiten bovenstaande twee
// statussen valt en dus helemaal uit fetchOrders() (en dus alle tabs)
// verdwijnt — inclusief "Gecreëerde labels"/"Verzonden", waar hij juist
// zichtbaar zou moeten blijven. Orders die lokaal als 'label', 'verzonden'
// of 'geannuleerd' gemarkeerd staan, of waarvoor een Trunkrs-label bestaat,
// halen we daarom hieronder alsnog gericht op via hun bekende order-id.
const extra = await fetchLocallyTrackedMissingOrders(all);
return all.concat(extra);
}

async function fetchLocallyTrackedMissingOrders(alreadyFetched) {
const present = new Set(alreadyFetched.map(o => String(o.number)));
const trackedNumbers = new Set([
...Object.keys(orderStatusStore).filter(n => orderStatusStore[n] && orderStatusStore[n] !== 'inkomend'),
...Object.keys(trunkrsLabelsStore)
]);
const extra = [];
for (const num of trackedNumbers) {
if (present.has(num)) continue;
const id = (trunkrsLabelsStore[num] && trunkrsLabelsStore[num].orderId) || orderIdMapStore[num];
if (!id) {
// Kan gebeuren voor orders die al 'label'/'verzonden' waren VOORDAT deze
// fix live ging (order-id nog niet bekend) — deze blijven helaas
// onvindbaar totdat er handmatig iets aan te doen is; nieuwe gevallen
// worden vanaf nu altijd correct bijgehouden.
console.error('fetchLocallyTrackedMissingOrders: geen bekend order-id voor order ' + num + ', kan niet opzoeken.');
continue;
}
try {
const r = await axios.get('https://api.webshopapp.com/' + SHOP + '/orders/' + id + '.json', { headers: apiHeaders() });
if (r.data.order) extra.push(r.data.order);
} catch(e) {
console.error('fetchLocallyTrackedMissingOrders error voor order ' + num + ' (id ' + id + '):', e.message);
}
}
return extra;
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
// "genegeerd" = lokaal verborgen via de rode "Geselecteerde bestellingen
// verwijderen"-knop op Inkomende orders (op verzoek van Pieter, 2026-08-30).
// Dit is puur een lokale statuswissel in deze app - er wordt nooit iets bij
// Lightspeed of de vervoerder aangepast of verwijderd.
const allowedStatuses = ['inkomend', 'label', 'verzonden', 'geannuleerd', 'genegeerd'];
if (!Array.isArray(orderNumbers) || !allowedStatuses.includes(status)) return res.status(400).json({ error: 'orderNumbers en een geldige status (inkomend, label, verzonden, geannuleerd, genegeerd) zijn verplicht' });
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
const nowIso = new Date().toISOString();
trunkrsLabelsStore[orderKey] = {
orderId: order.id,
trunkrsNr: shipment.trunkrsNr,
label: shipment.label,
service: service,
autoService: autoService,
serviceOverride: serviceOverride || null,
state: shipment.state,
// Het gewicht dat we daadwerkelijk naar Trunkrs hebben gestuurd (zie
// buildTrunkrsShipmentPayload) - los opgeslagen zodat het ook later nog
// getoond kan worden (labeldetails), niet alleen ten tijde van aanmaken.
weightKg: payload.parcel[0].weight.value,
printedBy: null,
printedAt: null,
cancelledAt: null,
createdAt: nowIso
};
saveTrunkrsLabels(trunkrsLabelsStore);

// Lokaal automatisch verplaatsen naar "Labels aangemaakt"
orderStatusStore[orderKey] = 'label';
saveOrderStatus(orderStatusStore);

const lightspeedSync = await syncTrunkrsToLightspeed(orderId, shipment.trunkrsNr);

res.json({
ok: true,
orderId: order.id,
trunkrsNr: shipment.trunkrsNr,
label: shipment.label,
service: service,
autoService: autoService,
state: shipment.state,
weightKg: trunkrsLabelsStore[orderKey].weightKg,
createdAt: nowIso,
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

// --- Instellingenpaneel: inpakstations beheren (Afdrukopties) ------------
// Zit achter dezelfde HTTP Basic Auth als de rest van het instellingenpaneel
// (packgo-medewerkers hierboven volgt hetzelfde patroon).
app.get('/api/settings/print-stations', (req, res) => {
  const stations = Object.keys(printStationsStore).sort(function(a, b) {
    return (printStationsStore[a].naam || '').localeCompare(printStationsStore[b].naam || '');
  }).map(function(id) {
    const s = printStationsStore[id];
    // Token bewust niet meegeven in de lijst - alleen relevant voor de
    // print-agent zelf, die zit in het gegenereerde scriptje (zie
    // agent-script-route hieronder).
    return { id: s.id, naam: s.naam, printerIp: s.printerIp, printerPort: s.printerPort, createdAt: s.createdAt, lastSeenAt: s.lastSeenAt || null };
  });
  res.json({ stations: stations });
});

app.post('/api/settings/print-stations', (req, res) => {
  const { naam, printerIp, printerPort } = req.body || {};
  const naamTrimmed = naam != null ? String(naam).trim() : '';
  const ipTrimmed = printerIp != null ? String(printerIp).trim() : '';
  const poort = printerPort ? parseInt(printerPort, 10) : 9100;
  if (!naamTrimmed || !ipTrimmed) return res.status(400).json({ error: 'Naam en printer-IP zijn verplicht.' });
  if (!Number.isInteger(poort) || poort < 1 || poort > 65535) return res.status(400).json({ error: 'Poort moet een getal tussen 1 en 65535 zijn.' });
  const id = crypto.randomUUID();
  const token = crypto.randomBytes(24).toString('hex');
  printStationsStore[id] = {
    id: id,
    naam: naamTrimmed,
    printerIp: ipTrimmed,
    printerPort: poort,
    token: token,
    createdAt: new Date().toISOString(),
    lastSeenAt: null
  };
  savePrintStations(printStationsStore);
  res.json({ ok: true, id: id, naam: naamTrimmed, printerIp: ipTrimmed, printerPort: poort });
});

app.delete('/api/settings/print-stations/:id', (req, res) => {
  const id = req.params.id;
  if (!printStationsStore[id]) return res.status(404).json({ error: 'Station niet gevonden.' });
  delete printStationsStore[id];
  savePrintStations(printStationsStore);
  // Openstaande printjobs voor dit station opruimen - niemand zal ze nog ophalen.
  Object.keys(printJobsStore).forEach(function(jobId) {
    if (printJobsStore[jobId].stationId === id) delete printJobsStore[jobId];
  });
  savePrintJobs(printJobsStore);
  res.json({ ok: true });
});

// Genereert het kleine print-agent-scriptje voor 1 station, met het eigen
// token/printer-IP er al in verwerkt - de medewerker hoeft alleen nog maar
// "node print-agent.js" te draaien op die pc. Puur Node core modules
// (http/https/net), geen npm install nodig. Kan altijd opnieuw gedownload
// worden (bv. na een IP-wijziging van de printer) - het token wordt niet
// ingetrokken bij het downloaden.
app.get('/api/settings/print-stations/:id/agent-script', (req, res) => {
  const s = printStationsStore[req.params.id];
  if (!s) return res.status(404).send('Station niet gevonden.');
  const baseUrl = req.protocol + '://' + req.get('host');
  const script = buildPrintAgentScript({ baseUrl: baseUrl, token: s.token, naam: s.naam, printerIp: s.printerIp, printerPort: s.printerPort });
  const safeNaam = s.naam.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'station';
  res.set('Content-Type', 'application/javascript; charset=utf-8');
  res.set('Content-Disposition', 'attachment; filename="print-agent-' + safeNaam + '.js"');
  res.send(script);
});

function buildPrintAgentScript(cfg) {
  return [
    '// LJ Verzending — print-agent voor station "' + cfg.naam + '"',
    '// Automatisch gegenereerd - draai dit met: node print-agent.js',
    '// Geen npm install nodig (gebruikt alleen Node core modules).',
    '// Haalt verzendlabels (als rauwe ZPL, rechtstreeks van Trunkrs) op voor',
    '// dit station en stuurt ze via een kale TCP-verbinding naar de eigen',
    '// (netwerk)labelprinter. Herdownload dit bestand als het printer-',
    '// IP-adres wijzigt.',
    "const http = require('http');",
    "const https = require('https');",
    "const net = require('net');",
    '',
    'const BASE_URL = ' + JSON.stringify(cfg.baseUrl) + ';',
    'const TOKEN = ' + JSON.stringify(cfg.token) + ';',
    'const PRINTER_IP = ' + JSON.stringify(cfg.printerIp) + ';',
    'const PRINTER_PORT = ' + JSON.stringify(cfg.printerPort) + ';',
    'const POLL_MS = 3000;',
    '',
    'function apiRequest(method, path, body) {',
    '  return new Promise(function(resolve, reject) {',
    '    const url = new URL(path, BASE_URL);',
    '    const lib = url.protocol === "https:" ? https : http;',
    '    const payload = body ? JSON.stringify(body) : null;',
    '    const opts = {',
    '      method: method,',
    '      headers: Object.assign({ Authorization: "Bearer " + TOKEN }, payload ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) } : {})',
    '    };',
    '    const r = lib.request(url, opts, function(res) {',
    '      let data = "";',
    '      res.on("data", function(chunk) { data += chunk; });',
    '      res.on("end", function() {',
    '        if (res.statusCode >= 200 && res.statusCode < 300) {',
    '          try { resolve(data ? JSON.parse(data) : {}); } catch (e) { resolve({}); }',
    '        } else {',
    '          reject(new Error("HTTP " + res.statusCode + ": " + data));',
    '        }',
    '      });',
    '    });',
    '    r.on("error", reject);',
    '    if (payload) r.write(payload);',
    '    r.end();',
    '  });',
    '}',
    '',
    'function printZpl(zpl) {',
    '  return new Promise(function(resolve, reject) {',
    '    const socket = net.createConnection({ host: PRINTER_IP, port: PRINTER_PORT }, function() {',
    '      socket.write(zpl, "utf8", function() { socket.end(); });',
    '    });',
    '    socket.setTimeout(8000, function() { socket.destroy(new Error("Printer reageerde niet binnen 8 seconden (IP/poort/netwerk controleren)")); });',
    '    socket.on("close", function() { resolve(); });',
    '    socket.on("error", reject);',
    '  });',
    '}',
    '',
    'async function tick() {',
    '  try {',
    '    const jobs = await apiRequest("GET", "/api/print-agent/jobs");',
    '    for (const job of (jobs.jobs || [])) {',
    '      try {',
    '        await printZpl(job.zpl);',
    '        await apiRequest("POST", "/api/print-agent/jobs/" + job.id + "/ack", { ok: true });',
    '        console.log("[print-agent] label geprint voor order " + job.orderNumber);',
    '      } catch (e) {',
    '        console.error("[print-agent] printen mislukt voor order " + job.orderNumber + ":", e.message);',
    '        await apiRequest("POST", "/api/print-agent/jobs/" + job.id + "/ack", { ok: false, error: e.message }).catch(function(){});',
    '      }',
    '    }',
    '  } catch (e) {',
    '    console.error("[print-agent] kon niet verbinden met LJ Verzending:", e.message);',
    '  }',
    '  setTimeout(tick, POLL_MS);',
    '}',
    '',
    'console.log("[print-agent] gestart voor station \\"' + cfg.naam + '\\" -> printer " + PRINTER_IP + ":" + PRINTER_PORT + " (elke " + (POLL_MS/1000) + "s ophalen bij " + BASE_URL + ")");',
    'tick();',
    ''
  ].join('\n');
}

// Stuurt het (al aangemaakte) Trunkrs-verzendlabel van 1 order als printjob
// naar 1 specifiek inpakstation. Gebruikt de rauwe ZPL die Trunkrs standaard
// meelevert naast de PDF (zie trunkrsLabelsStore) - geen extra Trunkrs-call
// of PDF-conversie nodig.
app.post('/api/print-stations/:id/print-label', (req, res) => {
  const station = printStationsStore[req.params.id];
  if (!station) return res.status(404).json({ error: 'Station niet gevonden.' });
  const { orderNumber } = req.body || {};
  const key = orderNumber != null ? String(orderNumber) : '';
  const tl = key && trunkrsLabelsStore[key];
  if (!tl) return res.status(404).json({ error: 'Geen Trunkrs-label bekend voor deze order.' });
  const zpl = tl.label && tl.label.zpl;
  if (!zpl) return res.status(422).json({ error: 'Dit label heeft geen ZPL-data (onverwacht - normaal levert Trunkrs dit altijd mee naast de PDF).' });
  const jobId = crypto.randomUUID();
  printJobsStore[jobId] = {
    id: jobId,
    stationId: station.id,
    orderNumber: key,
    zpl: zpl,
    status: 'pending',
    createdAt: new Date().toISOString(),
    deliveredAt: null,
    doneAt: null,
    error: null
  };
  savePrintJobs(printJobsStore);
  res.json({ ok: true, jobId: jobId });
});

// --- Print-agent-endpoints (eigen token, geen kantoor-Basic-Auth) --------
// Zie requirePrintAgentToken hierboven en de bypass in de Basic-Auth-
// middleware bovenaan dit bestand.
app.get('/api/print-agent/jobs', requirePrintAgentToken, (req, res) => {
  const station = req.printStation;
  station.lastSeenAt = new Date().toISOString();
  savePrintStations(printStationsStore);
  const jobs = Object.keys(printJobsStore)
    .map(function(id) { return printJobsStore[id]; })
    .filter(function(j) { return j.stationId === station.id && j.status === 'pending'; });
  jobs.forEach(function(j) { j.status = 'delivered'; j.deliveredAt = new Date().toISOString(); });
  if (jobs.length) savePrintJobs(printJobsStore);
  res.json({ jobs: jobs.map(function(j) { return { id: j.id, orderNumber: j.orderNumber, zpl: j.zpl, createdAt: j.createdAt }; }) });
});

app.post('/api/print-agent/jobs/:jobId/ack', requirePrintAgentToken, (req, res) => {
  const job = printJobsStore[req.params.jobId];
  if (!job || job.stationId !== req.printStation.id) return res.status(404).json({ error: 'Printjob niet gevonden.' });
  const { ok, error } = req.body || {};
  job.status = ok ? 'done' : 'failed';
  job.doneAt = new Date().toISOString();
  job.error = ok ? null : (error || 'Onbekende fout');
  savePrintJobs(printJobsStore);
  res.json({ ok: true });
});

// PIN-check voor het Pack & Go-scherm (zie packgoMedewerkersStore hierboven).
// Geeft alleen de naam terug bij een geldige PIN, nooit de lijst van
// PIN's/namen zelf - de client kent alleen het resultaat van 1 invoer.
app.post('/api/packgo/login', (req, res) => {
const { pin } = req.body || {};
const pinTrimmed = pin != null ? String(pin).trim() : '';
let naam = null;
if (pinTrimmed) {
for (const key in packgoMedewerkersStore) {
if (packgoMedewerkersStore[key] === pinTrimmed) { naam = key; break; }
}
}
if (!naam) return res.status(401).json({ error: 'Onjuiste PIN' });
res.json({ ok: true, naam: naam });
});

// --- Instellingenpaneel: Pack & Go-medewerkers beheren (rechter zijbalk) --
// Zit achter dezelfde HTTP Basic Auth als de rest van de app - geen aparte
// beveiliging nodig, net zoals klantgegevens elders in de app ook alleen
// achter die ene inlog zitten.
app.get('/api/settings/packgo-medewerkers', (req, res) => {
const medewerkers = Object.keys(packgoMedewerkersStore).sort(function(a, b) { return a.localeCompare(b); }).map(function(naam) {
return { naam: naam, pin: packgoMedewerkersStore[naam] };
});
res.json({ medewerkers: medewerkers });
});

app.post('/api/settings/packgo-medewerkers', (req, res) => {
const { naam, pin } = req.body || {};
const naamTrimmed = naam != null ? String(naam).trim() : '';
const pinTrimmed = pin != null ? String(pin).trim() : '';
if (!naamTrimmed || !pinTrimmed) return res.status(400).json({ error: 'Naam en PIN zijn verplicht.' });
if (!/^[0-9]{4,6}$/.test(pinTrimmed)) return res.status(400).json({ error: 'PIN moet 4 tot 6 cijfers zijn.' });
const dubbeleNaam = Object.keys(packgoMedewerkersStore).find(function(k) { return k !== naamTrimmed && packgoMedewerkersStore[k] === pinTrimmed; });
if (dubbeleNaam) return res.status(409).json({ error: 'Deze PIN is al in gebruik door ' + dubbeleNaam + '.' });
packgoMedewerkersStore[naamTrimmed] = pinTrimmed;
savePackgoMedewerkers(packgoMedewerkersStore);
res.json({ ok: true });
});

app.delete('/api/settings/packgo-medewerkers/:naam', (req, res) => {
const naam = decodeURIComponent(req.params.naam);
if (!packgoMedewerkersStore[naam]) return res.status(404).json({ error: 'Medewerker niet gevonden.' });
delete packgoMedewerkersStore[naam];
savePackgoMedewerkers(packgoMedewerkersStore);
res.json({ ok: true });
});

// Legt vast wie een label heeft geprint (voor de "Geprint door"-kolom).
// Geen aparte beveiliging op deze route zelf - de PIN-check bij inloggen
// (hierboven) is het beveiligingsmoment; dit endpoint registreert alleen
// het resultaat daarvan.
app.post('/api/trunkrs/mark-printed', (req, res) => {
const { orderNumber, naam } = req.body || {};
if (!orderNumber || !naam) return res.status(400).json({ error: 'orderNumber en naam verplicht' });
const key = String(orderNumber);
if (!trunkrsLabelsStore[key]) return res.status(404).json({ error: 'Geen Trunkrs-label bekend voor deze order' });
trunkrsLabelsStore[key].printedBy = naam;
trunkrsLabelsStore[key].printedAt = new Date().toISOString();
saveTrunkrsLabels(trunkrsLabelsStore);
res.json({ ok: true });
});

// Annuleert een aangemaakt Trunkrs-label (echte annulering bij Trunkrs zelf
// via DELETE /shipments/{trunkrsNr}) en zet de order lokaal op "geannuleerd".
app.post('/api/trunkrs/cancel-label', async (req, res) => {
if (!TRUNKRS_API_KEY) return res.status(503).json({ error: 'TRUNKRS_API_KEY is niet ingesteld (Railway env var).' });
const { orderNumber } = req.body || {};
if (!orderNumber) return res.status(400).json({ error: 'orderNumber verplicht' });
const key = String(orderNumber);
const entry = trunkrsLabelsStore[key];
if (!entry || !entry.trunkrsNr) return res.status(404).json({ error: 'Geen Trunkrs-label bekend voor deze order' });
try {
await axios.delete(TRUNKRS_BASE_URL + '/shipments/' + entry.trunkrsNr, { headers: trunkrsHeaders() });
entry.cancelledAt = new Date().toISOString();
saveTrunkrsLabels(trunkrsLabelsStore);
orderStatusStore[key] = 'geannuleerd';
saveOrderStatus(orderStatusStore);
res.json({ ok: true });
} catch(e) {
const detail = e.response ? JSON.stringify(e.response.data) : e.message;
console.error('trunkrs/cancel-label error for order ' + orderNumber + ':', detail);
res.status(500).json({ error: 'Label annuleren mislukt: ' + detail });
}
});

// Haalt de actuele status (state.code) live op bij Trunkrs voor alle bekende
// labels (behalve al geannuleerde) en werkt trunkrsLabelsStore bij. Bedoeld
// voor de "STATUS"-kolom in "Gecreëerde labels" en "Verzonden" - Pieter wil
// deze gevuld zien vanuit het Trunkrs-portaal i.p.v. een statische waarde.
// Fase-2-webhooks (automatisch, zie project-notities) zijn nog niet gebouwd;
// dit endpoint pollt op aanvraag (bv. bij het openen van een tabblad) i.p.v.
// continu op de achtergrond, om binnen de Trunkrs-rate-limits te blijven.
app.post('/api/trunkrs/refresh-statuses', async (req, res) => {
if (!TRUNKRS_API_KEY) return res.status(503).json({ error: 'TRUNKRS_API_KEY is niet ingesteld (Railway env var).' });
const keys = Object.keys(trunkrsLabelsStore).filter(function(k) {
const entry = trunkrsLabelsStore[k];
return entry && entry.trunkrsNr && !entry.cancelledAt;
});
let orderStatusChanged = false;
try {
await mapWithConcurrency(keys, 5, async function(key) {
const entry = trunkrsLabelsStore[key];
try {
const r = await axios.get(TRUNKRS_BASE_URL + '/shipments/' + entry.trunkrsNr, { headers: trunkrsHeaders() });
const data = (r.data && r.data.data) ? r.data.data : r.data;
if (data && data.state) entry.state = data.state;
// Automatische overgang "Gecreëerde labels" -> "Verzonden" zodra Trunkrs
// de zending voor het eerst fysiek scant (binnenkomst/sortering op hun
// warehouse) - op verzoek van Pieter (2026-08-29). Alleen vooruit, nooit
// een al op "geannuleerd" gezette order overschrijven.
const code = data && data.state && data.state.code;
if (code && TRUNKRS_WAREHOUSE_SCAN_OR_LATER_CODES.indexOf(code) !== -1 &&
orderStatusStore[key] !== 'geannuleerd' && orderStatusStore[key] !== 'verzonden') {
orderStatusStore[key] = 'verzonden';
orderStatusChanged = true;
}
} catch (e) {
// 1 mislukte status-lookup mag de andere orders niet blokkeren.
console.error('refresh-statuses: status ophalen mislukt voor ' + key + ':', e.response ? JSON.stringify(e.response.data) : e.message);
}
});
saveTrunkrsLabels(trunkrsLabelsStore);
if (orderStatusChanged) saveOrderStatus(orderStatusStore);
res.json({ labels: trunkrsLabelsStore, orderStatus: orderStatusStore });
} catch (e) {
res.status(500).json({ error: 'Statussen ophalen mislukt: ' + e.message });
}
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
