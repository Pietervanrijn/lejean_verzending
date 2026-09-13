require('dotenv').config();
const express = require('express');
const axios = require('axios');
const fs = require('fs');
const crypto = require('crypto');
const { PDFDocument, degrees } = require('pdf-lib');
const app = express();
// Railway zet TLS af bij zijn eigen proxy en stuurt intern gewoon HTTP door
// naar deze container. Zonder "trust proxy" denkt Express daardoor dat elk
// verzoek plain-HTTP is (req.protocol === "http"), ook als de bezoeker via
// https:// binnenkwam. Dat gaf op 2026-08-31 een concreet probleem: het
// gegenereerde print-agent-scriptje (zie buildPrintAgentScript) bakte zijn
// eigen BASE_URL met "http://", waardoor elk verzoek van het scriptje bij
// Railway een 301-redirect naar https:// terugkreeg die het scriptje niet
// volgt - het station kon daardoor nooit printjobs ophalen. Met trust proxy
// aan leest Express de X-Forwarded-Proto-header van Railway's proxy en klopt
// req.protocol weer.
app.set('trust proxy', 1);
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

// printStatusStore/orderStatusStore/trunkrsLabelsStore worden overal
// gelezen op het KALE ordernummer (String(order.number), bv. "80384") - nooit
// op de "ORD"-weergavewaarde (bv. "ORD80384"). Een aantal client-aanroepen
// stuurde per ongeluk toch die weergavewaarde mee als ordernummer, waardoor
// de bijbehorende statuswijziging op een sleutel terechtkwam die nergens
// meer gelezen werd - een stille no-op (gevonden en gefixt op verzoek van
// Pieter, 2026-08-30). Deze helper normaliseert dat bij elke schrijfactie,
// als vangnet ook voor eventuele toekomstige aanroepen die het per ongeluk
// weer fout doen.
function bareOrderNumberKey(n) {
  return String(n == null ? '' : n).replace(/^ORD/i, '');
}

// Ruimt eenmalig (bij opstarten) foutief "ORD"-gesleutelde entries op die
// hierdoor eerder al in een van deze bestanden terecht zijn gekomen. Heeft de
// kale sleutel nog geen waarde, dan wordt de tot dusver genegeerde ORD-waarde
// alsnog toegepast (dat herstelt de status die stilletjes verloren ging);
// heeft de kale sleutel al een waarde, dan blijft die leidend - dat is de
// sleutel die de app al die tijd daadwerkelijk las - en wordt de foutieve
// entry gewoon opgeruimd.
function migrateOrdPrefixedKeys(store, label) {
  var changed = false;
  Object.keys(store).forEach(function(k) {
    if (!/^ORD/i.test(k)) return;
    var bareKey = bareOrderNumberKey(k);
    if (bareKey && !(bareKey in store)) {
      console.log('[migratie] ' + label + ': "' + k + '" -> "' + bareKey + '" (' + store[k] + ')');
      store[bareKey] = store[k];
    }
    delete store[k];
    changed = true;
  });
  return changed;
}

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
if (migrateOrdPrefixedKeys(printStatusStore, 'print-status')) savePrintStatus(printStatusStore);
if (migrateOrdPrefixedKeys(orderStatusStore, 'order-status')) saveOrderStatus(orderStatusStore);

// Handmatige correcties op verzendmethode/adres vanuit het "Bewerk order"-
// potlood-icoon in het Inkomend-tabblad (op verzoek van Pieter, 2026-09-10).
// Bewust ALLEEN een lokale override in deze app - er wordt nooit iets
// teruggeschreven naar de echte Lightspeed-order. Gekeyed op het kale
// ordernummer (zie bareOrderNumberKey), net als de andere stores hierboven.
const ORDER_OVERRIDES_FILE = DATA_DIR + '/order-overrides.json';
function loadOrderOverrides() {
try { return JSON.parse(fs.readFileSync(ORDER_OVERRIDES_FILE, 'utf8')); } catch(e) { return {}; }
}
function saveOrderOverrides(data) {
try { fs.writeFileSync(ORDER_OVERRIDES_FILE, JSON.stringify(data)); } catch(e) { console.error('saveOrderOverrides error:', e.message); }
}
let orderOverridesStore = loadOrderOverrides();
if (migrateOrdPrefixedKeys(orderOverridesStore, 'order-overrides')) saveOrderOverrides(orderOverridesStore);

// Past een eventuele opgeslagen override toe op een rauwe Lightspeed-order,
// VOORDAT deze verder verwerkt wordt (zie enrichOrders() en de
// labelaanmaak-route hieronder). Omdat vrijwel alle logica in deze app
// (verzendmethode-badge, dropdown, en het adres dat daadwerkelijk naar
// Trunkrs gaat bij het aanmaken van een label) gewoon van deze
// order.addressShipping*/shipmentTitle-velden leest, hoeft er verder nergens
// iets aangepast te worden zodra dit vroeg genoeg gebeurt - de correctie
// stroomt vanzelf door.
function applyOrderOverride(order) {
const ov = orderOverridesStore[bareOrderNumberKey(order.number)];
if (!ov) return order;
const merged = Object.assign({}, order);
if (ov.name) merged.addressShippingName = ov.name;
if (ov.street) merged.addressShippingStreet = ov.street;
if (ov.number) merged.addressShippingNumber = ov.number;
if (ov.extension !== undefined) merged.addressShippingExtension = ov.extension;
if (ov.zipcode) merged.addressShippingZipcode = ov.zipcode;
if (ov.city) merged.addressShippingCity = ov.city;
if (ov.countryCode) merged.addressShippingCountry = { code: ov.countryCode, code3: ov.countryCode };
if (ov.shippingMethod) merged.shipmentTitle = ov.shippingMethod;
// _carrierOverride/_frozenOverride zijn geen echte Lightspeed-velden - ze
// worden hier alleen "doorgeprikt" op het (rauwe) orderobject zodat ze,
// samen met alle andere velden hierboven, automatisch meeliften in
// enrichOrders()'s `{ ...order, ... }`-spread verderop, zonder dat
// enrichOrders() zelf iets van deze override hoeft te weten. _frozenOverride
// wordt daarnaast ook direct in de labelaanmaak-route hieronder gebruikt.
if (ov.carrier) merged._carrierOverride = ov.carrier;
if (typeof ov.frozen === 'boolean') merged._frozenOverride = ov.frozen;
return merged;
}

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
// trunkrsLabelsStore/orderIdMapStore werden hier eerder bewust NIET
// gemigreerd (aanname: "server-derived, dus altijd kaal gesleuteld"). Die
// aanname bleek onjuist: het testorder ORD80456 (Lightspeed-ordernummer dat
// zelf al de tekst "ORD" bevat) liet zien dat /api/trunkrs/label (zie
// orderKey hieronder) en de order-id-cache hierboven wél degelijk een
// ongestripte "ORD..."-sleutel konden wegschrijven, die vervolgens nergens
// meer gelezen werd zodra de order via "genegeerd" weer als kaal
// ordernummer werd bijgewerkt - gevonden en gefixt op verzoek van Pieter,
// 2026-08-31 (zie ook enrichOrders() en orderKey verderop in dit bestand).
if (migrateOrdPrefixedKeys(trunkrsLabelsStore, 'trunkrs-labels')) saveTrunkrsLabels(trunkrsLabelsStore);
if (migrateOrdPrefixedKeys(orderIdMapStore, 'order-id-map')) saveOrderIdMap(orderIdMapStore);

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
//
// Sinds 2026-09-02 draait de print-agent ook een klein lokaal statuspunt
// (http://127.0.0.1:9743, zie startLocalStatusServer() in
// buildPrintAgentScript) dat alleen vanaf de pc zelf bereikbaar is. Pack &
// Go in de browser roept dit bij het laden aan om automatisch te herkennen
// welk inpakstation dit is - geen handmatige "welk station ben ik"-keuze
// meer nodig (zie findDirectPrintStation()/detectLocalPrintStation() in
// index.html). Werkt op precies dezelfde manier als Sendcloud's eigen
// client: eenmalig het scriptje downloaden/starten op die pc, daarna weet
// de webpagina het vanzelf.
const PRINT_STATIONS_FILE = DATA_DIR + '/print-stations.json';
function loadPrintStations() {
  try { return JSON.parse(fs.readFileSync(PRINT_STATIONS_FILE, 'utf8')); } catch(e) { return {}; }
}
function savePrintStations(data) {
  try { fs.writeFileSync(PRINT_STATIONS_FILE, JSON.stringify(data)); } catch(e) { console.error('savePrintStations error:', e.message); }
}
let printStationsStore = loadPrintStations();

// Elk inpakstation had tot 2026-08-31 maar 1 printer (voor labels, kaal
// printerIp/printerPort op het station zelf). Op verzoek van Pieter komt daar
// een volledig gelijkwaardige tweede printer bij (voor pakbonnen), elk met
// een eigen formaat en een "eerst bekijken voordat er geprint wordt"-
// schakelaar (zie Sendcloud's Afdrukopties-scherm). Deze migratie verplaatst
// bestaande stations naar de nieuwe geneste vorm zonder de al werkende
// labelprinter-configuratie te verliezen.
// Sinds 12-09-2026 slaan we per documenttype geen printerIp/printerPort meer
// op maar een Windows-printernaam (zie parsePrinterConfig hierboven - alles
// gaat nu via de Windows-driver i.p.v. een kale TCP-verbinding, zodat het
// werkt ongeacht printermerk). Bestaande stations van vóór die datum hebben
// nog het oude ip/poort-schema; die kunnen we niet automatisch omzetten naar
// een printernaam (een IP-adres vertelt ons niet welke Windows-printer daar
// destijds bij hoorde), dus die velden worden hier leeggemaakt - Pieter kiest
// dan eenmalig opnieuw de juiste Windows-printer via de instellingen
// (dezelfde gedetecteerde-printers-keuzelijst als voorheen, nu met namen
// i.p.v. IP-adressen).
function migrateDocTypeToPrinterNaam(cfg, fallbackFormaat) {
  if (!cfg || cfg.printerNaam !== undefined) return cfg;
  return {
    printerNaam: '',
    formaat: cfg.formaat || fallbackFormaat,
    previewFirst: cfg.previewFirst !== false
  };
}

function migratePrintStationsShape(store) {
  let changed = false;
  Object.keys(store).forEach(function(id) {
    const s = store[id];
    if (!s.label) {
      s.label = { printerNaam: '', formaat: 'A6', previewFirst: true };
      changed = true;
    } else {
      const migrated = migrateDocTypeToPrinterNaam(s.label, 'A6');
      if (migrated !== s.label) { s.label = migrated; changed = true; }
    }
    if (!s.pakbon) {
      s.pakbon = { printerNaam: '', formaat: 'A4', previewFirst: true };
      changed = true;
    } else {
      const migrated = migrateDocTypeToPrinterNaam(s.pakbon, 'A4');
      if (migrated !== s.pakbon) { s.pakbon = migrated; changed = true; }
    }
    if (!s.detectedPrinters || (s.detectedPrinters[0] && s.detectedPrinters[0].ip !== undefined)) {
      // Ook oude gedetecteerde-printerlijsten (met .ip) opruimen - die tonen
      // anders nog IP-adressen in een keuzelijst die nu namen verwacht.
      s.detectedPrinters = [];
      changed = true;
    }
  });
  return changed;
}
if (migratePrintStationsShape(printStationsStore)) savePrintStations(printStationsStore);

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

// --- Caches om Lightspeed rate-limiting (429) te voorkomen ----------------
// Ontdekt op 2026-08-30: bij ELKE keer dat /api/orders werd opgehaald (elke
// 30s door de auto-refresh in index.html, per open tabblad) werd voor ELKE
// order opnieuw de productenlijst bij Lightspeed opgehaald (voor het
// aantal artikelen), en voor elke order die al buiten de "inkomend"-status
// viel (label/verzonden/geannuleerd) óók nog eens de volledige orderdata.
// Bij tientallen orders x meerdere open tabbladen liep dit binnen enkele
// minuten tegen Lightspeed's rate limit aan. Zodra dat gebeurde faalde
// fetchOrders() zelf óók (dezelfde rate limit), waardoor alle tabs leeg
// leken ("geen orders gevonden") - dit is de oorzaak van het "ik zie geen
// orders"-probleem.
// Productdata en orderdata van een reeds geplaatste order veranderen in de
// praktijk niet meer, dus we cachen ze hier in het geheugen: 1x per
// serverstart ophalen bij Lightspeed i.p.v. elke 30 seconden opnieuw. Wordt
// automatisch leeggemaakt bij een herstart/nieuwe deploy. Als een order-detail
// toch een keer handmatig gecorrigeerd moet worden: de Railway-service
// herstarten leegt deze cache.
const orderProductsSummaryCache = new Map(); // orderId -> {itemCount, quantityOrdered}
const orderDetailCache = new Map(); // orderId -> volledig order-object van Lightspeed

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
const key = bareOrderNumberKey(o.number);
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
// bareOrderNumberKey hier ook: orderStatusStore/trunkrsLabelsStore zijn kaal
// gesleuteld, dus zonder normalisatie zou een order met een al "ORD"-bevattend
// Lightspeed-ordernummer hier ten onrechte als "nog niet aanwezig" gezien
// worden en dubbel in de resultaten belanden.
const present = new Set(alreadyFetched.map(o => bareOrderNumberKey(o.number)));
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
if (orderDetailCache.has(id)) { extra.push(orderDetailCache.get(id)); continue; }
try {
const r = await axios.get('https://api.webshopapp.com/' + SHOP + '/orders/' + id + '.json', { headers: apiHeaders() });
if (r.data.order) { orderDetailCache.set(id, r.data.order); extra.push(r.data.order); }
} catch(e) {
console.error('fetchLocallyTrackedMissingOrders error voor order ' + num + ' (id ' + id + '):', e.message);
}
}
return extra;
}

async function fetchOrderProductsSummary(orderId) {
if (orderProductsSummaryCache.has(orderId)) return orderProductsSummaryCache.get(orderId);
try {
const r = await axios.get('https://api.webshopapp.com/' + SHOP + '/orders/' + orderId + '/products.json', { headers: apiHeaders() });
const products = r.data.orderProducts || r.data.products || [];
const itemCount = products.length;
const quantityOrdered = products.reduce(function(s,p){ return s + (p.quantityOrdered || 0); }, 0);
const result = { itemCount: itemCount, quantityOrdered: quantityOrdered };
orderProductsSummaryCache.set(orderId, result);
return result;
} catch(e) {
console.error('fetchOrderProductsSummary error:', e.message);
// Bewust NIET cachen: bij een tijdelijke fout (bv. 429) mag een
// volgende poll het alsnog opnieuw proberen i.p.v. voorgoed "null" te tonen.
return { itemCount: null, quantityOrdered: null };
}
}

async function enrichOrders(orders) {
// Voorheen werd hier gefilterd op alleen DAGBEZORGING/afhaal-orders. De tool
// (nu LJ Verzending) dekt inmiddels alle verzendmethodes, dus alle orders
// met status "klaar voor verzending"/"klaar voor afhalen" worden verrijkt
// en getoond; de verzendmethode zelf blijft gewoon zichtbaar per order.
const enriched = await mapWithConcurrency(orders, 5, async (rawOrder) => {
const order = applyOrderOverride(rawOrder);
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
// Let op: NIET String(order.number) hier - Lightspeed geeft voor sommige
// (test)orders een ordernummer terug dat zelf al "ORD" bevat (bv.
// "ORD80456"), terwijl deze stores overal elders juist kaal gesleuteld
// worden (zie bareOrderNumberKey hierboven). Zonder deze normalisatie mist
// de lookup dan stil de eerder opgeslagen status/printstatus/label - precies
// het bugbeeld dat Pieter meldde (order bleef als "inkomend" tonen na
// "genegeerd", 2026-08-31).
const printStatus = printStatusStore[bareOrderNumberKey(order.number)] || 'geen';
const orderStatus = orderStatusStore[bareOrderNumberKey(order.number)] || 'inkomend';
const summary = await fetchOrderProductsSummary(order.id);
const trunkrsLabel = trunkrsLabelsStore[bareOrderNumberKey(order.number)] || null;
const hasOverride = !!orderOverridesStore[bareOrderNumberKey(order.number)];
return { ...order, _klant: klant, _ordNummer: ordNummer, _shippingMethod: shippingMethod, _isPickup: isPickup, _printStatus: printStatus, _orderStatus: orderStatus, itemCount: summary.itemCount, quantityOrdered: summary.quantityOrdered, _trunkrsLabel: trunkrsLabel, _hasOverride: hasOverride };
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
// Let op: reference krijgt bewust een korte unieke suffix i.p.v. kaal
// String(order.number). Op 2026-08-31 wees Trunkrs een verzendlabel voor
// ORD80535 af met "Shipment(s) with barcode [ORD80535] is already
// existing.", terwijl Pieter zowel via een barcode-zoekopdracht als in de
// volledige recente-zendingenlijst in het echte Trunkrs-portaal geen enkele
// zending met die referentie kon terugvinden - Trunkrs's eigen
// dubbel-check op dit veld is dus aantoonbaar niet 1-op-1 betrouwbaar/
// zichtbaar. Onze eigen bescherming tegen per ongeluk twee keer aanmaken
// zit voortaan in de route hierboven (trunkrsLabelsStore-check); deze
// suffix zorgt er alleen voor dat we nooit meer tegen Trunkrs's eigen
// (kennelijk soms hangende/spook-)blokkade op dit exacte veld aanlopen, nu
// niet meer voor ORD80535 en ook niet voor toekomstige orders.
const parcel = {
description: 'LJ Verzending order ' + order.number,
reference: String(order.number) + '-' + crypto.randomBytes(3).toString('hex')
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

// Korte gedeelde cache + samenvoeging van gelijktijdige aanvragen: als
// meerdere tabbladen/medewerkers (of de auto-refresh + een handmatige klik)
// toevallig tegelijk verversen, start dit maar 1x een volledige Lightspeed-
// ronde i.p.v. elke aanvraag apart - scheelt nog eens extra belasting bovenop
// de caches in fetchOrderProductsSummary/fetchLocallyTrackedMissingOrders.
let ordersResultCache = { data: null, ts: 0 };
let ordersFetchInFlight = null;
const ORDERS_CACHE_MS = 10000;

app.get('/api/orders', async (req, res) => {
try {
const now = Date.now();
if (ordersResultCache.data && (now - ordersResultCache.ts) < ORDERS_CACHE_MS) {
return res.json(ordersResultCache.data);
}
if (!ordersFetchInFlight) {
ordersFetchInFlight = (async () => {
const orders = await fetchOrders();
const enriched = await enrichOrders(orders);
const methods = [...new Set(enriched.map(o => o._shippingMethod).filter(Boolean))].sort();
const payload = { orders: enriched, total: enriched.length, shippingMethods: methods };
ordersResultCache = { data: payload, ts: Date.now() };
return payload;
})().finally(() => { ordersFetchInFlight = null; });
}
const payload = await ordersFetchInFlight;
res.json(payload);
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
const key = bareOrderNumberKey(n);
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
orderStatusStore[bareOrderNumberKey(n)] = status;
});
saveOrderStatus(orderStatusStore);
res.json({ ok: true, orderStatus: orderStatusStore });
});

// "Bewerk order" (potlood-icoon, Inkomend-tabblad): verzendmethode + adres
// lokaal corrigeren zonder dit ooit naar Lightspeed terug te schrijven (op
// verzoek van Pieter, 2026-09-10 - zie ook applyOrderOverride() hierboven).
app.post('/api/order-overrides/:ordNummer', (req, res) => {
const key = bareOrderNumberKey(req.params.ordNummer);
if (!key) return res.status(400).json({ error: 'ordNummer verplicht' });
const { name, street, number, extension, zipcode, city, countryCode, shippingMethod, carrier, frozen } = req.body || {};
const override = {};
if (name) override.name = String(name).trim();
if (street) override.street = String(street).trim();
if (number) override.number = String(number).trim();
if (extension !== undefined) override.extension = String(extension).trim();
if (zipcode) override.zipcode = String(zipcode).trim();
if (city) override.city = String(city).trim();
if (countryCode) override.countryCode = String(countryCode).trim().toUpperCase();
if (shippingMethod) override.shippingMethod = String(shippingMethod).trim();
// "Automatisch" (lege waarde) slaat bewust geen verzender op - dat is geen
// foutieve invoer maar de expliciete keuze om terug te vallen op de
// bestaande tekst-gebaseerde detectie (zie resolveCarrierKey() in
// index.html). ALLOWED_CARRIERS = alleen vervoerders die de app al kent.
const ALLOWED_CARRIERS = ['trunkrs', 'postnl', 'chillbill'];
if (carrier && ALLOWED_CARRIERS.includes(String(carrier).toLowerCase())) override.carrier = String(carrier).toLowerCase();
// "frozen" komt van een vinkje (altijd true/false, geen "geen keuze"), dus
// hier op type checken i.p.v. op truthy-heid - anders zou "niet frozen"
// (false) ten onrechte als "niet meegegeven" behandeld worden.
if (typeof frozen === 'boolean') override.frozen = frozen;
if (!Object.keys(override).length) return res.status(400).json({ error: 'Geen velden om op te slaan' });
override.updatedAt = new Date().toISOString();
orderOverridesStore[key] = override;
saveOrderOverrides(orderOverridesStore);
ordersResultCache = { data: null, ts: 0 };
res.json({ ok: true, override: orderOverridesStore[key] });
});

// Herstelt een order weer naar de originele Lightspeed-gegevens (verwijdert
// de lokale override).
app.delete('/api/order-overrides/:ordNummer', (req, res) => {
const key = bareOrderNumberKey(req.params.ordNummer);
delete orderOverridesStore[key];
saveOrderOverrides(orderOverridesStore);
ordersResultCache = { data: null, ts: 0 };
res.json({ ok: true });
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

// Beste-poging, zelfde patroon als syncTrunkrsToLightspeed hieronder, maar dan
// voor vervoerders zonder eigen carrier-API-koppeling (Chill-Bill/DAGBEZORGING):
// op het moment dat de Verzendinformatie-export voor zulke orders wordt
// gegenereerd, zet dit de Lightspeed-shipment toch op "shipped" - net als bij
// het aanmaken van een Trunkrs-label. Geen trackingCode: die heeft Chill-Bill
// niet. Mag per order falen zonder de andere orders in de batch te blokkeren.
app.post('/api/orders/mark-shipped', async (req, res) => {
const { orderIds } = req.body || {};
if (!Array.isArray(orderIds) || !orderIds.length) return res.status(400).json({ error: 'orderIds verplicht' });
const results = [];
for (const id of orderIds) {
try {
const shipRes = await axios.get('https://api.webshopapp.com/' + SHOP + '/shipments.json', { headers: apiHeaders(), params: { order: id } });
const shipment = shipRes.data.shipments && shipRes.data.shipments[0];
if (!shipment) { results.push({ id, ok: false, error: 'geen shipment gevonden voor order ' + id }); continue; }
await axios.put('https://api.webshopapp.com/' + SHOP + '/shipments/' + shipment.id + '.json', { shipment: { status: 'shipped' } }, { headers: apiHeaders() });
results.push({ id, ok: true });
} catch(e) {
console.error('mark-shipped error for order ' + id + ':', e.response ? JSON.stringify(e.response.data) : e.message);
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
let order = orderRes.data.order;
if (!order) return res.status(404).json({ error: 'Order niet gevonden' });
// Past een eventuele lokale correctie (potlood-icoon, Inkomend-tabblad) toe
// zodat een fout adres/verzendmethode ook daadwerkelijk in het bij Trunkrs
// aangemaakte label terechtkomt - zie applyOrderOverride() hierboven.
order = applyOrderOverride(order);

// Eigen idempotentie-check, VOORDAT we Trunkrs uberhaupt aanroepen: als we
// voor deze order al eerder succesvol een label hebben aangemaakt (staat in
// trunkrsLabelsStore), geef die gewoon terug i.p.v. opnieuw bij Trunkrs aan
// te kloppen. Nodig geworden na een geval (ORD80535, 2026-08-31) waarbij
// Trunkrs's eigen "barcode already existing"-check afging op een referentie
// die nergens in het Trunkrs-portaal terug te vinden was (dus kennelijk niet
// betrouwbaar is als bescherming tegen dubbel aanmaken) - zie ook de nieuwe
// unieke suffix in buildTrunkrsShipmentPayload() hieronder. Zo blijven we
// zelf in controle over "is dit al aangemaakt?" i.p.v. te vertrouwen op een
// check aan Trunkrs's kant die aantoonbaar kan haperen.
const bestaandOrderKey = bareOrderNumberKey(order.number);
const bestaandLabel = trunkrsLabelsStore[bestaandOrderKey];
if (bestaandLabel && bestaandLabel.trunkrsNr && !bestaandLabel.cancelledAt) {
res.json({
ok: true,
alreadyExisted: true,
orderId: order.id,
trunkrsNr: bestaandLabel.trunkrsNr,
label: bestaandLabel.label,
service: bestaandLabel.service,
autoService: bestaandLabel.autoService,
state: bestaandLabel.state,
weightKg: bestaandLabel.weightKg,
createdAt: bestaandLabel.createdAt,
lightspeedSync: true,
lightspeedSyncError: null
});
return;
}

const productsRes = await axios.get('https://api.webshopapp.com/' + SHOP + '/orders/' + orderId + '/products.json', { headers: apiHeaders() });
const products = productsRes.data.orderProducts || productsRes.data.products || [];

const autoService = bepaalTrunkrsService(products);
// Prioriteit: (1) expliciete serviceOverride die met DEZE aanvraag is
// meegestuurd (bv. het potloodje in Pack & Go, per-scan), (2) een via
// "Bewerk order" opgeslagen "Frozen zending"-vinkje (order._frozenOverride,
// al toegepast door applyOrderOverride() hierboven), (3) de automatische
// inschatting op basis van artikelcodes.
const persistedService = typeof order._frozenOverride === 'boolean'
? (order._frozenOverride ? 'SAME_DAY_FROZEN_FOOD' : 'SAME_DAY')
: null;
const service = (serviceOverride === 'SAME_DAY' || serviceOverride === 'SAME_DAY_FROZEN_FOOD') ? serviceOverride : (persistedService || autoService);
const payload = buildTrunkrsShipmentPayload(order, products, service);

const trunkrsRes = await axios.post(TRUNKRS_BASE_URL + '/shipments', payload, { headers: trunkrsHeaders() });
const shipment = trunkrsRes.data.data && trunkrsRes.data.data[0] ? trunkrsRes.data.data[0] : trunkrsRes.data.data;

// Kaal sleutelen (zie bareOrderNumberKey) i.p.v. String(order.number): anders
// belandt een order waarvan Lightspeed zelf al een "ORD..."-ordernummer
// teruggeeft ongestript in trunkrsLabelsStore/orderStatusStore, terwijl alle
// andere plekken in deze app die stores juist kaal gesleuteld lezen.
const orderKey = bareOrderNumberKey(order.number);
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

// Trunkrs levert label.pdf/label.zpl in de praktijk altijd als een https-URL
// naar hun eigen API (bv. https://api.trunkrs.nl/api/v2/shipments/.../label),
// die zelf weer met onze x-api-key beveiligd is. Een browser die zo'n URL
// rechtstreeks opent (window.open) stuurt die header niet mee en krijgt dus
// "Unauthorized" terug (ontdekt door Pieter bij het printen van ORD80535,
// 2026-08-31 - de eerste keer dat een echt Trunkrs-label ook echt geopend
// werd, i.p.v. alleen aangemaakt). Deze route haalt het bestand daarom
// server-side op (mét de API-key) en stuurt het door naar de browser.
async function fetchTrunkrsLabelBuffer(url) {
const r = await axios.get(url, { headers: trunkrsHeaders(), responseType: 'arraybuffer' });
return Buffer.from(r.data);
}

// Trunkrs levert het verzendlabel-PDF liggend aan (breder dan hoog, ca.
// 160x105mm), terwijl de Zebra-printers op de inpakstations al langer op
// staand etiketformaat staan ingesteld (nodig voor Sendcloud, dat wél
// staande labels levert - Pieter wil de printerinstellingen bewust niet
// aanpassen, dat zou Sendcloud juist weer breken). Zonder correctie wordt
// het liggende Trunkrs-PDF "noscale" op een staand canvas geplaatst en komt
// het gedraaid/afgesneden uit de printer (ontdekt 13-09-2026, foto van een
// fysiek label bevestigde het patroon 1-op-1 met een testrotatie van
// precies dit PDF). Draait hier daarom zelf 270° (tegen de klok in) zodat
// het label past op het al bestaande, ongewijzigde staande printerprofiel -
// zelfde aanpak als bij de printerdriver-omschakeling in PR #44: het
// probleem in software oplossen i.p.v. per-printer instellingen aanpassen.
// Raakt alleen de automatische print-agent-route hieronder; het handmatig
// bekijken/downloaden van een label (/api/trunkrs/label-file) blijft het
// PDF ongewijzigd tonen zoals Trunkrs het aanlevert.
async function rotateLandscapeLabelPdf(buffer) {
const pdfDoc = await PDFDocument.load(buffer);
const page = pdfDoc.getPage(0);
const { width, height } = page.getSize();
if (width > height) {
page.setRotation(degrees(270));
}
return Buffer.from(await pdfDoc.save());
}

// --- Pakbon-PDF-rendering (voor direct/silent printen naar de pakbonprinter) --
// Rendert de door de browser-client opgebouwde pakbon-HTML (dezelfde HTML
// die tot 2026-08-31 alleen via window.print() gebruikt werd) server-side
// naar echte PDF-bytes met puppeteer - dat is een echte (headless) Chromium,
// dus de al bestaande layout/CSS/barcode (JsBarcode) werkt hier ongewijzigd,
// zonder dat de pakbon-opmaak ergens opnieuw nagebouwd hoeft te worden.
// 1 gedeelde browserinstantie wordt hergebruikt over meerdere aanroepen heen
// (opstarten van Chromium kost ruim 1 seconde, dat wil je niet per pakbon
// opnieuw doen); alleen de pagina zelf wordt per aanroep geopend/gesloten.
let puppeteerBrowserPromise = null;
function getPuppeteerBrowser() {
  if (!puppeteerBrowserPromise) {
    const puppeteer = require('puppeteer');
    puppeteerBrowserPromise = puppeteer.launch({
      headless: 'new',
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    }).catch(function(e) { puppeteerBrowserPromise = null; throw e; });
  }
  return puppeteerBrowserPromise;
}
async function renderHtmlToPdf(html) {
  const browser = await getPuppeteerBrowser();
  const page = await browser.newPage();
  try {
    // networkidle0: de pakbon-HTML laadt JsBarcode via een <script src>
    // (CDN) om de barcode te tekenen - wachten tot dat script binnen is en
    // heeft kunnen draaien, anders is de barcode leeg op de PDF.
    await page.setContent(html, { waitUntil: 'networkidle0', timeout: 20000 });
    // Puppeteer v22+ geeft hier een Uint8Array terug i.p.v. een echte Node
    // Buffer - .toString('base64') daarop negeert de encoding stilzwijgend en
    // levert een kommagescheiden lijst getallen op i.p.v. base64 (gevonden
    // tijdens het lokaal testen van de pakbon-PDF-route, 2026-08-31). Expliciet
    // naar Buffer wrappen voorkomt dat.
    const bytes = await page.pdf({ printBackground: true, preferCSSPageSize: true });
    return Buffer.from(bytes);
  } finally {
    await page.close().catch(function(){});
  }
}

app.get('/api/trunkrs/label-file/:orderNumber', async (req, res) => {
const key = bareOrderNumberKey(req.params.orderNumber);
const tl = key && trunkrsLabelsStore[key];
if (!tl || !tl.label) return res.status(404).json({ error: 'Geen label bekend voor deze order.' });
const format = req.query.format === 'zpl' ? 'zpl' : 'pdf';
const src = format === 'zpl' ? tl.label.zpl : tl.label.pdf;
if (!src) return res.status(404).json({ error: 'Geen ' + format.toUpperCase() + '-data bekend voor dit label.' });
try {
if (/^https?:/i.test(src)) {
const buf = await fetchTrunkrsLabelBuffer(src);
res.set('Content-Type', format === 'zpl' ? 'text/plain; charset=utf-8' : 'application/pdf');
return res.send(buf);
}
// Testdata-fallback (mock-Trunkrs/lokale tests leveren soms al kant-en-
// klare data zonder tussenliggende URL): een data:-URI voor pdf, of kale
// ZPL-tekst - beide direct doorsturen, geen extra ophaalstap nodig.
if (format === 'pdf' && /^data:/i.test(src)) {
const b64 = src.split(',')[1] || '';
res.set('Content-Type', 'application/pdf');
return res.send(Buffer.from(b64, 'base64'));
}
res.set('Content-Type', 'text/plain; charset=utf-8');
return res.send(src);
} catch (e) {
const detail = e.response ? JSON.stringify(e.response.data) : e.message;
console.error('label-file proxy error voor order ' + key + ':', detail);
res.status(502).json({ error: 'Label ophalen bij Trunkrs mislukt: ' + detail });
}
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
    return {
      id: s.id,
      naam: s.naam,
      label: s.label,
      pakbon: s.pakbon,
      detectedPrinters: s.detectedPrinters || [],
      createdAt: s.createdAt,
      lastSeenAt: s.lastSeenAt || null
    };
  });
  res.json({ stations: stations });
});

// Sinds 12-09-2026 wordt hier bewust geen printer-IP/poort meer opgeslagen.
// We stuurden voorheen kale printertaal (ZPL) rechtstreeks over een TCP-
// socket naar het IP van de printer - dat werkt alleen als de printer die
// exacte taal ook spreekt (Zebra: ZPL). Op mini inpak bleek de Intermec PM43
// een andere printertaal (Fingerprint/IPL) te spreken: de bytes kwamen aan,
// de verbinding sloot netjes, maar er kwam niets uit - weer een ander,
// printermerk-specifiek probleem boven op de eerdere ZPL/base64-bugs. Op
// verzoek van Pieter (die hier terecht op wees dat Sendcloud ook geen
// per-merk-uitzonderingen heeft) printen we nu altijd op dezelfde, merk-
// onafhankelijke manier: het document als PDF stil afdrukken via de
// Windows-printerdriver (met SumatraPDF, zie buildPrintAgentScript) - die
// driver (Zebra's eigen driver, Intermec's eigen driver, of welk merk dan
// ook) zet een gewone PDF zelf om naar wat die printer nodig heeft. Daarom
// volstaat hier de Windows-printernaam (zoals Get-Printer 'm kent) i.p.v.
// IP+poort.
function parsePrinterConfig(input, fallbackFormaat) {
  const c = input || {};
  const printerNaam = c.printerNaam != null ? String(c.printerNaam).trim() : '';
  return {
    printerNaam: printerNaam,
    formaat: c.formaat ? String(c.formaat) : fallbackFormaat,
    previewFirst: c.previewFirst !== false
  };
}

app.post('/api/settings/print-stations', (req, res) => {
  const { naam, printerNaam } = req.body || {};
  const naamTrimmed = naam != null ? String(naam).trim() : '';
  const printerNaamTrimmed = printerNaam != null ? String(printerNaam).trim() : '';
  if (!naamTrimmed || !printerNaamTrimmed) return res.status(400).json({ error: 'Naam en Windows-printernaam (voor labels) zijn verplicht.' });
  const id = crypto.randomUUID();
  const token = crypto.randomBytes(24).toString('hex');
  printStationsStore[id] = {
    id: id,
    naam: naamTrimmed,
    token: token,
    createdAt: new Date().toISOString(),
    lastSeenAt: null,
    label: { printerNaam: printerNaamTrimmed, formaat: 'A6', previewFirst: true },
    // Pakbonprinter is bewust leeg bij aanmaken - Pieter vult 'm apart in via
    // de Afdrukopties-instellingen (of kiest 'm uit de door de print-agent
    // gedetecteerde Windows-printers), zodra de print-agent op deze pc draait.
    pakbon: { printerNaam: '', formaat: 'A4', previewFirst: true },
    detectedPrinters: []
  };
  savePrintStations(printStationsStore);
  res.json({ ok: true, id: id, naam: naamTrimmed, label: printStationsStore[id].label, pakbon: printStationsStore[id].pakbon });
});

// Werkt de label- en/of pakbon-printerconfiguratie van 1 station bij (naam,
// Windows-printernaam, formaat, preview-schakelaar). Overschrijft alleen de
// meegegeven delen - stuur bv. alleen { pakbon: {...} } mee om enkel de
// pakbonprinter aan te passen zonder de labelconfiguratie aan te raken.
app.patch('/api/settings/print-stations/:id', (req, res) => {
  const s = printStationsStore[req.params.id];
  if (!s) return res.status(404).json({ error: 'Station niet gevonden.' });
  const { naam, label, pakbon } = req.body || {};
  if (naam != null && String(naam).trim()) s.naam = String(naam).trim();
  if (label) s.label = parsePrinterConfig(label, 'A6');
  if (pakbon) s.pakbon = parsePrinterConfig(pakbon, 'A4');
  savePrintStations(printStationsStore);
  res.json({ ok: true, id: s.id, naam: s.naam, label: s.label, pakbon: s.pakbon });
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
// token/printernaam er al in verwerkt - de medewerker hoeft alleen nog maar
// "node print-agent.js" te draaien op die pc. Gebruikt verder alleen Node
// core modules; SumatraPDF (voor het echte, merkonafhankelijke printen, zie
// buildPrintAgentScript) wordt door het scriptje zelf eenmalig gedownload.
// Kan altijd opnieuw gedownload worden (bv. na het wijzigen van de gekozen
// printer) - het token wordt niet ingetrokken bij het downloaden.
app.get('/api/settings/print-stations/:id/agent-script', (req, res) => {
  const s = printStationsStore[req.params.id];
  if (!s) return res.status(404).send('Station niet gevonden.');
  const baseUrl = req.protocol + '://' + req.get('host');
  const script = buildPrintAgentScript({
    baseUrl: baseUrl,
    token: s.token,
    naam: s.naam,
    stationId: s.id,
    labelPrinterNaam: s.label.printerNaam,
    pakbonPrinterNaam: s.pakbon.printerNaam
  });
  const safeNaam = s.naam.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'station';
  res.set('Content-Type', 'application/javascript; charset=utf-8');
  res.set('Content-Disposition', 'attachment; filename="print-agent-' + safeNaam + '.js"');
  res.send(script);
});

// Kleine .bat-starter erbij (op verzoek van Pieter, 2026-08-31): zonder dit
// moest je elke keer zelf Command Prompt openen en "node ...js" intypen, wat
// in de praktijk best omslachtig bleek. Dit bestand mag je gewoon dubbel-
// klikken. Het zoekt zelf naar het print-agent-scriptje in dezelfde map (met
// een wildcard, want Windows plakt bij herhaald downloaden vanzelf "(1)",
// "(2)" etc. achter de bestandsnaam) i.p.v. een vaste naam te verwachten.
app.get('/api/settings/print-stations/:id/agent-launcher.bat', (req, res) => {
  const s = printStationsStore[req.params.id];
  if (!s) return res.status(404).send('Station niet gevonden.');
  const safeNaam = s.naam.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'station';
  const bat = buildPrintAgentLauncherBat({ naam: s.naam, safeNaam: safeNaam });
  res.set('Content-Type', 'application/bat; charset=utf-8');
  res.set('Content-Disposition', 'attachment; filename="start-print-agent-' + safeNaam + '.bat"');
  res.send(bat);
});

function buildPrintAgentLauncherBat(cfg) {
  // \r\n: Windows .bat-bestanden verwachten CRLF-regeleindes.
  //
  // Let op: "for %%f in (...)" (de vorige aanpak) doorloopt bestanden in de
  // volgorde die Windows toevallig teruggeeft - meestal alfabetisch, dus bij
  // een herhaalde download (Windows hangt dan zelf " (1)", " (2)", etc. aan
  // de bestandsnaam) kon dit een VEROUDERDE kopie van het scriptje pakken
  // i.p.v. de nieuwste, bijvoorbeeld nog een kopie van vóór een serverfix.
  // "dir /b /o-d" sorteert i.p.v. daarvan op laatst-gewijzigd-datum (nieuwste
  // eerst), zodat altijd het meest recent gedownloade scriptje gebruikt
  // wordt, ook als er per ongeluk oudere kopieën in dezelfde map staan
  // (gevonden op verzoek van Pieter, 2026-08-31, na een HTTP-301-fout die
  // bleek te komen van een oud scriptje dat de .bat nog steeds oppikte).
  return [
    '@echo off',
    'cd /d "%~dp0"',
    'echo Print-agent voor station "' + cfg.naam + '" wordt gestart...',
    'echo Laat dit venster openstaan zolang je labels wilt kunnen printen.',
    'echo.',
    'set GEVONDEN=0',
    'for /f "delims=" %%f in (\'dir /b /o-d "print-agent-' + cfg.safeNaam + '*.js" 2^>nul\') do (',
    '  set GEVONDEN=1',
    '  node "%%f"',
    '  goto :klaar',
    ')',
    'if %GEVONDEN%==0 echo Kon het print-agent-scriptje (print-agent-' + cfg.safeNaam + '*.js) niet vinden in deze map.',
    ':klaar',
    'pause'
  ].join('\r\n') + '\r\n';
}

function buildPrintAgentScript(cfg) {
  return [
    '// LJ Verzending — print-agent voor station "' + cfg.naam + '"',
    '// Automatisch gegenereerd - draai dit met: node print-agent.js',
    '// Gebruikt alleen Node core modules; SumatraPDF (zie printPdfOnPrinter',
    '// hieronder) wordt bij het eerste label/pakbon automatisch eenmalig',
    '// gedownload, geen handmatige installatie nodig.',
    '//',
    '// Sinds 12-09-2026: printen gaat altijd via de Windows-printerdriver (PDF',
    '// -> SumatraPDF -> gekozen Windows-printernaam), nooit meer via een kale',
    '// TCP-verbinding met printertaal-specifieke bytes (ZPL e.d.) rechtstreeks',
    '// naar een IP-adres. Dat laatste bleek niet merkonafhankelijk: op mini',
    '// inpak sprak de Intermec PM43 gewoon een andere printertaal dan de',
    '// Zebra, dus kwam er - ondanks een geslaagde TCP-verbinding - niets uit.',
    '// Door altijd de Windows-driver te gebruiken (net als bij een gewoon',
    '// "Print"-commando, en zoals Sendcloud dit ook doet) is er precies 1',
    '// codepad voor elk printermerk: de driver zet de PDF zelf om naar wat',
    '// die specifieke printer nodig heeft. Herdownload dit bestand als de',
    '// gekozen printer voor dit station wijzigt.',
    "const http = require('http');",
    "const https = require('https');",
    "const fs = require('fs');",
    "const os = require('os');",
    "const path = require('path');",
    "const { exec, execFile } = require('child_process');",
    '',
    'const BASE_URL = ' + JSON.stringify(cfg.baseUrl) + ';',
    'const TOKEN = ' + JSON.stringify(cfg.token) + ';',
    'const STATION_ID = ' + JSON.stringify(cfg.stationId) + ';',
    'const STATION_NAAM = ' + JSON.stringify(cfg.naam) + ';',
    'const APP_ORIGIN = ' + JSON.stringify(cfg.baseUrl) + ';',
    'const LABEL_PRINTER_NAAM = ' + JSON.stringify(cfg.labelPrinterNaam) + ';',
    'const PAKBON_PRINTER_NAAM = ' + JSON.stringify(cfg.pakbonPrinterNaam) + ';',
    'const POLL_MS = 3000;',
    'const DISCOVER_MS = 60000;',
    'const LOCAL_STATUS_PORT = 9743;',
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
    '// --- SumatraPDF: eenmalig, automatisch downloaden + uitpakken --------',
    '// Vaste versie (i.p.v. een "laatste versie"-link) zodat dit stabiel',
    '// blijft werken en niet op een onaangekondigd moment ander gedrag krijgt.',
    'const SUMATRA_VERSION = "3.6.1";',
    'const SUMATRA_ZIP_URL = "https://www.sumatrapdfreader.org/dl/rel/" + SUMATRA_VERSION + "/SumatraPDF-" + SUMATRA_VERSION + "-64.zip";',
    'const SUMATRA_EXE = path.join(__dirname, "SumatraPDF.exe");',
    'let sumatraReadyPromise = null;',
    '',
    'function downloadFile(url, destPath) {',
    '  return new Promise(function(resolve, reject) {',
    '    const file = fs.createWriteStream(destPath);',
    '    https.get(url, function(res) {',
    '      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {',
    '        file.close();',
    '        fs.unlink(destPath, function() {});',
    '        downloadFile(res.headers.location, destPath).then(resolve, reject);',
    '        return;',
    '      }',
    '      if (res.statusCode !== 200) {',
    '        file.close();',
    '        fs.unlink(destPath, function() {});',
    '        reject(new Error("download mislukt (HTTP " + res.statusCode + ")"));',
    '        return;',
    '      }',
    '      res.pipe(file);',
    '      file.on("finish", function() { file.close(resolve); });',
    '    }).on("error", function(e) {',
    '      fs.unlink(destPath, function() {});',
    '      reject(e);',
    '    });',
    '  });',
    '}',
    '',
    'function psQuote(s) {',
    '  return "\'" + String(s).replace(/\'/g, "\'\'") + "\'";',
    '}',
    '',
    '// Zet zichzelf maar 1x in werking, ook als er meerdere printjobs vlak na',
    '// elkaar binnenkomen terwijl de download nog bezig is (sumatraReadyPromise',
    '// wordt hergebruikt i.p.v. dat elke job een eigen download start).',
    'function ensureSumatraPdf() {',
    '  if (fs.existsSync(SUMATRA_EXE)) return Promise.resolve(SUMATRA_EXE);',
    '  if (sumatraReadyPromise) return sumatraReadyPromise;',
    '  sumatraReadyPromise = (async function() {',
    '    console.log("[print-agent] SumatraPDF (voor stil printen via de Windows-printerdriver) wordt eenmalig gedownload...");',
    '    const zipPath = path.join(__dirname, "sumatra-download.zip");',
    '    await downloadFile(SUMATRA_ZIP_URL, zipPath);',
    '    await new Promise(function(resolve, reject) {',
    '      const psCmd = "Expand-Archive -LiteralPath " + psQuote(zipPath) + " -DestinationPath " + psQuote(__dirname) + " -Force";',
    '      const encoded = Buffer.from(psCmd, "utf16le").toString("base64");',
    '      exec("powershell -NoProfile -NonInteractive -EncodedCommand " + encoded, { timeout: 30000 }, function(err) {',
    '        if (err) { reject(err); return; }',
    '        resolve();',
    '      });',
    '    });',
    '    fs.unlink(zipPath, function() {});',
    '    const gevonden = fs.readdirSync(__dirname).filter(function(f) { return /^SumatraPDF.*\\.exe$/i.test(f); });',
    '    if (!gevonden.length) throw new Error("kon SumatraPDF.exe niet vinden na het uitpakken");',
    '    const uitgepakt = path.join(__dirname, gevonden[0]);',
    '    if (uitgepakt !== SUMATRA_EXE) fs.copyFileSync(uitgepakt, SUMATRA_EXE);',
    '    console.log("[print-agent] SumatraPDF gereed.");',
    '    return SUMATRA_EXE;',
    '  })();',
    '  return sumatraReadyPromise;',
    '}',
    '',
    '// --- Printen: altijd dezelfde weg, ongeacht printermerk -----------------',
    '// pdfBuffer gaat naar een tijdelijk bestand en wordt daarna stil (geen',
    '// vensters, geen printvenster) via SumatraPDF naar de opgegeven Windows-',
    '// printernaam gestuurd - exact dezelfde manier als een normale "Print"-',
    '// opdracht vanuit een programma, alleen dan zonder de dialoogvensters.',
    '// "-print-settings noscale": het PDF-document (Trunkrs-label of onze',
    '// eigen pakbon) staat al op het juiste formaat, dus niet laten schalen.',
    'function printPdfOnPrinter(printerNaam, pdfBuffer) {',
    '  return ensureSumatraPdf().then(function(sumatraPath) {',
    '    return new Promise(function(resolve, reject) {',
    '      if (!printerNaam) { reject(new Error("Geen Windows-printer ingesteld voor dit documenttype.")); return; }',
    '      const tmpFile = path.join(os.tmpdir(), "lj-print-" + Date.now() + "-" + Math.random().toString(36).slice(2) + ".pdf");',
    '      fs.writeFile(tmpFile, pdfBuffer, function(err) {',
    '        if (err) { reject(err); return; }',
    '        execFile(sumatraPath, ["-print-to", printerNaam, "-silent", "-exit-when-done", "-print-settings", "noscale", tmpFile], { timeout: 30000 }, function(err2) {',
    '          fs.unlink(tmpFile, function() {});',
    '          if (err2) { reject(new Error("SumatraPDF-printopdracht mislukt (printernaam \'" + printerNaam + "\' correct overgenomen uit Windows?): " + err2.message)); return; }',
    '          resolve();',
    '        });',
    '      });',
    '    });',
    '  });',
    '}',
    '',
    'async function tick() {',
    '  try {',
    '    const jobs = await apiRequest("GET", "/api/print-agent/jobs");',
    '    for (const job of (jobs.jobs || [])) {',
    '      try {',
    '        const printerNaam = job.type === "pakbon" ? PAKBON_PRINTER_NAAM : LABEL_PRINTER_NAAM;',
    '        await printPdfOnPrinter(printerNaam, Buffer.from(job.content, "base64"));',
    '        await apiRequest("POST", "/api/print-agent/jobs/" + job.id + "/ack", { ok: true });',
    '        console.log("[print-agent] " + job.type + " geprint voor order " + job.orderNumber);',
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
    '// Vraagt Windows via PowerShell om de namen van alle geïnstalleerde',
    '// printers (netwerk én USB - dat laatste kon met de oude IP-gebaseerde',
    '// aanpak niet, want die had een netwerkadres nodig; via de Windows-driver',
    '// maakt dat niet meer uit) voor het printerkeuzemenu in de instellingen.',
    'const PS_CMD = "Get-Printer | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress";',
    '',
    '// -EncodedCommand (base64 UTF-16LE) i.p.v. de PowerShell-opdracht als',
    '// tekst mee te geven - dat laatste struikelt al snel over de dubbele',
    '// aanhalingstekens die ConvertTo-Json nodig heeft zodra dit ook nog eens',
    '// door de Windows-shell heen moet. Dit is de standaard, escape-vrije',
    '// manier om een PowerShell-opdracht vanuit Node.js aan te roepen.',
    'function discoverPrinters() {',
    '  if (process.platform !== "win32") return; // alleen zinvol op de Windows-pc\'s van de inpakstations',
    '  const encoded = Buffer.from(PS_CMD, "utf16le").toString("base64");',
    '  exec("powershell -NoProfile -NonInteractive -EncodedCommand " + encoded, { timeout: 15000 }, function(err, stdout) {',
    '    if (err) { console.error("[print-agent] printer-detectie mislukt:", err.message); return; }',
    '    let parsed;',
    '    try { parsed = JSON.parse((stdout || "").trim() || "[]"); } catch (e) { console.error("[print-agent] kon printerlijst niet lezen:", e.message); return; }',
    '    const list = Array.isArray(parsed) ? parsed : (parsed ? [parsed] : []);',
    '    const printers = list.filter(Boolean).map(function(naam) { return { name: String(naam) }; });',
    '    apiRequest("POST", "/api/print-agent/printers", { printers: printers }).catch(function(e) {',
    '      console.error("[print-agent] kon gedetecteerde printers niet doorgeven:", e.message);',
    '    });',
    '  });',
    '}',
    '',
    '// Klein lokaal statuspunt, alleen bereikbaar vanaf déze pc zelf',
    '// (127.0.0.1) - hierdoor kan Pack & Go in de browser, zolang die op',
    '// dezelfde pc open staat, vanzelf herkennen welk inpakstation dit is,',
    '// zonder dat iemand dat handmatig moet aangeven of onthouden. Zelfde',
    '// principe als Sendcloud\'s eigen download-print-client. Draait er om',
    '// wat voor reden dan ook geen print-agent op een pc, dan blijft alles',
    '// gewoon werken zoals voorheen (browser-printvenster als terugval).',
    'function startLocalStatusServer() {',
    '  const server = http.createServer(function(req, res) {',
    '    res.setHeader("Access-Control-Allow-Origin", APP_ORIGIN);',
    '    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");',
    '    res.setHeader("Access-Control-Allow-Headers", "Content-Type");',
    '    // Chrome/Edge vereisen dit expliciet (Private Network Access) zodra',
    '    // een https-pagina een lokaal adres (127.0.0.1) aanroept - zonder',
    '    // deze header wordt de aanvraag stilzwijgend geblokkeerd.',
    '    res.setHeader("Access-Control-Allow-Private-Network", "true");',
    '    if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }',
    '    if (req.method === "GET" && req.url.indexOf("/lj-print-agent-status") === 0) {',
    '      res.setHeader("Content-Type", "application/json; charset=utf-8");',
    '      res.writeHead(200);',
    '      res.end(JSON.stringify({ ok: true, stationId: STATION_ID, naam: STATION_NAAM }));',
    '      return;',
    '    }',
    '    res.writeHead(404);',
    '    res.end();',
    '  });',
    '  server.on("error", function(e) {',
    '    console.error("[print-agent] kon lokaal statuspunt (poort " + LOCAL_STATUS_PORT + ") niet starten - draait hier per ongeluk al een andere print-agent? Automatische stationherkenning in Pack & Go werkt dan niet mee, maar het printen zelf (via printjobs) blijft gewoon werken. Details: " + e.message);',
    '  });',
    '  server.listen(LOCAL_STATUS_PORT, "127.0.0.1", function() {',
    '    console.log("[print-agent] lokaal statuspunt actief op http://127.0.0.1:" + LOCAL_STATUS_PORT + " (voor automatische stationherkenning door Pack & Go op deze pc)");',
    '  });',
    '}',
    '',
    'console.log("[print-agent] gestart voor station \\"' + cfg.naam + '\\""); ',
    'console.log("[print-agent] label -> Windows-printer " + JSON.stringify(LABEL_PRINTER_NAAM || "(niet ingesteld)") + ", pakbon -> " + JSON.stringify(PAKBON_PRINTER_NAAM || "(niet ingesteld)"));',
    'console.log("[print-agent] elke " + (POLL_MS/1000) + "s printjobs ophalen bij " + BASE_URL);',
    'tick();',
    'discoverPrinters();',
    'setInterval(discoverPrinters, DISCOVER_MS);',
    'startLocalStatusServer();',
    ''
  ].join('\n');
}

// Stuurt het (al aangemaakte) Trunkrs-verzendlabel van 1 order als printjob
// naar 1 specifiek inpakstation.
//
// Tot 11-09-2026 gebruikte dit de rauwe ZPL die Trunkrs meelevert, rechtstreeks
// naar het IP van de labelprinter. Dat bleek geen begaanbare weg: eerst zat
// er een dubbele base64-laag in (zie de git-historie van dit bestand voor
// die uitzoekerij), en toen dát opgelost was bleek de Intermec PM43 op mini
// inpak sowieso een andere printertaal te spreken dan de Zebra op Kantoor
// Pieter - ZPL is geen universele taal, elk printermerk heeft zijn eigen.
//
// Sinds 12-09-2026 (op verzoek van Pieter, die er terecht op wees dat
// Sendcloud ook geen printer-specifieke uitzonderingen heeft) gebruiken we
// daarom altijd de PDF-variant van het label en printen die stil via de
// Windows-printerdriver (zie buildPrintAgentScript/printPdfOnPrinter) - die
// driver zet 'm zelf om naar wat de aangesloten printer nodig heeft, welk
// merk dat ook is. Dit is exact dezelfde weg als de pakbon hieronder al
// gebruikte, dus label en pakbon delen nu ook echt 1 printpad.
app.post('/api/print-stations/:id/print-label', async (req, res) => {
  const station = printStationsStore[req.params.id];
  if (!station) return res.status(404).json({ error: 'Station niet gevonden.' });
  const { orderNumber } = req.body || {};
  const key = bareOrderNumberKey(orderNumber);
  const tl = key && trunkrsLabelsStore[key];
  if (!tl) return res.status(404).json({ error: 'Geen Trunkrs-label bekend voor deze order.' });
  const pdfSrc = tl.label && tl.label.pdf;
  if (!pdfSrc) return res.status(422).json({ error: 'Dit label heeft geen PDF-data (onverwacht - normaal levert Trunkrs dit altijd mee).' });
  let pdfBuffer;
  try {
    if (/^https?:/i.test(pdfSrc)) {
      // Trunkrs levert hier in de praktijk een https-URL (met auth erachter,
      // vandaar server-side ophalen i.p.v. de url zelf doorgeven - zie ook
      // /api/trunkrs/label-file hieronder waar hetzelfde speelde).
      pdfBuffer = await fetchTrunkrsLabelBuffer(pdfSrc);
    } else if (/^data:/i.test(pdfSrc)) {
      // Testdata-fallback (mock-Trunkrs levert soms al een kant-en-klare
      // data:-URI zonder tussenliggende url).
      pdfBuffer = Buffer.from(pdfSrc.split(',')[1] || '', 'base64');
    } else {
      pdfBuffer = Buffer.from(pdfSrc, 'base64');
    }
  } catch (e) {
    const detail = e.response ? JSON.stringify(e.response.data) : e.message;
    console.error('print-label: PDF ophalen bij Trunkrs mislukt voor order ' + key + ':', detail);
    return res.status(502).json({ error: 'Label ophalen bij Trunkrs mislukt: ' + detail });
  }
  try {
    pdfBuffer = await rotateLandscapeLabelPdf(pdfBuffer);
  } catch (e) {
    // Mag het aanmaken van de printjob niet blokkeren - dan liever het
    // origineel (mogelijk verkeerd gedraaid) label printen dan helemaal
    // niets. Zou normaal nooit mogen gebeuren (Trunkrs levert altijd een
    // geldig PDF), dus wel loggen om op te vallen.
    console.error('print-label: label roteren mislukt voor order ' + key + ':', e.message);
  }
  const jobId = crypto.randomUUID();
  printJobsStore[jobId] = {
    id: jobId,
    stationId: station.id,
    orderNumber: key,
    type: 'label',
    content: pdfBuffer.toString('base64'),
    status: 'pending',
    createdAt: new Date().toISOString(),
    deliveredAt: null,
    doneAt: null,
    error: null
  };
  savePrintJobs(printJobsStore);
  res.json({ ok: true, jobId: jobId });
});

// Rendert de door de klant/client al opgebouwde pakbon-HTML (dezelfde HTML
// die tot 2026-08-31 rechtstreeks naar een nieuw browsertabblad ging voor
// window.print()) server-side naar echte PDF-bytes en stuurt die als
// printjob (type 'pakbon') naar de pakbonprinter van 1 specifiek inpakstation.
// Hergebruikt bewust de bestaande, al werkende pakbon-layout/-opmaak in
// plaats van die server-side opnieuw op te bouwen - puppeteer rendert exact
// dezelfde HTML/CSS/JS (incl. de JsBarcode-barcode) als de browser zou doen.
app.post('/api/print-stations/:id/print-pakbon', async (req, res) => {
  const station = printStationsStore[req.params.id];
  if (!station) return res.status(404).json({ error: 'Station niet gevonden.' });
  const { html, orderNumbers } = req.body || {};
  if (!html || typeof html !== 'string') return res.status(400).json({ error: 'Geen pakbon-HTML meegegeven.' });
  try {
    const pdfBuffer = await renderHtmlToPdf(html);
    const jobId = crypto.randomUUID();
    printJobsStore[jobId] = {
      id: jobId,
      stationId: station.id,
      orderNumber: Array.isArray(orderNumbers) ? orderNumbers.map(bareOrderNumberKey).join(',') : '',
      type: 'pakbon',
      content: pdfBuffer.toString('base64'),
      status: 'pending',
      createdAt: new Date().toISOString(),
      deliveredAt: null,
      doneAt: null,
      error: null
    };
    savePrintJobs(printJobsStore);
    res.json({ ok: true, jobId: jobId });
  } catch (e) {
    console.error('print-pakbon: PDF-rendering mislukt:', e.message);
    res.status(502).json({ error: 'Pakbon omzetten naar PDF mislukt: ' + e.message });
  }
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
  res.json({ jobs: jobs.map(function(j) { return { id: j.id, orderNumber: j.orderNumber, type: j.type || 'label', content: j.content != null ? j.content : j.zpl, createdAt: j.createdAt }; }) });
});

// Ontvangt de door de print-agent gedetecteerde Windows-printers (zie
// discoverPrinters() in buildPrintAgentScript) en bewaart ze bij het
// station, zodat de instellingenpagina er een keuzelijst van kan tonen i.p.v.
// dat Pieter zelf de exacte Windows-printernaam moet opzoeken en overtypen.
// Sinds 12-09-2026 alleen nog de naam (geen IP meer nodig, want er wordt
// altijd via de Windows-driver geprint - dat werkt dus ook voor USB-
// aangesloten printers, die voorheen niet in deze lijst konden voorkomen).
app.post('/api/print-agent/printers', requirePrintAgentToken, (req, res) => {
  const station = req.printStation;
  const { printers } = req.body || {};
  station.detectedPrinters = Array.isArray(printers)
    ? printers.filter(function(p) { return p && p.name; }).map(function(p) { return { name: String(p.name).trim() }; })
    : [];
  station.lastSeenAt = new Date().toISOString();
  savePrintStations(printStationsStore);
  res.json({ ok: true });
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
const key = bareOrderNumberKey(orderNumber);
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
const key = bareOrderNumberKey(orderNumber);
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
