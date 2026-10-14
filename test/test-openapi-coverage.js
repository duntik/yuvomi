/**
 * Modul: OpenAPI-Vollstaendigkeit
 * Zweck: Jede Route unter /api/v1 steht auch in der Spec.
 *
 * WARUM DAS EIN EIGENER GUARD IST. `/api/v1` ist seit v2.7.1 eine ZUGESAGTE
 * Oberflaeche: die Spec ist das, was ein Integrator liest, und was dort fehlt,
 * existiert fuer ihn nicht. test:openapi-structure sichert bisher nur die
 * FORM der Fragment-Dateien - dass jede importiert und gespreadet ist. Ob die
 * Spec den Code trifft, hat nie jemand geprueft.
 *
 * Gemessen am 2026-08-29, als der erste Anlass auffiel (POST
 * /auth/onboarding-seen kam mit #911 dazu und stand nirgends): 34 von 297
 * Routen fehlten, darunter vier VOLLSTAENDIGE Module - quick-links,
 * screensaver, recipe-providers und permissions. Kein einziger Test hat das je
 * gemeldet, weil keiner in diese Richtung geschaut hat.
 *
 * DER GUARD FOLGT DEN ROUTERN, NICHT EINER DATEILISTE. Vier Module (budget,
 * calendar, health, inventory) verteilen ihre Routen auf Unterdateien, die der
 * gemountete Router seinerseits einbindet. Ein Guard, der nur die in
 * server/index.js genannte Datei liest, waere fuer diese Routen blind - und
 * zwar still: er faende weniger Verstoesse und saehe deshalb gruener aus.
 *
 * Ausfuehren: node --test test/test-openapi-coverage.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildOpenApiSpec } from '../server/openapi.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const INDEX = readFileSync(resolve(ROOT, 'server/index.js'), 'utf8');

const spec = buildOpenApiSpec({});

/**
 * `app.use('/api/v1/x', xRouter)` - der erste Mount je Router gewinnt.
 *
 * NUR NAMEN AUF `Router`, und der Grund ist ein gemessener Fehlalarm: unter
 * `/api/v1` haengen ausser den Routern auch `requireAuth`, `csrfMiddleware` und
 * `idempotencyMiddleware`. `requireAuth` kommt aus server/auth.js - DERSELBEN
 * Datei wie `authRouter`. Ohne diesen Filter wurde auth.js zweimal
 * ausgewertet, einmal korrekt unter `/api/v1/auth` und einmal unter `/api/v1`,
 * und der Guard meldete 26 Routen als undokumentiert, die es unter dem
 * erfundenen Pfad `/api/v1/2fa/setup` nie gab. Ein Guard, der Falsches meldet,
 * wird abgeschaltet statt befolgt.
 */
function routerMounts() {
  const mounts = new Map();
  for (const m of INDEX.matchAll(/app\.use\(\s*'(\/api\/v1[^']*)'\s*,\s*(?:[\w.]+\s*,\s*)*(\w+)\s*\)/g)) {
    if (!m[2].endsWith('Router')) continue;
    if (!mounts.has(m[2])) mounts.set(m[2], m[1]);
  }
  return mounts;
}

/**
 * Importname -> Datei, fuer alles was aus server/ kommt.
 *
 * BEIDE IMPORTFORMEN, und das ist kein Detail: der Auth-Router kommt als
 * `import { router as authRouter, ... } from './auth.js'`. Ein Regex, der nur
 * den Default-Import kennt, sieht ihn nicht - und dann faellt der GANZE
 * /auth-Zweig aus der Pruefung, ohne dass etwas rot wird. Der Guard sah dabei
 * gruener aus, nicht roter.
 */
function routerFiles() {
  const files = new Map();
  for (const m of INDEX.matchAll(/import\s+(\w+)\s+from\s+'\.\/([\w./-]+\.js)'/g)) {
    files.set(m[1], resolve(ROOT, 'server', m[2]));
  }
  for (const m of INDEX.matchAll(/import\s+\{([^}]+)\}\s+from\s+'\.\/([\w./-]+\.js)'/g)) {
    for (const part of m[1].split(',')) {
      const alias = part.trim().split(/\s+as\s+/).pop().trim();
      if (alias && !files.has(alias)) files.set(alias, resolve(ROOT, 'server', m[2]));
    }
  }
  return files;
}

/**
 * Routen, die index.js selbst haelt (`app.get('/api/v1/version', ...)`).
 *
 * Sie gehen durch keinen Router und wuerden der Gegenrichtung sonst als
 * "Spec verspricht etwas, das es nicht gibt" auffallen - eine Falschmeldung,
 * die den Guard unglaubwuerdig macht.
 */
function directAppRoutes() {
  return [...INDEX.matchAll(/app\.(get|post|put|patch|delete)\(\s*'(\/api\/v1[^']*)'/g)]
    .map((m) => ({ verb: m[1], path: m[2].replace(/:(\w+)/g, '{$1}'), file: 'server/index.js' }));
}

/**
 * Alle Router-Dateien ab `entry`, JE MIT IHREM EIGENEN PRAEFIX.
 *
 * DER SUB-MOUNT IST DER GANZE PUNKT. `inventory/index.js` haengt seine fuenf
 * Unterrouter unter `/locations`, `/categories`, `/items`, `/entries` und
 * `/deadlines-feed` ein. Wer allen Unterdateien den Mount des Elternrouters
 * gibt, erfindet Pfade wie `/api/v1/inventory/{key}`, die es nie gab - und
 * meldet sie dann als fehlende Doku. Ein Guard, der falsche Befunde
 * produziert, wird abgeschaltet, nicht befolgt.
 *
 * Erfasst wird deshalb `router.use('<pfad>', <name>)` zusammen mit dem Import,
 * aus dem `<name>` stammt. Ein `router.use` ohne Pfad (Middleware) aendert den
 * Praefix nicht.
 */
function routerSources(entry, prefix = '', seen = new Map()) {
  if (seen.has(entry) || !existsSync(entry)) return seen;
  seen.set(entry, prefix);
  const src = readFileSync(entry, 'utf8');

  const imports = new Map();
  for (const m of src.matchAll(/import\s+(\w+)\s+from\s+'(\.[^']+\.js)'/g)) {
    imports.set(m[1], resolve(dirname(entry), m[2]));
  }

  const mounted = new Set();
  for (const m of src.matchAll(/router\.use\(\s*'([^']*)'\s*,\s*(?:[\w.]+\s*,\s*)*(\w+)\s*\)/g)) {
    const file = imports.get(m[2]);
    if (!file) continue;
    mounted.add(file);
    routerSources(file, prefix + m[1].replace(/\/+$/, ''), seen);
  }

  // Aufgeteilte Module ohne Sub-Mount (calendar/, budget/, health/) haengen
  // ihre Teile per `router.use(x)` oder als Re-Export ein - sie teilen den
  // Praefix des Elternrouters.
  for (const [, file] of imports) {
    if (mounted.has(file)) continue;
    if (!file.includes(`${resolve(ROOT, 'server/routes')}${sep}`)) continue;
    routerSources(file, prefix, seen);
  }
  return seen;
}

/**
 * Die Routen einer Datei, als OpenAPI-Pfad geschrieben.
 *
 * `:id` wird zu `{id}`, die Express-5-Wildcard `{*rest}` behaelt ihren Namen
 * als `{rest}` - genau so schreibt die Spec sie.
 *
 * DIE ROUTER-VARIABLE HEISST NICHT IMMER `router`. In server/auth.js legt eine
 * Fabrik ihre Routen auf `targetRouter`; ein Regex, der nur `router.` kennt,
 * uebersieht /forgot-password, /reset-password und den ganzen /invites-Zweig -
 * und meldet sie dann als Zusage ohne Code. Wieder ein Fall, in dem die
 * Blindheit den Guard GRUENER aussehen laesst.
 */
function routesIn(file, mount) {
  const src = readFileSync(file, 'utf8');
  const out = [];
  for (const m of src.matchAll(/\b\w*[Rr]outer\.(get|post|put|patch|delete|all)\(\s*'([^']*)'/g)) {
    const path = m[2]
      .replace(/\{\*(\w+)\}/g, '{$1}')
      .replace(/:(\w+)/g, '{$1}')
      .replace(/\/+$/, '');
    const full = (mount + (path === '/' ? '' : path)).replace(/\/+$/, '') || mount;
    // `router.all` deckt jede Methode ab - fuer die Spec zaehlt es als GET.
    out.push({ verb: m[1] === 'all' ? 'get' : m[1], path: full, file });
  }
  return out;
}

function allRoutes() {
  const mounts = routerMounts();
  const files  = routerFiles();
  const routes = [];
  for (const [name, mount] of mounts) {
    const entry = files.get(name);
    if (!entry) continue;
    for (const [source, prefix] of routerSources(entry)) {
      routes.push(...routesIn(source, mount + prefix));
    }
  }
  routes.push(...directAppRoutes());
  return routes;
}

/**
 * Bewusst nicht dokumentiert - jede Zeile nennt ihren Grund.
 *
 * DERZEIT LEER, und das ist der richtige Zustand: als der Guard entstand, waren
 * alle 40 offenen Routen echte Luecken und keine davon eine bewusste Ausnahme.
 * Die Liste bleibt trotzdem stehen, weil es eine geben KANN - dann aber mit
 * einem Grund an Ort und Stelle. Eine Ausnahme ohne Begruendung ist eine
 * Luecke mit besserer Tarnung.
 */
const INTENTIONALLY_UNDOCUMENTED = new Map([]);

test('jede Route unter /api/v1 steht in der OpenAPI-Spec', () => {
  const routes = allRoutes();

  // Gegen einen Guard, der nur deshalb gruen ist, weil er nichts findet: die
  // Zahl darf schwanken, aber nicht einbrechen.
  assert.ok(routes.length > 250,
    `unerwartet wenige Routen gefunden (${routes.length}) - der Router-Verfolger greift nicht mehr`);

  const missing = routes
    .filter((r) => !spec.paths[r.path]?.[r.verb])
    .map((r) => `${r.verb.toUpperCase()} ${r.path}`)
    .filter((label) => !INTENTIONALLY_UNDOCUMENTED.has(label));

  assert.deepEqual([...new Set(missing)].sort(), [],
    'Diese Routen fehlen in der Spec. /api/v1 ist eine zugesagte Oberflaeche - was dort nicht '
    + 'steht, existiert fuer einen Integrator nicht:\n  ' + [...new Set(missing)].sort().join('\n  '));
});

test('der Router-Verfolger sieht auch die aufgeteilten Module', () => {
  // Ohne diese Probe koennte der Test oben gruen sein, weil er budget/,
  // calendar/, health/ und inventory/ gar nicht erreicht - der teuerste Fall,
  // weil er wie Abdeckung aussieht.
  const routes = allRoutes();
  for (const part of ['routes/calendar/', 'routes/budget/', 'routes/health/', 'routes/inventory/']) {
    assert.ok(routes.some((r) => r.file.split(sep).join('/').includes(part)),
      `keine Route aus ${part} gefunden - der Verfolger geht nicht in die Unterdateien`);
  }
});

test('die Spec beschreibt keine Route, die es nicht gibt', () => {
  // Die Gegenrichtung: eine Zusage ohne Code ist so falsch wie fehlende Doku,
  // nur schwerer zu bemerken - sie faellt erst dem Integrator auf, der sie ruft.
  const real = new Set(allRoutes().map((r) => `${r.verb} ${r.path}`));
  const phantom = [];
  for (const [path, ops] of Object.entries(spec.paths)) {
    if (!path.startsWith('/api/v1/')) continue;
    for (const verb of Object.keys(ops)) {
      if (!['get', 'post', 'put', 'patch', 'delete'].includes(verb)) continue;
      if (!real.has(`${verb} ${path}`)) phantom.push(`${verb.toUpperCase()} ${path}`);
    }
  }
  assert.deepEqual(phantom.sort(), [],
    `Die Spec verspricht Routen, die kein Router bedient:\n  ${phantom.sort().join('\n  ')}`);
});
