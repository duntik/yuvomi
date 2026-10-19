/**
 * Modul: Ergebnis eines Sync-Laufs festhalten (#820)
 * Zweck: Ein gescheiterter Google-/Apple-Sync stand bisher nur im Serverlog. Für
 *        den Haushalt sah das aus wie ein Kalender, der einfach aufhört zu
 *        aktualisieren - der Melder von #820 bemerkte es erst nach zwei Wochen
 *        und an den Dubletten, die der Wiederanschluss hinterließ. Der letzte
 *        Fehler gehört deshalb dorthin, wo der Nutzer nach dem Sync schaut.
 *
 * Warum sync_config und keine Migration: Google und Apple haben keine
 * Kontotabelle - ihre gesamte Verbindung liegt als Schlüssel/Wert in
 * `sync_config`. Ein zusätzliches Schlüsselpaar je Provider ist hier dasselbe,
 * was `carddav_accounts.last_error` (Migration 92) für CardDAV ist, und braucht
 * kein Schema.
 *
 * Abhängigkeiten: keine externen.
 */

import { createLogger } from '../logger.js';

const log = createLogger('SyncOutcome');

// Dieselbe Deckelung wie bei CardDAV (server/services/cardav-sync.js): ein
// Stacktrace oder eine HTML-Fehlerseite als Wert würde die Statuszeile sprengen.
const MAX_SYNC_ERROR_LENGTH = 500;

const errorKey = (provider) => `${provider}_last_error`;
const errorAtKey = (provider) => `${provider}_last_error_at`;

/**
 * Hält fest, wie ein Lauf ausgegangen ist.
 *
 * ERFOLG MUSS AKTIV LÖSCHEN: „kein Eintrag" heißt „zuletzt lief alles durch".
 * Bliebe ein alter Fehler stehen, meldete die UI einen Ausfall, den der nächste
 * Lauf längst behoben hat - und der Nutzer lernt, die Warnung zu übersehen.
 *
 * Der Sync selbst darf hieran nicht scheitern: ein Schreibfehler wird geloggt
 * und verschluckt, nie geworfen.
 *
 * @param {object} database
 * @param {string} provider  'google' | 'apple'
 * @param {Error|string|null} error  null = sauberer Lauf
 */
export function recordSyncOutcome(database, provider, error) {
  try {
    if (!error) {
      database.prepare('DELETE FROM sync_config WHERE key IN (?, ?)')
        .run(errorKey(provider), errorAtKey(provider));
      return;
    }
    const message = String(error?.message || error).slice(0, MAX_SYNC_ERROR_LENGTH);
    const set = database.prepare(`
      INSERT INTO sync_config (key, value)
      VALUES (?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                     updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
    `);
    set.run(errorKey(provider), message);
    set.run(errorAtKey(provider), new Date().toISOString());
  } catch (err) {
    log.error(`Failed to record sync outcome for ${provider}:`, err?.message || err);
  }
}

/**
 * Der letzte festgehaltene Fehler, für den Status-Endpunkt.
 * @returns {{ lastError: string|null, lastErrorAt: string|null }}
 */
export function readSyncOutcome(database, provider) {
  const get = (key) => database.prepare('SELECT value FROM sync_config WHERE key = ?').get(key)?.value ?? null;
  return { lastError: get(errorKey(provider)), lastErrorAt: get(errorAtKey(provider)) };
}

/**
 * Führt einen Sync-Lauf aus und hält sein Ergebnis fest. Der Fehler wird
 * WEITERGEWORFEN: der manuelle „Jetzt synchronisieren"-Knopf soll ihn weiterhin
 * sofort als Toast zeigen. Neu ist nur, dass er auch den Lauf überlebt, den
 * niemand angestoßen hat - den des Schedulers.
 *
 * @param {object} database
 * @param {string} provider
 * @param {() => Promise<any>} run
 */
export async function withSyncOutcome(database, provider, run) {
  try {
    const result = await run();
    recordSyncOutcome(database, provider, null);
    return result;
  } catch (err) {
    // Ein Lauf, dessen Verbindung währenddessen ersetzt oder getrennt wurde
    // (#2035), hat über die jetzige nichts zu sagen: kein Eintrag, auch kein
    // Löschen eines stehenden.
    if (!err?.superseded) recordSyncOutcome(database, provider, err);
    throw err;
  }
}

export { MAX_SYNC_ERROR_LENGTH };
