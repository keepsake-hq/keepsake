# GOAL: Keepsake Premium Product UI Pass

## Ziel

Keepsake soll nicht nur “sauber” aussehen, sondern wie ein echtes Premium-Mac-Werkzeug wirken.

Aktueller Stand ist besser als vorher, aber noch nicht gut genug:
- zu leer
- zu generisch
- zu wenig visuelle Führung
- Settings wirkt wie ein Rohbau
- Sources/Home wirken funktional, aber nicht premium
- zu wenig Referenz-Qualität aus echten Produkt-UIs

Keepsake muss sich anfühlen wie:
1Password + Finder Inspector + Raycast + Linear Settings + Stripe/Vercel-Dichte.

Nicht:
AI-Dashboard, Website, SaaS-Landingpage, shadcn-Demo, Dribbble-Konzept.

---

## Pflicht: Erst Referenzen sammeln

Vor Code-Änderungen MUSST du echte Referenzen prüfen.

Nutze dafür MCP:

### NicelyDone
Suche und prüfe mindestens 8 Screens:
- Vercel Settings / Notifications
- GitHub Settings / Notifications
- Make Settings
- Linear Settings
- Attio Settings / CRM UI
- Twingate Connect / Setup UI
- Expensify Setup List
- Slite / Notion-like workspace settings

### Mobbin
Suche und prüfe mindestens 6 Screens oder Flows:
- web app settings with sidebar
- account preferences rows
- integration settings list
- security settings desktop app
- onboarding connect sources
- agent setup / developer tools setup if available

### Browser-Inspiration
Nutze NICHT wahllos alle Bookmark-Seiten.
Erlaubt:
- Refero Styles
- PageFlows
- SaaSFrame
- SaaS UI UX Patterns
- Attio
- shadcn/ui als Komponentenbasis

Mit Vorsicht:
- 21st.dev nur für kleine Motion/Interaction-Ideen
- Magic UI / Aceternity nur wenn es NICHT nach Landingpage/AI-Slop aussieht

Vermeiden:
- Dribbble
- Landbook
- Awwwards
- MotionSites
- Landing Pages
Diese sind zu website-lastig.

### Ergebnis vor Umsetzung
Lege intern eine kurze Referenzmatrix an:
- Referenz
- Was daran für Keepsake relevant ist
- Was übernommen wird
- Was bewusst NICHT übernommen wird

Nicht mit Code starten, bevor diese Referenzprüfung erledigt ist.

---

## Produkt-Wahrheit

Keepsake ist ein privater, lokaler Memory-Tresor für AI-Kontext.

Die UI muss Sicherheit nicht behaupten, sondern durch Kontrolle zeigen:
- Quelle
- Zeitpunkt
- Zugriff
- Status
- Aktion
- lokale Speicherung
- keine Netzwerkaktion ohne Nutzerklick

Keine großen Trust-Sprüche.
Keine “100% secure”-Bühne.
Keine Marketing-Sprache.

---

## Design-Prinzipien

### Grundgefühl
- ruhig
- dicht
- präzise
- lokal
- kontrolliert
- hochwertig
- Mac-App, nicht Webseite

### Visuell
- Systemfont / SF Pro Look
- kleine Radius: 6–10px
- sehr feine Linien
- fast keine Schatten
- keine Glows
- keine Gradients
- keine Emoji-Icons
- Grün nur für Status, Auswahl, echte Aktion
- mehr Dichte, aber gut lesbar
- weniger leere weiße Flächen

### UX
- feste App-Fläche
- kein Website-Scroll
- Sidebar fix
- Header fix
- nur echte Arbeitsbereiche scrollen
- jede Ansicht wirkt wie ein Werkzeugfenster
- keine langen erklärenden Absätze
- keine Kartenwand
- keine Hero-Fläche

---

## Hauptfokus: Settings komplett veredeln

Settings ist aktuell der schwächste Screen.

### Problem
Aktuell:
- zu leer
- linke Liste wirkt dünn
- rechte Fläche wirkt wie Rohbau
- einzelne Rows haben zu wenig Gewicht
- keine Premium-Hierarchie
- nicht genug “Preferences App”-Gefühl

### Zielbild
Settings muss wirken wie:
Linear Settings + Arc Settings + 1Password Preferences.

### Struktur
Links:
- schmale Settings-Navigation
- klare Gruppen
- aktive Kategorie sichtbar, aber nicht laut
- optional kleine Statuswerte rechts, aber sparsam

Rechts:
- nur aktive Kategorie sichtbar
- Header der Kategorie oben
- darunter kompakte Settings-Rows
- jede Row:
  - links: Name + kurze Beschreibung
  - rechts: Status / Toggle / Button / Menu
- gefährliche Aktionen unten separat

### Settings-Kategorien

1. General
   - Vault location/status
   - Network access
   - Agent access

2. Appearance
   - Theme: Light / Dark / System
   - Density: Comfortable / Compact falls sinnvoll
   - Optional: sidebar behavior

3. Recovery Key
   - Recovery key status
   - Show key
   - Print key
   - Copy key nur mit Warnzustand

4. Quick Unlock
   - PIN/passphrase status
   - Enable / Change / Disable
   - kurze Sicherheitserklärung, maximal 1 Satz

5. Sync
   - Off by default
   - Device sync planned/disabled
   - Kein Fake-Connected-State

6. Backup
   - Encrypted backup off/on/planned
   - Last backup
   - Restore action

7. Updates
   - Manual update check
   - Last checked
   - klare Info: no automatic checks

8. Advanced
   - Agent config
   - Local data folder
   - Export/debug info falls vorhanden
   - Danger zone

### Entfernen aus Settings
- “Memories saved”
- “Bring your memories in”
- Import CTA
- lange Recovery-Erklärungen
- lange Sync-Erklärungen

Diese Dinge gehören nach Home/Sources/Onboarding, nicht Settings.

---

## Home verbessern

Aktuell ist Home okay, aber noch nicht premium.

### Ziele
- Command-Bar hochwertiger machen
- Ledger dichter und präziser
- rechte Details/Inspector wieder sichtbar und stark, wenn Platz da ist
- Statuszeile oben knapper und schöner

### Home-Aufbau
Links bleibt Sidebar.

Mitte:
- Header: “Memory”
- kleine Statuszeile: Vault, Key, Access
- Command-Bar
- Memory Ledger als Tabelle/Liste

Rechts:
- Inspector mit ausgewählter Memory
- Quelle
- Typ
- erstellt
- letzter Zugriff
- verwandte Memories
- Aktionen

### Entfernen / Kürzen
- “Local context ledger” kann bleiben, aber eventuell besser: “Local memory ledger.”
- “Access User action” wirkt komisch. Besser:
  - `Vault Local`
  - `Key This Mac`
  - `Network Manual`

---

## Sources verbessern

Sources ist funktional, aber noch zu generisch.

### Ziele
- wie Integrationsliste in hochwertiger App
- Cloud-Planned-Zeilen klar secondary/disabled
- lokale Quellen stärker priorisieren
- Row-Text kürzen
- Actions klarer

### Row-Aufbau
- Icon/Initial
- Source Name
- kurze Beschreibung, maximal 3–5 Wörter
- Type
- Status
- Last activity
- Action

### Gute Actions
- `Scan`
- `Pick`
- `Paste`
- `Setup`
- `Planned`

Nicht:
- lange Buttontexte
- gleiche Gewichtung für Planned und aktive lokale Quellen

---

## Search verbessern

### Ziel
Search wirkt wie Werkzeug, nicht wie leerer Screen.

- Query oben fix
- Modi als kompakte Segments
- Resultate als Ledger
- Empty State nur eine Zeile + optional Beispiel
- keine Erklärungstexte

Search Modes:
- Balanced
- Recent
- Semantic
- Graph
- Hybrid

---

## Profile verbessern

### Ziel
Profile ist Audit, nicht Storytelling.

- Fakten als Tabelle
- Quellenanteile klar
- Konflikte klar
- veraltete Fakten klar
- Aktionen rechts oben: Rebuild, Clear
- wenig Text

Begriffe:
- “Profile audit” ist okay
- “What Keepsake knows” vermeiden, klingt zu storyhaft

---

## Motion / Interaction

Motion nur dezent:
- 150–200ms
- active row transition
- hover states
- settings category switch darf weich sein
- keine fancy page reveals
- keine Magic-UI-Landingpage-Effekte
- reduced motion beachten

Wenn 21st.dev genutzt wird:
- nur für Micro-Interaction-Ideen
- keine auffälligen Animationen übernehmen

---

## Komponentenqualität

Standardisiere:
- Buttons
- Status-Chips
- Segmented Controls
- Setting Rows
- Ledger Rows
- Inspector Sections
- Empty States
- Danger Zone

Alle interaktiven Elemente brauchen:
- default
- hover
- focus
- active
- disabled

Focus sichtbar, aber nicht hässlich.

---

## Dateien

Primär:
- `apps/desktop/ui/index.html`
- `apps/desktop/ui/app.js`
- `apps/desktop/ui/src/input.css`

Optional:
- `DESIGN.md`

Nicht anfassen:
- Crypto
- Backend
- Sync-Logik
- Netzwerkverhalten
- Git remote / push ohne Freigabe

---

## Harte Verbote

- keine Website-Optik
- keine Landingpage-Inspiration direkt übernehmen
- keine langen Textblöcke
- keine großen leeren weißen Flächen
- keine Hero-Karten
- keine Card-Grids
- keine Emojis
- keine Gradients
- keine Glows
- keine “AI Dashboard”-Ästhetik
- keine Fake-Connected-Cloud-States
- keine automatische Netzwerkaktion

---

## Qualitätsprüfung

Nach Umsetzung MUSS geprüft werden:

### Build / Code
- `pnpm --dir apps/desktop build:css`
- `node --check apps/desktop/ui/app.js`
- `node $HOME/.agents/skills/impeccable/scripts/detect.mjs --json apps/desktop/ui/index.html apps/desktop/ui/app.js`

### Browser
Prüfe live:
- Home
- Sources
- Search
- Profile
- Settings
- Map falls sichtbar betroffen

Viewports:
- 1280x800
- 1536x900

Prüfen:
- keine Console Errors
- kein Body/Main-Scroll
- nur Listen/Inspector/Arbeitsbereiche scrollen
- Settings zeigt nur aktive Kategorie rechts
- keine abgeschnittenen Texte
- Dark Mode nicht kaputt

### Optional, wenn sinnvoll
- `cargo test --workspace --all-targets`

---

## Abnahmekriterien

Die Arbeit gilt erst als fertig, wenn:

1. Settings sichtbar hochwertiger wirkt als vorher.
2. Settings keine lange Hilfeseite mehr ist.
3. Home/Sources/Search/Profile weniger generisch wirken.
4. Referenzen von NicelyDone/Mobbin tatsächlich ausgewertet wurden.
5. Der Agent kurz dokumentiert, welche Referenzen welche Entscheidung beeinflusst haben.
6. Alle Checks grün sind oder sauber begründet ist, warum ein Check nicht lief.
7. Screenshots von Settings, Home und Sources geprüft wurden.
8. Keine neuen Backend-/Security-Risiken eingeführt wurden.

---

## Abschlussbericht

Am Ende berichten:

- Welche Referenzen geprüft wurden
- Was daraus übernommen wurde
- Was bewusst nicht übernommen wurde
- Was an Settings geändert wurde
- Was an Home/Sources/Search/Profile geändert wurde
- Welche Checks grün waren
- Welche Screenshots geprüft wurden
- Was nicht angefasst wurde
