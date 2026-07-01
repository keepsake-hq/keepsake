# Keepsake Product Register

## Product
Keepsake is a private, local-first long-term memory vault for people and AI agents.

It stores memories on the user's device, encrypts them with the user's seed, and lets local assistants recall and write to one shared memory instead of keeping separate silos.

## Audience
- Primary: users who want AI memory without giving a hosted service their private context.
- Secondary: developers and power users who connect Claude Code, Codex, Cursor, OpenCode, local notes, exports, and files.

## Core Promise
- Private by default: no network call unless the user asks for it.
- Local-first: imports, search, graph, profile, and consolidation work locally.
- Portable: memories can move through encrypted passports and safe copies.
- Agent-friendly: assistants get scoped local access, never the seed phrase.

## Product Shape
- App register: restrained product UI.
- First screen after unlock is the working tool, not a marketing page.
- The app should feel like a calm personal vault: clear, readable, low-drama, trustworthy.

## Non-Negotiables
- No automatic connector sync to cloud services.
- No silent update checks or background pings.
- No plaintext hashes, fingerprints, tags, or token records that can cross the zero-knowledge boundary.
- No synced OAuth tokens.
- No fake connected states for planned cloud integrations.

## Current Implementation Direction
- Existing local imports become a connector catalog.
- Existing graph becomes a clearer map view.
- Existing profile storage becomes a visible "what Keepsake knows" screen.
- Existing agent MCP setup becomes an in-app guided setup flow.
