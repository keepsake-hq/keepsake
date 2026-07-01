# Memory System Reference Board

Date: 2026-07-01

## Scope Read In This Session
- SuperMemory homepage and docs: connectors, MCP/plugins, RAG, memory graph, personal app, search modes, changelog.
- NicelyDone MCP searches for integration settings, connector flows, connector components, knowledge graph screens.
- Mobbin MCP setup was completed with `codex mcp add mobbin --url https://api.mobbin.com/mcp`; the CLI reported successful login, but the live Codex tool registry did not expose Mobbin tools until a session refresh.
- Mobbin screenshot from the planning thread: client tiles for Claude Code, Cursor, Codex, v0, Other; numbered MCP setup steps; copyable commands.

## SuperMemory Patterns To Adapt
- Bring context together first: let the user add high-signal sources during onboarding.
- Source breadth: AI chats, bookmarks, Notion, Drive, Gmail, GitHub, files, web pages.
- Agent access: MCP/plugins make memory available across assistants.
- Search modes: semantic, hybrid, chunk/document results, graph enrichment.
- Memory graph: visible relationships, not just a flat list.
- Consolidation: related memories can be grouped into clearer summaries.

## SuperMemory Patterns To Reject Or Change
- Hosted context cloud as the default. Keepsake stays local-first.
- Silent background cloud sync. Keepsake requires a user action before network use.
- Opaque cloud connectors. Keepsake must show source, status, and privacy behavior.
- Fake availability. Planned connectors are shown as planned, not connected.

## NicelyDone References Used
- Town integrations screen: dense settings page, third-party app rows, custom MCP server area.
- Mailchimp integrations screen: searchable integration marketplace with sidebar context.
- Bird integrations screens: integration marketplace list and search state.
- Maze team integrations: simple third-party app connection inside settings.
- Attio app directory modal: browse/search integration directory without leaving current work.
- Slite integration empty states: clear prompt to connect external apps.
- Reflect graph screens: sparse graph canvas, filters, labels, left context.
- Clew related-items graph modal: detail view plus graph without overwhelming the page.
- Twingate connect button: clean logo/title/action composition.
- Sana card: compact integration card with lock/connect state.
- Linear card: richer integration card with search/filter controls.
- Expensify setup list: vertical checklist for setup tasks.

## Mobbin References To Re-query After Tool Refresh
- Onboarding flows for connecting sources.
- Settings/integration screens for desktop and mobile.
- Agent/client setup screens with copyable commands.
- Empty, syncing, error, and permission-denied states.

## Keepsake UI Decisions From References
- Home gets four concrete actions: add context, search memory, connect agent, review profile.
- Sources screen uses starter cards plus a full integration list.
- Agent setup uses Mobbin-style client selector tiles and numbered copy steps.
- Graph keeps the Reflect-like sparse map and adds clearer filters/detail states.
- Documents are shown as rows with source, date, title, and preview.
- Cloud connectors are visible but marked Planned until explicit OAuth flows exist.
