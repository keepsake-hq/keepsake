# Keepsake Design Register

## Scene
A user opens Keepsake on a laptop in normal daylight to save, search, import, or connect AI memory. The interface should lower anxiety, not perform cleverness.

## Visual Direction
- Primary theme: light, quiet, secure, local.
- Existing tokens stay authoritative: off-white canvas, white surfaces, dark ink, muted gray, green brand accent.
- Dark mode exists as a polished alternate, not the main identity.
- Use restrained cards only for real objects: connector cards, memory rows, modals, setup steps.
- Avoid decorative hero sections, gradient text, glass effects, nested cards, and fake dashboard drama.

## Interaction Direction
- Every network-capable action must say what will connect before it connects.
- Local sources should say "reads local files only" in plain language.
- Planned cloud connectors stay disabled or marked "Planned"; never pretend they are live.
- Agent setup should use client tiles, numbered steps, and copyable command blocks.
- Search results should show source/type clearly so the user knows where a memory came from.

## App-Raum Rule
- No website scroll feeling: the unlocked desktop app uses the visible window height as a fixed tool space.
- Sidebar, header, command bars, and tool controls stay fixed inside each view.
- Only concrete work regions scroll: memory ledgers, source lists, search results, profile audit lists, map details, and inspectors.
- Avoid vertically stacked landing-page sections. Each view should feel like a Finder/1Password/Linear-style instrument, not a page to read downward.
- Settings uses a real app-preferences model: categories on the left, one active category on the right, compact rows with the label on the left and the status/control on the right.

## Reference Patterns
- SuperMemory: broad source onboarding, agent context cloud, hybrid search, graph, connectors.
- NicelyDone Town/Mailchimp/Bird/Maze/Slite: integration marketplace and settings lists.
- NicelyDone Reflect/Clew: graph and map clarity.
- NicelyDone Twingate/Sana/Linear/Expensify: connect buttons, integration cards, setup lists.
- Mobbin screenshot supplied in the planning thread: client selector tiles plus numbered setup commands.
- Premium UI pass: NicelyDone Vercel/GitHub/Slite for compact preference rows and left settings navigation; Linear for dense preferences and restrained active states; Attio/Twingate/GitBook for integration rows with a clear action column; Mobbin Skiff/Vercel setup flows for recovery confirmation and command-copy patterns.
- Do not borrow: SaaS marketing banners, upsell blocks, long scroll pages, concierge/chat setup lists, large empty hero states, or colorful product-specific sidebars.

## Component Rules
- Connector card: icon/initial, title, description, privacy note, status chip, primary action.
- Integration list row: use when the source list is dense.
- Setup step: number, short title, copyable command or clear instruction.
- Empty state: one sentence, one useful action.
- Status chip text: Available, Connected, Planned, Needs action, Error.

## Copy Rules
- Plain English in the app.
- No unexplained privacy slogans. State the mechanism: local only, encrypted, user-initiated network.
- No hidden technical acronyms in primary UI unless the user is in an agent/developer setup screen.
