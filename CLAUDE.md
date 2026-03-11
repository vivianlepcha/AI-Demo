# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## First-time setup (Claude Code plugin)

This repo ships a `frontend-dev-agent` skill in `.claude/plugins/`. Run once after cloning to register it with your local Claude Code:

```bash
bash .claude/setup-plugin.sh
```

Requires `jq`. Then restart Claude Code. The skill triggers on phrases like *"clone this site"*, *"recreate UI from screenshot"*, *"extract design tokens"*, *"reverse engineer this design"*.

## Commands

```bash
npm run dev      # Start dev server (Next.js)
npm run build    # Production build
npm run start    # Start production server
npm run lint     # Run ESLint
```

To add shadcn components: `npx shadcn@latest add <component>`

## Architecture

This is a **single-page Next.js 16 / React 19 demo** that replicates the Pandora UK brand's authentication and account experience. There is no backend — all auth state is stored in `localStorage`.

### View state machine (`src/app/page.tsx`)

The entire app lives in one file. The root `Home` component manages two top-level views via `useState`:

- **`auth`** — shows `AuthPage`, which contains a Login/Join tab switcher (`LoginForm` / `JoinForm`) plus `OrderStatusPanel` in a side column
- **`dashboard`** — shows `Dashboard` after a successful sign-in or registration

Session persistence: on mount, `useEffect` reads `pandora_user` from `localStorage` to restore an active session. Registration stores users in `pandora_users` (array). Demo credentials: `demo@pandora.net` / `pandora123`.

### Styling system

Tailwind CSS v4 with a custom CSS layer in `src/app/globals.css`. All Pandora-specific design tokens use `--p-*` CSS variables (e.g. `--p-black`, `--p-divider`, `--p-btn-primary`). Component-level classes use a `p-` prefix (`p-btn`, `p-field`, `p-tab`, etc.) — these are defined as plain CSS classes in globals, not Tailwind utilities.

Border radius is globally set to `0rem` — the brand uses sharp corners throughout.

Animation classes `anim-up` + `d1`–`d5` stagger fade-up entry animations.

### Fonts

Three custom font families loaded via `@font-face` in `globals.css`, served from `/public/fonts/`:
- **GothamSSm** — default body font (`font-family: inherit` on all components)
- **PanDisplay** — used inline with `fontFamily: "'PanDisplay', Arial, sans-serif"` for display headings
- **PanText** — available but currently unused in JSX

### shadcn/ui

Configured in `components.json` with `base-nova` style. Pre-added primitives are in `src/components/ui/`. The `cn()` utility is at `src/lib/utils.ts`.
