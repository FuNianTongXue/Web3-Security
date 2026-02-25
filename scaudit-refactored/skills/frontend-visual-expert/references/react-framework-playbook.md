# React Framework Playbook

## Framework Selection

- Use `Next.js` when you need SSR/SSG, routing conventions, and strong full-stack productivity.
- Use `Remix` when nested routing, data loading boundaries, and web-standard forms are central.
- Use `Vite + React Router` when building SPA products that prioritize fast local iteration and flexible architecture.

## State Strategy

- Use local component state for isolated interaction logic.
- Use server-state tools (`TanStack Query` or equivalent) for fetch/cache/retry/invalidation.
- Use a lightweight global store (`Zustand`, `Jotai`, or context modules) only for cross-page shared state.

## UI Architecture

- Split by feature domain first, then by layer (page/container/presentational where needed).
- Keep route-level data loading near routes and pass normalized data downward.
- Centralize theme tokens and avoid hardcoded visual values in business components.

## Styling Guidance

- Prefer one primary styling strategy per project (CSS modules, Tailwind, or CSS-in-JS).
- Define reusable primitives for buttons, inputs, cards, dialogs, and data display patterns.
- Keep variants explicit (`size`, `tone`, `state`) instead of ad-hoc class combinations.

## Delivery Quality Gate

- Validate bundle and render performance on representative pages.
- Confirm keyboard and screen-reader baseline for core interactions.
- Verify UI consistency across Chromium, Safari, and Firefox when relevant.
