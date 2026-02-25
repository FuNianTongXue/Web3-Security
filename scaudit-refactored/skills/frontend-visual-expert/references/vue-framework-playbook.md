# Vue Framework Playbook

## Framework Selection

- Use `Nuxt` when SSR/SSG, SEO, and convention-driven full-stack delivery are required.
- Use `Vite + Vue Router` when building SPA applications with custom architecture needs.
- Use `Quasar` when a component-rich cross-platform UI baseline is needed quickly.

## State Strategy

- Use component-local refs/reactive state for localized UI behavior.
- Use `Pinia` for shared business state across modules.
- Use server-state patterns (query composables or fetch wrappers) for caching and retry logic.

## Composition and Modules

- Prefer Composition API with reusable composables for domain logic.
- Keep composables focused: one concern per composable, clear input/output contracts.
- Keep API clients and DTO normalization outside view components.

## Styling Guidance

- Keep design tokens centralized in CSS variables or theme config.
- Build consistent base components (`BaseButton`, `BaseInput`, `BaseModal`) before page-level assembly.
- Avoid style drift by reusing spacing and typography primitives across features.

## Delivery Quality Gate

- Validate hydration and route transitions for perceived smoothness.
- Confirm accessibility of forms, dialogs, and navigation with keyboard-only interaction.
- Verify mobile breakpoints and touch interaction comfort on real or emulated devices.
