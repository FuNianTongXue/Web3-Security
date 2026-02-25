# UI Polish Checklist

Use this checklist before final delivery.

## 1) Visual Direction

- Define a clear visual theme and avoid default-library appearance.
- Establish a type scale with distinct levels for page title, section title, body, and helper text.
- Use consistent spacing rhythm (for example 4/8-based scale) across layout and components.
- Keep contrast strong for readability and emphasize primary actions clearly.

## 2) Interaction Quality

- Provide hover, active, focus, disabled, loading, and error states for interactive elements.
- Keep primary flows short and predictable; avoid forcing users through unnecessary steps.
- Use animation only when it improves orientation or feedback.
- Keep transition timing consistent (for example 120ms to 240ms).

## 3) Responsive Behavior

- Validate breakpoints for common mobile and desktop widths.
- Protect content hierarchy on small screens: keep key actions visible without deep scrolling.
- Ensure touch targets are large enough and spaced for finger interaction.

## 4) Accessibility Baseline

- Use semantic HTML and correct label relationships.
- Keep full keyboard operability for forms, menus, dialogs, and tabs.
- Ensure focus is visible and does not get trapped unexpectedly.
- Pair status colors with text or icon cues, not color alone.

## 5) Perceived Performance

- Show skeletons or progress indicators for non-trivial loading times.
- Avoid layout shifts during data hydration.
- Defer non-critical rendering and heavy assets where possible.

## 6) Release Gate

- Confirm PM acceptance criteria and backend contract alignment.
- Confirm empty/error edge cases with realistic mock data.
- Run a quick visual pass for alignment, spacing, and typography consistency.
