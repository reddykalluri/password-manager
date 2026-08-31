# accessibility

Cross-cutting accessibility and responsive-design requirements (high-level requirement 8), binding on the web client, desktop apps, mobile apps, and extension UIs. Treated as release gates, not enhancements.

## ADDED Requirements

### Requirement: WCAG 2.2 AA conformance
All user interfaces SHALL conform to WCAG 2.2 Level AA. Automated checks (axe or equivalent) SHALL run in CI for web-technology surfaces, and a manual audit against the full AA criteria SHALL pass before each major release. Known non-conformances block release or carry a documented remediation deadline.

#### Scenario: CI gate
- GIVEN a pull request changing web-client UI
- WHEN CI runs the accessibility suite
- THEN new violations of automated-detectable AA criteria fail the build

### Requirement: Screen reader support
All surfaces SHALL be fully operable with the platform screen reader — NVDA/JAWS and Narrator on Windows, VoiceOver on macOS/iOS/iPadOS, TalkBack on Android — with correct roles, names, states, and focus order; secret values SHALL be announced only on explicit reveal, and dynamic events (autofill offers, save prompts, sync status) announced via live regions or platform announcements.

#### Scenario: Screen-reader fill
- GIVEN a TalkBack user on the Android autofill flow
- WHEN a credential suggestion appears
- THEN the suggestion is announced, selectable, and the fill result confirmed audibly without the password value being spoken

### Requirement: Keyboard operability
Every function on desktop and web SHALL be operable by keyboard alone: visible focus indicators (WCAG 2.4.11+), no traps, documented shortcuts for unlock, search, copy username/password/TOTP, and fill, and logical tab order in popup, list/detail, and dialogs.

#### Scenario: Keyboard-only fill
- GIVEN a keyboard-only user on a login page with the extension
- WHEN they invoke the fill shortcut, arrow through candidates, and press Enter
- THEN the form fills with no pointer use and focus returns to the form

### Requirement: Visual accessibility
All surfaces SHALL maintain AA contrast (4.5:1 text, 3:1 UI components), support 200% text scaling and OS text-size settings without loss of function, honour reduced-motion preferences, respect OS high-contrast/dark modes, and never use colour as the sole indicator (e.g. password-strength meters carry text labels).

#### Scenario: Large text on mobile
- GIVEN iOS text size at the largest accessibility setting
- WHEN the user browses and edits items
- THEN text reflows without truncation of critical labels or clipped touch targets

### Requirement: Responsive and input-agnostic layout
All surfaces SHALL function from 320 px width to large desktop displays and across pointer, touch, and keyboard input; touch targets SHALL be at least 24×24 CSS px (44×44 pt on iOS, 48×48 dp on Android), and no function SHALL depend on hover alone.

#### Scenario: Narrow window
- GIVEN the desktop app resized to 320 px width
- WHEN the user searches and opens an item
- THEN the layout collapses to a single usable column with all actions reachable
