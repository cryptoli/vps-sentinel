# Panel Theme Extensions

The panel UI loads a base stylesheet and then an optional theme stylesheet from `/themes/<theme-id>/theme.css`.

## Configure Themes

Set `PANEL_THEMES` as a comma-separated list of `id:Label` entries:

```bash
PANEL_THEME=default
PANEL_THEMES='default:Default,clean:Clean'
```

Theme IDs may contain letters, numbers, `_`, and `-`. Labels are display text only.

## Package Layout

For self-hosted deployments, place third-party themes under the panel web directory:

```text
panel/web/themes/clean/theme.css
```

For Cloudflare deployments, put the same directory under `panel/web` before running `scripts/deploy-cloudflare-panel.sh`.

## CSS Contract

Themes should override CSS custom properties and small component rules instead of replacing application structure. Keep selectors scoped to existing classes such as `.app-shell`, `.card`, `.topbar`, `.sidebar-shell`, `.data-table`, and chart classes. Do not hide security-critical fields or inject external scripts.

The stable theme contract is version `1`. Prefer overriding `--theme-*` variables:

| Variable | Purpose |
| --- | --- |
| `--theme-bg` | Application canvas background. |
| `--theme-bg-soft` | Secondary canvas and workspace background. |
| `--theme-surface` | Card, table, and control surfaces. |
| `--theme-surface-strong` | Raised or highlighted surfaces. |
| `--theme-text` | Primary text. |
| `--theme-muted` | Secondary text. |
| `--theme-border` | Standard borders. |
| `--theme-border-soft` | Subtle table and card separators. |
| `--theme-accent` | Primary action and selected state color. |
| `--theme-info` | Informational accent. |
| `--theme-success` | Healthy/confirmed state. |
| `--theme-warning` | Warning/degraded state. |
| `--theme-danger` | Critical/offline state. |
| `--theme-discovery` | Secondary accent used for traffic/discovery visuals. |
| `--theme-sidebar-bg` | Sidebar background, including gradients if needed. |
| `--theme-sidebar-text` | Sidebar text color. |

Example:

```css
:root[data-theme="clean"] {
  --theme-bg: #f7f9fc;
  --theme-bg-soft: #eef3f8;
  --theme-surface: #ffffff;
  --theme-text: #101828;
  --theme-muted: #5b677a;
  --theme-border: #d8e1ec;
  --theme-accent: #1769e0;
  --theme-success: #087f5b;
  --theme-warning: #b7791f;
  --theme-danger: #c92a2a;
  --theme-sidebar-bg: linear-gradient(180deg, #0b1726, #0f2035);
  --theme-sidebar-text: #edf4ff;
}
```

Keep component overrides small and reversible. A theme may adjust density or borders, but it should not change DOM assumptions, table column visibility, authentication UI, or security review controls.
