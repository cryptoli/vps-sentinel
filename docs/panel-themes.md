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
