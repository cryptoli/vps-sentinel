# 面板主题扩展

面板前端会先加载基础样式，再从 `/themes/<theme-id>/theme.css` 加载可选主题样式。

## 配置主题

`PANEL_THEMES` 使用逗号分隔的 `id:Label` 格式：

```bash
PANEL_THEME=default
PANEL_THEMES='default:Default,clean:Clean'
```

主题 ID 只能包含字母、数字、`_` 和 `-`。Label 只用于页面展示。

## 目录结构

自建部署时，把第三方主题放到面板 web 目录：

```text
panel/web/themes/clean/theme.css
```

Cloudflare 部署时，在运行 `scripts/deploy-cloudflare-panel.sh` 之前，把同样目录放到 `panel/web` 下。

## CSS 契约

主题应优先覆盖 CSS 自定义属性和少量组件规则，不应替换应用结构。选择器应限定在已有类名，例如 `.app-shell`、`.panel-card`、`.topbar`、`.sidebar-shell`、`.data-table` 和图表类名。主题不得隐藏安全关键字段，也不得注入外部脚本。

稳定主题契约版本为 `1`。建议优先覆盖 `--theme-*` 变量：

| 变量 | 用途 |
| --- | --- |
| `--theme-bg` | 应用画布背景。 |
| `--theme-bg-soft` | 次级画布和工作区背景。 |
| `--theme-surface` | 卡片、表格、控件表面。 |
| `--theme-surface-strong` | 强调或抬高表面。 |
| `--theme-text` | 主文本。 |
| `--theme-muted` | 次级文本。 |
| `--theme-border` | 标准边框。 |
| `--theme-border-soft` | 表格和卡片的弱分隔线。 |
| `--theme-accent` | 主操作和选中态颜色。 |
| `--theme-info` | 信息提示色。 |
| `--theme-success` | 健康/确认状态。 |
| `--theme-warning` | 警告/降级状态。 |
| `--theme-danger` | 严重/离线状态。 |
| `--theme-discovery` | 流量和发现类辅助视觉。 |
| `--theme-sidebar-bg` | 侧栏背景，可包含渐变。 |
| `--theme-sidebar-text` | 侧栏文本颜色。 |

示例：

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

组件级覆盖应保持小而可回退。主题可以调整密度和边框，但不应改变 DOM 假设、表格列可见性、认证 UI 或安全复核控件。
