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

Cloudflare 部署时，在运行 `scripts/deploy-cloudflare-panel.sh` 之前把同样目录放到 `panel/web` 下。

## CSS 约定

主题应优先覆盖 CSS 变量和少量组件规则，不应该替换应用结构。选择器应限定在已有类名，例如 `.app-shell`、`.card`、`.topbar`、`.sidebar-shell`、`.data-table` 和图表类名。主题不得隐藏安全关键字段，也不得注入外部脚本。
