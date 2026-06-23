import { cp, mkdir, readdir, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const uiDir = path.dirname(fileURLToPath(import.meta.url));
const panelUiDir = path.resolve(uiDir, "..");
const panelDir = path.resolve(panelUiDir, "..");
const sourceDir = path.resolve(panelUiDir, "out");
const targetDir = path.resolve(panelDir, "web");

if (!targetDir.endsWith(`${path.sep}panel${path.sep}web`)) {
  throw new Error(`Refusing to sync unexpected target directory: ${targetDir}`);
}

await mkdir(targetDir, { recursive: true });
for (const entry of await readdir(targetDir)) {
  await rm(path.join(targetDir, entry), { recursive: true, force: true });
}
await cp(sourceDir, targetDir, { recursive: true });

console.log(`Synced Next.js static panel to ${path.relative(process.cwd(), targetDir) || targetDir}`);
