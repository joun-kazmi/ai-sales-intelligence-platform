// Screenshots of / and an account page for docs/ (run against the synthetic demo artifact).
//   APP_USERNAME=u APP_PASSWORD=p ARTIFACT_PATH=out/demo/artifact.duckdb uvicorn ... --port 18093 &
//   NODE_PATH=$(npm root -g) node scripts/screenshots.mjs http://127.0.0.1:18093 docs/screenshots
import { createRequire } from 'module';
const { chromium } = createRequire(import.meta.url)('playwright');
const [base, outDir] = process.argv.slice(2);
const browser = await chromium.launch();
const ctx = await browser.newContext({ httpCredentials: { username: 'u', password: 'p' }, viewport: { width: 1280, height: 860 } });
const page = await ctx.newPage();
await page.goto(base + '/');
await page.screenshot({ path: `${outDir}/ranked-list.png` });
const href = await page.getAttribute('tbody tr:first-child a.domain', 'href');
await page.goto(base + href);
await page.screenshot({ path: `${outDir}/account.png`, fullPage: true });
await browser.close();
