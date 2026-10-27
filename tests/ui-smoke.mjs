// UI smoke test: serves the SPA locally, signs in as each role and
// verifies the main screens render. Run with: node tests/ui-smoke.mjs
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join } from "node:path";
import { chromium } from "playwright";

const APP = new URL("../app/", import.meta.url).pathname;
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".png": "image/png" };

const server = createServer(async (req, res) => {
  try {
    const path = req.url === "/" ? "/index.html" : req.url;
    const file = await readFile(join(APP, path.replace(/\.\./g, "")));
    res.writeHead(200, { "Content-Type": TYPES[extname(path)] ?? "application/octet-stream" });
    res.end(file);
  } catch {
    res.writeHead(404).end("not found");
  }
});
await new Promise((r) => server.listen(4173, r));

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1360, height: 900 } });
const errors = [];
page.on("pageerror", (e) => errors.push(e.message));

const results = [];
const check = (name, ok) => results.push({ name, ok });

// ---- login page renders
await page.goto("http://localhost:4173/");
await page.waitForSelector("#li-btn");
check("login page renders", true);

// ---- wrong password shows error
await page.fill("#li-email", "alice@trustvault.demo");
await page.fill("#li-pass", "wrong-password");
await page.click("#li-btn");
await page.waitForSelector(".error-note");
check("wrong password rejected", true);

// ---- alice signs in
await page.fill("#li-pass", "TrustVault!Alice2026");
await page.click("#li-btn");
await page.waitForSelector("#docs-card table");
const rows = await page.locator("#docs-card tbody tr").count();
check(`alice sees her documents (${rows})`, rows >= 3);
check("alice sees upload button", await page.locator("#btn-upload").count() === 1);
check("alice does not see admin tabs", await page.locator('[data-nav="audit"]').count() === 0);

// ---- search filters
await page.fill("#f-title", "acme");
await page.click("#f-apply");
await page.waitForTimeout(600);
const filtered = await page.locator("#docs-card tbody tr").count();
check(`title search narrows results (${filtered})`, filtered === 1);

// ---- details modal with grants
await page.locator("#docs-card tbody tr").first().click();
await page.waitForSelector(".modal");
check("details modal opens", true);
await page.waitForSelector(".modal #d-grants table");
check("grants section shows carol", (await page.locator(".modal").innerText()).includes("carol@trustvault.demo"));
await page.keyboard.press("Escape");

// ---- viewer signs in and sees only granted docs
await page.click("#logout");
await page.waitForSelector("#li-btn");
await page.fill("#li-email", "carol@trustvault.demo");
await page.fill("#li-pass", "TrustVault!Carol2026");
await page.click("#li-btn");
await page.waitForSelector("#docs-card table");
const carolTitles = await page.locator("#docs-card tbody tr td:first-child").allInnerTexts();
check(`carol sees only granted docs (${carolTitles.length})`, carolTitles.length >= 3 && !carolTitles.join("|").includes("Salary"));

// ---- admin sees audit trail
await page.click("#logout");
await page.waitForSelector("#li-btn");
await page.fill("#li-email", "admin@trustvault.demo");
await page.fill("#li-pass", "TrustVault!Admin2026");
await page.click("#li-btn");
await page.waitForSelector("#docs-card table");
await page.click('[data-nav="audit"]');
await page.waitForSelector("#audit-card table");
const auditText = await page.locator("#audit-card").innerText();
check("audit shows grant.added", auditText.includes("grant.added"));
check("audit shows doc.uploaded", auditText.includes("doc.uploaded"));
check("audit shows auth.login", auditText.includes("auth.login"));
await page.click("#verify-btn");
await page.waitForSelector("#verify-out .banner.ok");
check("chain verification passes", true);

await page.screenshot({ path: "demo/out/admin-audit.png", fullPage: false });

// ---- users page
await page.click('[data-nav="users"]');
await page.waitForSelector("#users-card table");
check("users page renders", true);

console.table(results);
const failed = results.filter((r) => !r.ok);
await browser.close();
server.close();
if (errors.length) console.log("PAGE ERRORS:", errors);
if (failed.length || errors.length) process.exit(1);
console.log("UI smoke: all green");
