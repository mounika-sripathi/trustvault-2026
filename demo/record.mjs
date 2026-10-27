// Demo video recorder — records the 8 narration segments against the local SPA
// and the terminal pages. Usage: node demo/record.mjs
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join } from "node:path";
import { chromium } from "playwright";

const APP = new URL("../app/", import.meta.url).pathname;
const DEMO = new URL("./", import.meta.url).pathname;
const SEGS = new URL("./segments/", import.meta.url).pathname;
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".json": "application/json" };

const server = createServer(async (req, res) => {
  try {
    const isDemo = req.url.startsWith("/term/");
    const root = isDemo ? DEMO : APP;
    const path = req.url.replace(/^\/term\//, "/").split("?")[0];
    const rel = path.replace(/\.\./g, "").replace(/^\//, "") || "index.html";
    const file = await readFile(join(root, rel));
    res.writeHead(200, { "Content-Type": TYPES[extname(rel)] ?? "application/octet-stream" });
    res.end(file);
  } catch {
    res.writeHead(404).end("not found");
  }
});
await new Promise((r) => server.listen(4174, r));
const URL_ = "http://localhost:4174";
const ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImR5bWNlcm1icGNidGhpbWlva2JhIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTMxMDg3NDgsImV4cCI6MjEwODY4NDc0OH0.PYV5ASOrozq5CeVtAiftW5uixg7pM7Y4tmYE4PWimec";

const browser = await chromium.launch();

async function login(page, email, pass) {
  await page.goto(URL_ + "/");
  await page.waitForSelector("#li-btn");
  await page.click("#li-email");
  await page.type("#li-email", email, { delay: 18 });
  await page.type("#li-pass", pass, { delay: 18 });
  await page.click("#li-btn");
  await page.waitForSelector("#docs-card table", { timeout: 20000 });
}

async function openDoc(page, title) {
  const row = page.locator("#docs-card tbody tr", { hasText: title });
  await row.locator("button", { hasText: "Open" }).click();
  await page.waitForSelector("#d-grants", { timeout: 10000 });
}

async function segment(name, targetSec, fn) {
  const ONLY = (process.env.SEGS || "").split(",").filter(Boolean);
  if (ONLY.length && !ONLY.includes(name)) { console.log(`${name}: skipped`); return; }
  const ctx = await browser.newContext({
    viewport: { width: 1280, height: 720 },
    recordVideo: { dir: SEGS, size: { width: 1280, height: 720 } },
  });
  const page = await ctx.newPage();
  const video = page.video();
  const t0 = Date.now();
  try {
    await fn(page);
  } catch (e) {
    console.error(`!! ${name}: ${e.message.split("\n")[0]}`);
  }
  const remain = targetSec * 1000 - (Date.now() - t0);
  if (remain > 0) await page.waitForTimeout(remain);
  const path = await video.path();
  await ctx.close();
  const { rename } = await import("node:fs/promises");
  await rename(path, join(SEGS, `${name}.webm`));
  console.log(`${name}: ${((Date.now() - t0) / 1000).toFixed(1)}s`);
}

// ---- seg1: login screen
await segment("seg1", 21.5, async (page) => {
  await page.goto(URL_ + "/");
  await page.waitForSelector("#li-btn");
  await page.mouse.move(640, 300);
  await page.waitForTimeout(1500);
  await page.mouse.move(620, 420, { steps: 12 });
  await page.waitForTimeout(1200);
  await page.mouse.move(660, 480, { steps: 10 });
  await page.waitForTimeout(1200);
});

// ---- seg2: alice login, list, filters
await segment("seg2", 28.5, async (page) => {
  await login(page, "alice@trustvault.demo", "TrustVault!Alice2026");
  await page.waitForTimeout(2200);
  await page.fill("#f-title", "contract");
  await page.click("#f-apply");
  await page.waitForTimeout(2000);
  await page.fill("#f-title", "");
  await page.click("#f-apply");
  await page.waitForTimeout(1500);
});

// ---- seg3: upload (good file + fake pdf rejection)
await segment("seg3", 27, async (page) => {
  await login(page, "alice@trustvault.demo", "TrustVault!Alice2026");
  await page.waitForTimeout(1200);
  await page.click("#btn-upload");
  await page.waitForSelector("#up-file");
  await page.setInputFiles("#up-file", join(DEMO, "assets/demo-notes.md"));
  await page.type("#up-title", "Security Notes — Demo Upload", { delay: 12 });
  await page.click("#up-go");
  await page.waitForTimeout(3200);
  // rejected upload: script disguised as a PDF
  await page.click("#btn-upload");
  await page.waitForSelector("#up-file");
  await page.setInputFiles("#up-file", join(DEMO, "assets/fake.pdf"));
  await page.type("#up-title", "Definitely a legit PDF", { delay: 12 });
  await page.click("#up-go");
  await page.waitForSelector(".error-note", { timeout: 15000 });
});

// ---- seg4: grants + suggestions
await segment("seg4", 34, async (page) => {
  await login(page, "alice@trustvault.demo", "TrustVault!Alice2026");
  await openDoc(page, "Q4 Salary Letters");
  await page.waitForTimeout(1200);
  await page.selectOption("#g-user", { label: "Carol Chen (carol@trustvault.demo)" });
  await page.click("#g-add");
  await page.waitForTimeout(1800);
  // suggestions
  await page.click("#g-suggest");
  await page.waitForTimeout(2500);
});

// ---- seg5: carol sees + downloads the granted doc
await segment("seg5", 23.5, async (page) => {
  await login(page, "carol@trustvault.demo", "TrustVault!Carol2026");
  await page.waitForTimeout(2000);
  await openDoc(page, "Q4 Salary Letters");
  await page.waitForTimeout(1500);
  await page.click("#d-download");
  await page.waitForTimeout(3000);
});

// ---- seg6: revoke, immediate refusal
await segment("seg6", 37, async (page) => {
  // off-camera setup: give carol a live grant to revoke on camera
  const r = await fetch("https://dymcermbpcbthimiokba.supabase.co/auth/v1/token?grant_type=password", {
    method: "POST",
    headers: { apikey: ANON_KEY, "Content-Type": "application/json" },
    body: JSON.stringify({ email: "alice@trustvault.demo", password: "TrustVault!Alice2026" }),
  });
  const tok = (await r.json()).access_token;
  await fetch(`https://dymcermbpcbthimiokba.supabase.co/rest/v1/grants`, {
    method: "POST",
    headers: { apikey: ANON_KEY, Authorization: `Bearer ${tok}`, "Content-Type": "application/json", Prefer: "return=minimal" },
    body: JSON.stringify({ document_id: "846c731a-2694-4fb2-a39e-b7b469dc7497", user_id: "8ee452b0-69a5-40f3-a5a2-62e611e53b2c", permission: "read", granted_by: (await (await fetch("https://dymcermbpcbthimiokba.supabase.co/rest/v1/profiles?select=id&email=eq.alice@trustvault.demo", { headers: { apikey: ANON_KEY, Authorization: `Bearer ${tok}` } })).json())[0].id }),
  });
  await login(page, "alice@trustvault.demo", "TrustVault!Alice2026");
  await openDoc(page, "Q4 Salary Letters");
  await page.waitForTimeout(1500);
  // the revoke click can race the modal re-render; the revoke fires either way
  await page.locator("#d-grants tr", { hasText: "Carol" }).locator("[data-revoke]").first().click({ timeout: 8000 }).catch(() => {});
  await page.waitForTimeout(2500);
  await page.click(".modal-close");
  await page.waitForTimeout(600);
  await page.click("#logout");
  await page.waitForSelector("#li-btn");
  await login(page, "carol@trustvault.demo", "TrustVault!Carol2026");
  await page.waitForTimeout(3000);
});

// ---- seg7: admin audit view + chain verification
await segment("seg7", 21, async (page) => {
  await login(page, "admin@trustvault.demo", "TrustVault!Admin2026");
  await page.click('[data-nav="audit"]');
  await page.waitForSelector("#audit-card table");
  await page.waitForTimeout(1500);
  await page.mouse.wheel(0, 900);
  await page.waitForTimeout(1500);
  await page.mouse.wheel(0, 900);
  await page.waitForTimeout(1200);
  await page.click("#verify-btn");
  await page.waitForTimeout(3500);
});

// ---- seg7b: tamper terminal
await segment("seg7b", 10.5, async (page) => {
  await page.goto(URL_ + "/term/terminal.html?data=/term/assets/tamper.json&speed=14&linedelay=500");
  await page.evaluate(() => window.terminalDone).catch(() => {});
  await page.waitForTimeout(2500);
});

// ---- seg8: tests terminal
await segment("seg8", 40, async (page) => {
  await page.goto(URL_ + "/term/terminal.html?data=/term/assets/tests.json&speed=12&linedelay=120");
  await page.evaluate(() => window.terminalDone).catch(() => {});
  await page.waitForTimeout(6000);
});

await browser.close();
server.close();
console.log("done");
