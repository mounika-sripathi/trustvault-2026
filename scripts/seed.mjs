// Seeds sample documents and grants against a deployed TrustVault
// instance. Run AFTER the migrations and edge functions are deployed.
//
//   SUPA_URL=... SUPA_ANON_KEY=... node scripts/seed.mjs
//
// Uploads go through the deployed upload-doc function and grants go
// through the REST API, exactly like the SPA does — so the audit trail
// is populated with real, chained entries rather than backfilled rows.

import { readFileSync } from "node:fs";

const URL_ = process.env.SUPA_URL ?? "https://dymcermbpcbthimiokba.supabase.co";
const ANON =
  process.env.SUPA_ANON_KEY ??
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImR5bWNlcm1icGNidGhpbWlva2JhIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTMxMDg3NDgsImV4cCI6MjEwODY4NDc0OH0.PYV5ASOrozq5CeVtAiftW5uixg7pM7Y4tmYE4PWimec";

const SAMPLES = new URL("./samples/", import.meta.url);

const users = {
  admin: { email: "admin@trustvault.demo", password: "TrustVault!Admin2026" },
  alice: { email: "alice@trustvault.demo", password: "TrustVault!Alice2026" },
  bob: { email: "bob@trustvault.demo", password: "TrustVault!Bob2026" },
  carol: { email: "carol@trustvault.demo", password: "TrustVault!Carol2026" },
  dave: { email: "dave@trustvault.demo", password: "TrustVault!Dave2026" },
};

async function signIn(email, password) {
  const r = await fetch(`${URL_}/auth/v1/token?grant_type=password`, {
    method: "POST",
    headers: { apikey: ANON, "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!r.ok) throw new Error(`sign-in failed for ${email}: ${await r.text()}`);
  return (await r.json()).access_token;
}

async function uploadDoc(token, filename, mime, title, category, description) {
  const bytes = readFileSync(new URL(filename, SAMPLES));
  const form = new FormData();
  form.append(
    "file",
    new File([bytes], filename, { type: mime }),
  );
  form.append("title", title);
  form.append("category", category);
  form.append("description", description);
  const r = await fetch(`${URL_}/functions/v1/upload-doc`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: form,
  });
  const body = await r.json();
  if (!r.ok) throw new Error(`upload failed (${filename}): ${JSON.stringify(body)}`);
  return body;
}

async function rest(token, path, method, body) {
  const r = await fetch(`${URL_}/rest/v1/${path}`, {
    method,
    headers: {
      apikey: ANON,
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Prefer: "return=representation",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await r.json().catch(() => null);
  if (!r.ok) throw new Error(`REST ${method} ${path}: ${JSON.stringify(data)}`);
  return data;
}

const main = async () => {
  const tokens = {};
  for (const [k, u] of Object.entries(users)) tokens[k] = await signIn(u.email, u.password);
  console.log("signed in:", Object.keys(tokens).join(", "));

  const profiles = await rest(tokens.admin, "profiles?select=id,email");
  const idByEmail = Object.fromEntries(profiles.map((p) => [p.email, p.id]));
  console.log("profiles loaded");

  const docs = {};
  const aliceUploads = [
    ["q4-salary-letters.pdf", "application/pdf", "Q4 Salary Letters — Engineering", "Finance", "Private to Alice: no grants, used as the cross-user negative case."],
    ["acme-master-services-agreement.pdf", "application/pdf", "Acme Master Services Agreement", "Legal", "Customer contract shared with one viewer."],
    ["company-handbook.md", "text/markdown", "Company Handbook", "General", "Shared with everyone in the demo org."],
  ];
  for (const [file, mime, title, cat, desc] of aliceUploads) {
    docs[title] = await uploadDoc(tokens.alice, file, mime, title, cat, desc);
    console.log("uploaded (alice):", title);
  }

  const bobUploads = [
    ["factory-floor-plan.png", "image/png", "Factory Floor Plan — Rev C", "Engineering", "Drawing shared with an external partner."],
    ["soc2-audit-evidence.pdf", "application/pdf", "SOC2 Audit Evidence Pack", "Compliance", "Private to Bob: no grants."],
    ["vendor-price-list.csv", "text/csv", "Vendor Price List", "Finance", "Editable by a partner account (edit grant)."],
  ];
  for (const [file, mime, title, cat, desc] of bobUploads) {
    docs[title] = await uploadDoc(tokens.bob, file, mime, title, cat, desc);
    console.log("uploaded (bob):", title);
  }

  const grants = [
    // [document, grantee email, permission, granted by]
    ["Acme Master Services Agreement", "carol@trustvault.demo", "read", "alice"],
    ["Company Handbook", "carol@trustvault.demo", "read", "alice"],
    ["Company Handbook", "dave@trustvault.demo", "read", "alice"],
    ["Factory Floor Plan — Rev C", "dave@trustvault.demo", "read", "bob"],
    ["Vendor Price List", "carol@trustvault.demo", "edit", "bob"],
  ];
  for (const [title, email, permission, by] of grants) {
    await rest(tokens[by], "grants", "POST", {
      document_id: docs[title].document_id,
      user_id: idByEmail[email],
      permission,
      granted_by: idByEmail[`${users[by].email}`],
    });
    console.log(`grant: ${email} → ${permission} on "${title}"`);
  }

  const audit = await rest(tokens.admin, "audit_log?select=seq&action&order=seq");
  console.log(`audit entries after seed: ${audit.length}`);
};

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
