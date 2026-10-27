// Generates the sample documents used by scripts/seed.mjs.
// The PDF writer is hand-rolled (no dependencies) so a clean clone can
// regenerate demo data anywhere.

import { writeFileSync, mkdirSync } from "node:fs";

mkdirSync(new URL("./samples/", import.meta.url), { recursive: true });

function makePdf(lines) {
  const esc = (s) => s.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
  const content =
    "BT\n/F1 11 Tf\n14 TL\n72 740 Td\n" +
    lines.map((l) => `(${esc(l)}) Tj\nT*`).join("") +
    "ET\n";

  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
    `<< /Length ${content.length} >>\nstream\n${content}endstream`,
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
  ];

  let out = "%PDF-1.4\n";
  const offsets = [];
  objects.forEach((obj, i) => {
    offsets.push(out.length);
    out += `${i + 1} 0 obj\n${obj}\nendobj\n`;
  });
  const xrefStart = out.length;
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) {
    out += `${String(off).padStart(10, "0")} 00000 n \n`;
  }
  out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`;
  return Buffer.from(out, "latin1");
}

const samples = {
  "q4-salary-letters.pdf": makePdf([
    "TRUSTVAULT DEMONSTRATION DATA",
    "",
    "Q4 2026 Salary Letters - Engineering",
    "",
    "This file is demonstration data for the TrustVault hiring",
    "challenge. It is deliberately private to Alice (the owner):",
    "no other account has been granted access, so it doubles as",
    "the negative test case for cross-user access.",
  ]),
  "acme-master-services-agreement.pdf": makePdf([
    "TRUSTVAULT DEMONSTRATION DATA",
    "",
    "MASTER SERVICES AGREEMENT - Acme Manufacturing Inc.",
    "",
    "1. Scope. Acme engages TrustVault Demo Corp to deliver the",
    "   services described in Statement of Work No. 3.",
    "2. Confidentiality. Each party shall protect the other's",
    "   confidential information with no less than reasonable care.",
    "3. Term. This agreement runs for 24 months from signing.",
    "",
    "Demonstration document - not a real contract.",
  ]),
  "company-handbook.md": Buffer.from(
    `# TrustVault Demo Corp — Company Handbook\n\n` +
      `Welcome. This handbook covers the basics for everyone.\n\n` +
      `## Security rules\n\n- Never share document links; share access instead.\n` +
      `- If you see a document you should not have, tell the administrator.\n` +
      `- Every document view is logged. The audit trail is append-only.\n\n` +
      `(Demonstration data.)\n`,
    "utf8",
  ),
  "vendor-price-list.csv": Buffer.from(
    `vendor,sku,unit_price,currency\n` +
      `Northwind Steel,BR-100,42.50,USD\n` +
      `Corrugated Inc,BOX-7,1.20,USD\n` +
      `OptiFasteners,SCW-9,0.35,USD\n` +
      `Demo Industries,DEMO-1,99.00,USD\n`,
    "utf8",
  ),
  "soc2-audit-evidence.pdf": makePdf([
    "TRUSTVAULT DEMONSTRATION DATA",
    "",
    "SOC 2 Type II - Evidence Pack (extract)",
    "",
    "CC6.1 Logical access: access to the document platform is",
    "restricted to named individuals; every access attempt,",
    "successful or refused, is recorded in an append-only log.",
    "CC7.2 Monitoring: hash-chained audit records are verified",
    "by administrators daily.",
    "",
    "Demonstration data for the hiring challenge.",
  ]),
};

for (const [name, buf] of Object.entries(samples)) {
  writeFileSync(new URL(`./samples/${name}`, import.meta.url), buf);
}
console.log("samples written");
