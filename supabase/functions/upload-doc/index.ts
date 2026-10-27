// upload-doc: the only route through which document bytes enter the system.
// Validates type (declared AND sniffed), size, filename; stores bytes in the
// private bucket under a server-generated path; creates the document or a
// new version. Audit rows are written by the DB triggers on `documents`.

import { createClient } from "jsr:@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const SUPA_URL = Deno.env.get("SUPABASE_URL")!;
const ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;

const MAX_BYTES = 25 * 1024 * 1024; // 25 MB

// allowlist of content types, with magic-byte signatures for binary types
const ALLOWED: Record<
  string,
  { ext: string[]; magic?: number[][]; text?: boolean }
> = {
  "application/pdf": { ext: ["pdf"], magic: [[0x25, 0x50, 0x44, 0x46]] }, // %PDF
  "image/png": { ext: ["png"], magic: [[0x89, 0x50, 0x4e, 0x47]] },
  "image/jpeg": { ext: ["jpg", "jpeg"], magic: [[0xff, 0xd8, 0xff]] },
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {
    ext: ["docx"], magic: [[0x50, 0x4b, 0x03, 0x04]], // zip local header
  },
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {
    ext: ["xlsx"], magic: [[0x50, 0x4b, 0x03, 0x04]],
  },
  "application/vnd.openxmlformats-officedocument.presentationml.presentation": {
    ext: ["pptx"], magic: [[0x50, 0x4b, 0x03, 0x04]],
  },
  "text/plain": { ext: ["txt"], text: true },
  "text/csv": { ext: ["csv"], text: true },
  "text/markdown": { ext: ["md"], text: true },
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}

function sanitizeFilename(name: string): string {
  const base = name.split(/[\\/]/).pop() ?? "file";
  const cleaned = base.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 120);
  return cleaned.length > 0 ? cleaned : "file";
}

function startsWith(bytes: Uint8Array, sig: number[]): boolean {
  if (bytes.length < sig.length) return false;
  return sig.every((b, i) => bytes[i] === b);
}

function looksLikeText(bytes: Uint8Array): boolean {
  const n = Math.min(bytes.length, 4096);
  let suspicious = 0;
  for (let i = 0; i < n; i++) {
    const b = bytes[i];
    if (b === 0) return false; // NUL byte — not text
    if (b < 9 || (b > 13 && b < 32)) suspicious++;
  }
  return suspicious / Math.max(n, 1) < 0.05;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  const authHeader = req.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) return json({ error: "unauthorized" }, 401);

  const userClient = createClient(SUPA_URL, ANON_KEY, {
    global: { headers: { Authorization: authHeader } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: { user }, error: userErr } = await userClient.auth.getUser();
  if (userErr || !user) return json({ error: "unauthorized" }, 401);

  const admin = createClient(SUPA_URL, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  const { data: profile } = await admin
    .from("profiles")
    .select("email, role, is_active")
    .eq("id", user.id)
    .maybeSingle();
  if (!profile || !profile.is_active) return json({ error: "forbidden" }, 403);

  // ---- parse multipart form ----
  let form: FormData;
  try {
    form = await req.formData();
  } catch {
    return json({ error: "invalid form data" }, 400);
  }

  const file = form.get("file");
  if (!(file instanceof File)) return json({ error: "file is required" }, 400);

  const documentId = (form.get("document_id") as string | null) ?? "";
  const title = ((form.get("title") as string | null) ?? "").trim();
  const category = ((form.get("category") as string | null) ?? "general").trim();
  const description = ((form.get("description") as string | null) ?? "").trim();
  const note = ((form.get("note") as string | null) ?? "").trim();

  // ---- validation: size ----
  if (file.size <= 0) return json({ error: "empty file" }, 400);
  if (file.size > MAX_BYTES) {
    return json({ error: `file exceeds the 25 MB limit` }, 413);
  }

  // ---- validation: declared type must be allowlisted ----
  const declared = (file.type || "").split(";")[0].trim().toLowerCase();
  const rule = ALLOWED[declared];
  if (!rule) {
    return json({ error: `content type not allowed: ${declared || "unknown"}` }, 415);
  }

  // ---- validation: extension must match declared type ----
  const ext = (file.name.split(".").pop() ?? "").toLowerCase();
  if (!rule.ext.includes(ext)) {
    return json({ error: `file extension .${ext} does not match ${declared}` }, 415);
  }

  const bytes = new Uint8Array(await file.arrayBuffer());

  // ---- validation: sniff the actual bytes ----
  if (rule.magic) {
    if (!rule.magic.some((sig) => startsWith(bytes, sig))) {
      return json({ error: "file contents do not match the declared type" }, 415);
    }
  } else if (rule.text) {
    if (!looksLikeText(bytes)) {
      return json({ error: "file contents do not look like text" }, 415);
    }
  }

  const sha256 = Array.from(
    new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
  ).map((b) => b.toString(16).padStart(2, "0")).join("");

  const filename = sanitizeFilename(file.name);

  // ================= new document =================
  if (!documentId) {
    if (profile.role !== "admin" && profile.role !== "owner") {
      return json({ error: "viewers cannot upload documents" }, 403);
    }
    if (!title) return json({ error: "title is required" }, 400);

    const docId = crypto.randomUUID();
    const path = `docs/${docId}/1/${filename}`;

    const { error: upErr } = await admin
      .storage
      .from("documents")
      .upload(path, bytes, { contentType: declared, upsert: false });
    if (upErr) return json({ error: "storage failure" }, 502);

    const { data: doc, error: insErr } = await admin
      .from("documents")
      .insert({
        id: docId,
        owner_id: user.id,
        title: title.slice(0, 200),
        category: category.slice(0, 60) || "general",
        description: description.slice(0, 2000),
        filename,
        mime_type: declared,
        size_bytes: file.size,
        sha256,
        storage_path: path,
        current_version: 1,
        status: "active",
      })
      .select("id")
      .single();
    if (insErr || !doc) {
      await admin.storage.from("documents").remove([path]);
      return json({ error: "insert failure" }, 502);
    }

    const { error: vErr } = await admin.from("document_versions").insert({
      document_id: docId,
      version_no: 1,
      filename,
      mime_type: declared,
      size_bytes: file.size,
      sha256,
      storage_path: path,
      uploaded_by: user.id,
      note: note.slice(0, 500),
    });
    if (vErr) return json({ error: "version record failure" }, 502);

    return json({ document_id: docId, version: 1, sha256 }, 201);
  }

  // ================= new version of an existing document =================
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(documentId)) {
    return json({ error: "not found" }, 404);
  }

  const { data: doc } = await admin
    .from("documents")
    .select("*")
    .eq("id", documentId)
    .maybeSingle();
  if (!doc) return json({ error: "not found" }, 404);

  const isAdmin = profile.role === "admin";
  const isOwner = doc.owner_id === user.id;
  let hasEdit = false;
  if (!isAdmin && !isOwner) {
    const { data: g } = await admin
      .from("grants")
      .select("permission")
      .eq("document_id", documentId)
      .eq("user_id", user.id)
      .is("revoked_at", null)
      .maybeSingle();
    hasEdit = g?.permission === "edit";
  }
  if (!(isAdmin || isOwner || hasEdit)) {
    return json({ error: "not found" }, 404); // no existence oracle
  }
  if (doc.status !== "active") {
    return json({ error: "document is not active" }, 409);
  }
  if (declared !== doc.mime_type) {
    return json({ error: "new versions must keep the original content type" }, 415);
  }

  const versionNo = doc.current_version + 1;
  const path = `docs/${documentId}/${versionNo}/${filename}`;

  const { error: upErr } = await admin
    .storage
    .from("documents")
    .upload(path, bytes, { contentType: declared, upsert: false });
  if (upErr) return json({ error: "storage failure" }, 502);

  const { error: vErr } = await admin.from("document_versions").insert({
    document_id: documentId,
    version_no: versionNo,
    filename,
    mime_type: declared,
    size_bytes: file.size,
    sha256,
    storage_path: path,
    uploaded_by: user.id,
    note: note.slice(0, 500),
  });
  if (vErr) return json({ error: "version record failure" }, 502);

  const { error: updErr } = await admin
    .from("documents")
    .update({
      filename,
      size_bytes: file.size,
      sha256,
      current_version: versionNo,
    })
    .eq("id", documentId);
  if (updErr) return json({ error: "update failure" }, 502);

  return json({ document_id: documentId, version: versionNo, sha256 }, 201);
});
