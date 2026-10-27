// serve-doc: the ONLY route through which document bytes leave the system.
// It re-verifies the caller's session and re-checks the grants table on
// every single request, so a revocation takes effect immediately. It never
// issues storage signed URLs — there is nothing long-lived to leak.

import { createClient } from "jsr:@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}

const SUPA_URL = Deno.env.get("SUPABASE_URL")!;
const ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  // ---- verify the caller's session token with the auth server ----
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

  const ip = (req.headers.get("x-forwarded-for") ?? "").split(",")[0].trim();
  const ua = req.headers.get("user-agent") ?? "";

  const audit = (
    action: string,
    docId: string | null,
    title: string,
    detail: Record<string, unknown>,
  ) =>
    admin.rpc("audit_write", {
      p_actor: user.id,
      p_actor_email: user.email ?? "",
      p_action: action,
      p_document: docId,
      p_document_title: title,
      p_target: null,
      p_target_email: "",
      p_detail: detail,
      p_ip: ip,
      p_user_agent: ua,
    });

  let body: { document_id?: string; version?: number };
  try {
    body = await req.json();
  } catch {
    return json({ error: "invalid request body" }, 400);
  }

  const docId = body.document_id ?? "";
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(docId)) {
    return json({ error: "not found" }, 404);
  }

  // ---- caller must be an active platform user ----
  const { data: profile } = await admin
    .from("profiles")
    .select("email, role, is_active")
    .eq("id", user.id)
    .maybeSingle();
  if (!profile || !profile.is_active) {
    await audit("auth.blocked_inactive", null, "", { document_id: docId });
    return json({ error: "not found" }, 404);
  }

  const { data: doc } = await admin
    .from("documents")
    .select("*")
    .eq("id", docId)
    .maybeSingle();
  if (!doc) return json({ error: "not found" }, 404);

  // ---- the access decision, made fresh for this request ----
  const isAdmin = profile.role === "admin";
  const isOwner = doc.owner_id === user.id;
  let grant: { permission: string } | null = null;
  if (!isAdmin && !isOwner) {
    const { data: g } = await admin
      .from("grants")
      .select("permission")
      .eq("document_id", docId)
      .eq("user_id", user.id)
      .is("revoked_at", null)
      .maybeSingle();
    grant = g ?? null;
  }

  const wantsVersion = body.version != null && body.version !== doc.current_version;
  const canRead = isAdmin || isOwner || grant !== null;
  const canReadOldVersion = isAdmin || isOwner || grant?.permission === "edit";
  const allowed =
    doc.status === "active" && canRead && (!wantsVersion || canReadOldVersion);

  // Denied and non-existent documents answer identically (404): the API
  // must not become an existence oracle. The audit trail records the truth.
  if (!allowed) {
    await audit("doc.download_denied", doc.id, doc.title, {
      requested_version: body.version ?? doc.current_version,
      reason: doc.status !== "active" ? "deleted" : "no_grant",
    });
    return json({ error: "not found" }, 404);
  }

  // ---- resolve the byte path (current or historical version) ----
  let storagePath = doc.storage_path;
  if (wantsVersion) {
    const { data: v } = await admin
      .from("document_versions")
      .select("storage_path")
      .eq("document_id", docId)
      .eq("version_no", body.version!)
      .maybeSingle();
    if (!v) return json({ error: "not found" }, 404);
    storagePath = v.storage_path;
  }

  const { data: blob, error: dlErr } = await admin
    .storage
    .from("documents")
    .download(storagePath);
  if (dlErr || !blob) return json({ error: "storage unavailable" }, 502);

  await audit("doc.downloaded", doc.id, doc.title, {
    version: body.version ?? doc.current_version,
    filename: doc.filename,
  });

  const bytes = new Uint8Array(await blob.arrayBuffer());
  return new Response(bytes, {
    headers: {
      ...CORS,
      "Content-Type": doc.mime_type,
      "Content-Disposition":
        `attachment; filename*=UTF-8''${encodeURIComponent(doc.filename)}`,
      "Cache-Control": "no-store",
    },
  });
});
