// vault-admin: privileged operations that need the service role.
// Every action re-verifies the caller's session and authorises it here,
// on the server, on every request: user management (admin) and hard
// document deletion (owner/admin). All actions are audited.

import { createClient } from "jsr:@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const SUPA_URL = Deno.env.get("SUPABASE_URL")!;
const ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

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

  const ip = (req.headers.get("x-forwarded-for") ?? "").split(",")[0].trim();
  const ua = req.headers.get("user-agent") ?? "";

  const audit = (
    action: string,
    detail: Record<string, unknown>,
    docId: string | null = null,
    docTitle = "",
    targetId: string | null = null,
    targetEmail = "",
  ) =>
    admin.rpc("audit_write", {
      p_actor: user.id,
      p_actor_email: user.email ?? "",
      p_action: action,
      p_document: docId,
      p_document_title: docTitle,
      p_target: targetId,
      p_target_email: targetEmail,
      p_detail: detail,
      p_ip: ip,
      p_user_agent: ua,
    });

  const { data: profile } = await admin
    .from("profiles")
    .select("email, role, is_active")
    .eq("id", user.id)
    .maybeSingle();
  const isAdmin = !!profile && profile.is_active && profile.role === "admin";

  let body: Record<string, string>;
  try {
    body = await req.json();
  } catch {
    return json({ error: "invalid request body" }, 400);
  }
  const action = body.action ?? "";

  // =============== admin-only: user management ===============
  if (action === "create_user") {
    if (!isAdmin) return json({ error: "forbidden" }, 403);

    const email = (body.email ?? "").trim().toLowerCase();
    const password = body.password ?? "";
    const fullName = (body.full_name ?? "").trim().slice(0, 120);
    const role = body.role ?? "viewer";

    if (!EMAIL_RE.test(email)) return json({ error: "invalid email" }, 400);
    if (password.length < 10) {
      return json({ error: "password must be at least 10 characters" }, 400);
    }
    if (!["admin", "owner", "viewer"].includes(role)) {
      return json({ error: "invalid role" }, 400);
    }

    const { data: authUser, error: createErr } = await admin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { full_name: fullName },
    });
    if (createErr || !authUser) {
      return json({ error: createErr?.message ?? "user creation failed" }, 409);
    }

    const { error: profErr } = await admin.from("profiles").insert({
      id: authUser.user.id,
      email,
      full_name: fullName,
      role,
    });
    if (profErr) {
      await admin.auth.admin.deleteUser(authUser.user.id);
      return json({ error: "profile creation failed" }, 502);
    }

    await audit("admin.user_created", { role, email }, null, "", authUser.user.id, email);
    return json({ user_id: authUser.user.id }, 201);
  }

  if (action === "deactivate_user" || action === "activate_user") {
    if (!isAdmin) return json({ error: "forbidden" }, 403);
    const targetId = body.user_id ?? "";
    if (!UUID_RE.test(targetId)) return json({ error: "invalid user_id" }, 400);
    if (targetId === user.id) {
      return json({ error: "you cannot deactivate yourself" }, 400);
    }

    const { data: target } = await admin
      .from("profiles")
      .select("email, role")
      .eq("id", targetId)
      .maybeSingle();
    if (!target) return json({ error: "user not found" }, 404);

    const activate = action === "activate_user";
    const { error: updErr } = await admin
      .from("profiles")
      .update({ is_active: activate })
      .eq("id", targetId);
    if (updErr) return json({ error: "update failed" }, 502);

    if (!activate) {
      // sever every live grant immediately — the person is leaving
      const { data: revoked, error: revErr } = await admin
        .from("grants")
        .update({ revoked_at: new Date().toISOString(), revoked_by: user.id })
        .eq("user_id", targetId)
        .is("revoked_at", null)
        .select("id");
      if (revErr) return json({ error: "revocation failed" }, 502);
      await audit("admin.user_deactivated", { grants_revoked: revoked?.length ?? 0 },
        null, "", targetId, target.email);
    } else {
      await audit("admin.user_activated", {}, null, "", targetId, target.email);
    }
    return json({ ok: true });
  }

  if (action === "reset_password") {
    if (!isAdmin) return json({ error: "forbidden" }, 403);
    const targetId = body.user_id ?? "";
    const password = body.new_password ?? "";
    if (!UUID_RE.test(targetId)) return json({ error: "invalid user_id" }, 400);
    if (password.length < 10) {
      return json({ error: "password must be at least 10 characters" }, 400);
    }
    const { data: target } = await admin
      .from("profiles")
      .select("email")
      .eq("id", targetId)
      .maybeSingle();
    if (!target) return json({ error: "user not found" }, 404);

    const { error: updErr } = await admin.auth.admin.updateUserById(targetId, {
      password,
    });
    if (updErr) return json({ error: "password reset failed" }, 502);

    await audit("admin.password_reset", {}, null, "", targetId, target.email);
    return json({ ok: true });
  }

  // =============== owner/admin: hard delete a document ===============
  if (action === "purge_document") {
    const documentId = body.document_id ?? "";
    if (!UUID_RE.test(documentId)) return json({ error: "not found" }, 404);

    const { data: doc } = await admin
      .from("documents")
      .select("*")
      .eq("id", documentId)
      .maybeSingle();
    if (!doc) return json({ error: "not found" }, 404);

    if (!(isAdmin || doc.owner_id === user.id)) {
      return json({ error: "not found" }, 404); // no existence oracle
    }

    // list every object under the document's prefix and remove them
    const { data: objects } = await admin
      .storage
      .from("documents")
      .list("docs", { limit: 1000 });
    const targets = (objects ?? [])
      .filter((o) => o.name.startsWith(`${documentId}/`))
      .map((o) => `docs/${o.name}`);

    if (targets.length > 0) {
      await admin.storage.from("documents").remove(targets);
    }

    // rows first (grants + versions cascade), then the audit entry
    const { error: delErr } = await admin
      .from("documents")
      .delete()
      .eq("id", documentId);
    if (delErr) return json({ error: "delete failed" }, 502);

    await audit("doc.purged", {
      title: doc.title,
      versions: doc.current_version,
      owner_id: doc.owner_id,
    }, documentId, doc.title);

    return json({ ok: true });
  }

  return json({ error: "unknown action" }, 400);
});
