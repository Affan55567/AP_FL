import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const allowedOrigins = new Set([
  "https://affan55567.github.io",
]);

function isAllowedOrigin(origin: string): boolean {
  return allowedOrigins.has(origin) ||
    /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
}

const allowedLanguages = new Set([
  "Python",
  "Java",
  "C++",
  "HTML",
  "CSS",
  "JavaScript",
  "Other",
]);

const maximumRequestBytes = 6 * 1024 * 1024;
const maximumImageDataLength = 5_000_000;

function corsHeaders(origin: string | null): HeadersInit {
  const headers: Record<string, string> = {
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
    "Vary": "Origin",
  };

  if (origin && isAllowedOrigin(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
  }

  return headers;
}

function jsonResponse(
  request: Request,
  body: Record<string, unknown>,
  status = 200,
): Response {
  const headers = new Headers(corsHeaders(request.headers.get("origin")));
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { status, headers });
}

function constantTimeEqual(left: string, right: string): boolean {
  const encoder = new TextEncoder();
  const leftBytes = encoder.encode(left);
  const rightBytes = encoder.encode(right);
  const length = Math.max(leftBytes.length, rightBytes.length);
  let difference = leftBytes.length ^ rightBytes.length;

  for (let index = 0; index < length; index += 1) {
    difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  }

  return difference === 0;
}

function isNonEmptyString(value: unknown, maximumLength: number): value is string {
  return typeof value === "string" &&
    value.trim().length > 0 &&
    value.length <= maximumLength;
}

Deno.serve(async (request: Request): Promise<Response> => {
  const origin = request.headers.get("origin");
  const headers = corsHeaders(origin);

  if (origin && !isAllowedOrigin(origin)) {
    return jsonResponse(request, { error: "Origin is not allowed." }, 403);
  }

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers });
  }

  if (request.method !== "POST") {
    return jsonResponse(request, { error: "Method not allowed." }, 405);
  }

  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (contentLength > maximumRequestBytes) {
    return jsonResponse(request, { error: "Request is too large." }, 413);
  }

  let payload: Record<string, unknown>;
  try {
    const rawBody = await request.text();
    if (new TextEncoder().encode(rawBody).byteLength > maximumRequestBytes) {
      return jsonResponse(request, { error: "Request is too large." }, 413);
    }

    const parsed: unknown = JSON.parse(rawBody);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return jsonResponse(request, { error: "Invalid request body." }, 400);
    }

    payload = parsed as Record<string, unknown>;
  } catch {
    return jsonResponse(request, { error: "Invalid JSON request body." }, 400);
  }

  const adminPassword = Deno.env.get("AP_FL_ADMIN_PASSWORD");
  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  let serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const secretKeysJson = Deno.env.get("SUPABASE_SECRET_KEYS");

  if (!serviceRoleKey && secretKeysJson) {
    try {
      const secretKeys = JSON.parse(secretKeysJson) as Record<string, string>;
      serviceRoleKey =
        secretKeys.default ??
        Object.values(secretKeys).find((value) => typeof value === "string");
    } catch (error) {
      console.error("Supabase secret-key configuration is invalid:", error);
      return jsonResponse(request, { error: "Project administration is not configured." }, 500);
    }
  }

  if (!adminPassword || !supabaseUrl || !serviceRoleKey) {
    console.error("Admin function server secrets are not configured.");
    return jsonResponse(request, { error: "Project administration is not configured." }, 500);
  }

  const supabase = createClient(supabaseUrl, serviceRoleKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  });

  const ipAddress =
    request.headers.get("cf-connecting-ip") ??
    request.headers.get("x-real-ip") ??
    request.headers.get("x-forwarded-for")?.split(",")[0].trim() ??
    "unknown";
  const rateLimitBytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`${adminPassword}:${ipAddress}`),
  );
  const rateLimitKey = Array.from(new Uint8Array(rateLimitBytes))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

  try {
    const { data: allowed, error } = await supabase.rpc(
      "consume_ap_fl_admin_attempt",
      { p_ip_hash: rateLimitKey },
    );

    if (error) {
      console.error("Admin rate limit check failed:", error.message);
      return jsonResponse(request, { error: "Project administration is temporarily unavailable." }, 503);
    }

    if (allowed !== true) {
      return jsonResponse(request, { error: "Too many admin requests. Try again in 15 minutes." }, 429);
    }
  } catch (error) {
    console.error("Admin rate limit check failed:", error);
    return jsonResponse(request, { error: "Project administration is temporarily unavailable." }, 503);
  }

  if (
    typeof payload.password !== "string" ||
    payload.password.length > 1024 ||
    !constantTimeEqual(payload.password, adminPassword)
  ) {
    return jsonResponse(request, { error: "Incorrect admin password." }, 401);
  }

  if (payload.action === "verify") {
    return jsonResponse(request, { ok: true });
  }

  if (payload.action === "publish") {
    const project = payload.project;
    if (typeof project !== "object" || project === null || Array.isArray(project)) {
      return jsonResponse(request, { error: "Invalid project." }, 400);
    }

    const candidate = project as Record<string, unknown>;
    const type = candidate.type;
    const title = candidate.title;
    const description = candidate.description;

    if (
      (type !== "program" && type !== "picture") ||
      !isNonEmptyString(title, 200) ||
      !isNonEmptyString(description, 5000)
    ) {
      return jsonResponse(request, { error: "Project type, title, or description is invalid." }, 400);
    }

    let row: {
      type: "program" | "picture";
      title: string;
      description: string;
      language: string | null;
      code: string | null;
      image_url: string | null;
    };

    if (type === "program") {
      const imageUrl = candidate.image_url;
      let validatedImageUrl: string | null = null;

      if (imageUrl !== null) {
        if (typeof imageUrl !== "string" || imageUrl.length > 2048) {
          return jsonResponse(request, { error: "Program image URL is invalid." }, 400);
        }

        try {
          const parsedImageUrl = new URL(imageUrl);
          if (parsedImageUrl.protocol !== "https:" && parsedImageUrl.protocol !== "http:") {
            return jsonResponse(request, { error: "Program image URL must use HTTP or HTTPS." }, 400);
          }
          validatedImageUrl = parsedImageUrl.href;
        } catch {
          return jsonResponse(request, { error: "Program image URL is invalid." }, 400);
        }
      }

      if (
        typeof candidate.language !== "string" ||
        !allowedLanguages.has(candidate.language) ||
        typeof candidate.code !== "string" ||
        candidate.code.trim().length === 0 ||
        candidate.code.length > 1_000_000
      ) {
        return jsonResponse(request, { error: "Program language, code, or image is invalid." }, 400);
      }

      row = {
        type,
        title: title.trim(),
        description: description.trim(),
        language: candidate.language,
        code: candidate.code,
        image_url: validatedImageUrl,
      };
    } else {
      if (
        candidate.language !== null ||
        candidate.code !== null ||
        typeof candidate.image_url !== "string" ||
        candidate.image_url.length > maximumImageDataLength ||
        !/^data:image\/(?:jpeg|png|webp|gif);base64,[A-Za-z0-9+/]*={0,2}$/.test(
          candidate.image_url,
        )
      ) {
        return jsonResponse(request, { error: "Picture data is invalid or too large." }, 400);
      }

      row = {
        type,
        title: title.trim(),
        description: description.trim(),
        language: null,
        code: null,
        image_url: candidate.image_url,
      };
    }

    try {
      const { data, error } = await supabase
        .from("projects")
        .insert(row)
        .select("id, type, title, description, language, code, image_url, created_at")
        .single();

      if (error) {
        console.error("Project insert failed:", error.message);
        return jsonResponse(request, { error: "Could not publish the project." }, 500);
      }

      return jsonResponse(request, { project: data }, 201);
    } catch (error) {
      console.error("Project insert failed:", error);
      return jsonResponse(request, { error: "Could not publish the project." }, 500);
    }
  }

  if (payload.action === "delete") {
    const projectId = payload.project_id;

    if (
      !(
        (typeof projectId === "string" &&
          projectId.trim().length > 0 &&
          projectId.length <= 128) ||
        (typeof projectId === "number" && Number.isSafeInteger(projectId))
      )
    ) {
      return jsonResponse(request, { error: "Project ID is invalid." }, 400);
    }

    try {
      const { data, error } = await supabase
        .from("projects")
        .delete()
        .eq("id", projectId)
        .select("id")
        .maybeSingle();

      if (error) {
        console.error("Project delete failed:", error.message);
        return jsonResponse(request, { error: "Could not remove the project." }, 500);
      }

      if (!data) {
        return jsonResponse(request, { error: "Project not found." }, 404);
      }

      return jsonResponse(request, { deleted: true });
    } catch (error) {
      console.error("Project delete failed:", error);
      return jsonResponse(request, { error: "Could not remove the project." }, 500);
    }
  }

  return jsonResponse(request, { error: "Unknown admin action." }, 400);
});
