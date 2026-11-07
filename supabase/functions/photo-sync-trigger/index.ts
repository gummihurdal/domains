// domains.azurenexus.com: run the "Sync photos from pCloud" GitHub workflow right after an upload, so new
// pictures/videos reach the gallery in minutes instead of waiting for the schedule.
// Deploy: supabase functions deploy photo-sync-trigger --no-verify-jwt --project-ref mjphpctvuxmbjhmcscoj
// Secret:  GH_DISPATCH_TOKEN = fine-grained GitHub token, repo gummihurdal/domains, permission Actions: read+write.
// No user data passes through here; the only effect is a workflow run, so it is rate-limited instead of authenticated.
import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const ORIGINS = new Set(["https://domains.azurenexus.com", "https://gummihurdal.github.io", "http://localhost:8000", "http://127.0.0.1:8000"]);
const REPO = "gummihurdal/domains";
const WORKFLOW = "sync-photos.yml";
let lastDispatch = 0;

function cors(req: Request): Record<string, string> {
  const o = req.headers.get("origin") ?? "";
  return {
    "Access-Control-Allow-Origin": ORIGINS.has(o) ? o : "https://domains.azurenexus.com",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "content-type",
    "Vary": "Origin",
  };
}

Deno.serve(async (req: Request) => {
  const h = { ...cors(req), "Content-Type": "application/json" };
  const reply = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: h });
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: h });
  if (req.method !== "POST") return reply({ ok: false, error: "POST only" }, 405);
  const token = Deno.env.get("GH_DISPATCH_TOKEN");
  if (!token) return reply({ ok: false, error: "GH_DISPATCH_TOKEN secret not set" }, 503);
  const now = Date.now();
  if (now - lastDispatch < 20_000) return reply({ ok: true, note: "a sync was requested seconds ago" });
  lastDispatch = now;
  const r = await fetch(`https://api.github.com/repos/${REPO}/actions/workflows/${WORKFLOW}/dispatches`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "domains-photo-sync",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ ref: "main" }),
  });
  if (r.status === 204) return reply({ ok: true });
  const text = (await r.text()).slice(0, 300);
  console.error("github dispatch failed", r.status, text);
  return reply({ ok: false, status: r.status, error: text }, 502);
});
