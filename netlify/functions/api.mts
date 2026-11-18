import { createHash } from "node:crypto";
import { lookup } from "node:dns/promises";
import net from "node:net";

const MAX_HASH = 50e6;
const bad = (error: string, message: string, status = 400) => Response.json({ error, message }, { status });

function isPrivate(ip: string) {
  if (net.isIPv6(ip)) return /^(::1?$|f[cd]|fe[89ab]|::ffff:)/i.test(ip);
  const [a, b] = ip.split(".").map(Number);
  return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}

async function guard(u: URL) {
  if (!/^https?:$/.test(u.protocol)) throw new Error("Hanya link http atau https yang bisa diperiksa");
  const { address } = await lookup(u.hostname.replace(/^\[|\]$/g, ""));
  if (isPrivate(address)) throw new Error("Alamat ini tidak diizinkan");
}

async function get(url: string, headers: Record<string, string> = {}) {
  let u = new URL(url);
  for (let i = 0; i < 6; i++) {
    await guard(u);
    const r = await fetch(u, { redirect: "manual", headers: { "user-agent": "Mozilla/5.0 RimbaUnduh", ...headers } });
    const loc = r.headers.get("location");
    if (r.status >= 300 && r.status < 400 && loc) { u = new URL(loc, u); continue; }
    return { r, url: u.toString() };
  }
  throw new Error("Link dialihkan terlalu sering");
}

// Ubah link halaman berbagi menjadi link file langsung
function direct(raw: string) {
  const u = new URL(raw);
  const h = u.hostname.replace(/^www\./, "");
  if (h === "drive.google.com") {
    const id = u.pathname.match(/\/d\/([\w-]+)/)?.[1] || u.searchParams.get("id");
    if (id) return `https://drive.usercontent.google.com/download?id=${id}&export=download&confirm=t`;
  }
  if (h === "dropbox.com") { u.searchParams.delete("raw"); u.searchParams.set("dl", "1"); return u.toString(); }
  if (h === "github.com" && u.pathname.includes("/blob/")) return `https://raw.githubusercontent.com${u.pathname.replace("/blob/", "/")}`;
  return u.toString();
}

async function resolve(raw: string) {
  let { r, url } = await get(direct(raw), { range: "bytes=0-0" });
  let type = r.headers.get("content-type") || "";
  if (type.includes("text/html") && new URL(url).hostname.endsWith("mediafire.com")) {
    const page = await (await get(url)).r.text();
    const m = page.match(/https?:\/\/download[\w.-]*\.mediafire\.com\/[^"'\s]+/);
    if (m) { ({ r, url } = await get(m[0], { range: "bytes=0-0" })); type = r.headers.get("content-type") || ""; }
  }
  r.body?.cancel();
  if (type.includes("text/html")) throw new Error("Link ini membuka halaman web, bukan file langsung");
  if (r.status >= 400) throw new Error(`Server file menjawab dengan kode ${r.status}`);
  const cd = r.headers.get("content-disposition") || "";
  const fromHeader = cd.match(/filename\*=UTF-8''([^;]+)/i)?.[1] || cd.match(/filename="?([^";]+)"?/i)?.[1];
  const fromPath = new URL(url).pathname.split("/").filter(Boolean).pop();
  const total = r.headers.get("content-range")?.match(/\/(\d+)$/)?.[1] || r.headers.get("content-length");
  let name = fromHeader || fromPath || "file";
  try { name = decodeURIComponent(name); } catch {}
  return { url, name, size: total ? Number(total) : null, type: type.split(";")[0] || "tidak diketahui", host: new URL(url).hostname };
}

const vt = (path: string, init: RequestInit = {}) =>
  fetch("https://www.virustotal.com/api/v3" + path, { ...init, headers: { "x-apikey": Netlify.env.get("VT_API_KEY")!, ...init.headers } });

export default async (req: Request) => {
  const q = new URL(req.url).searchParams;
  const op = q.get("op");
  const url = q.get("url") || "";
  try {
    if (op === "resolve") {
      if (!url) return bad("url", "Tempel link dulu");
      return Response.json(await resolve(url));
    }
    if (!Netlify.env.get("VT_API_KEY")) return bad("no_key", "Kunci VirusTotal belum dipasang di server", 503);

    if (op === "scan") {
      await guard(new URL(url));
      const r = await vt("/urls", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ url }) });
      const j = await r.json();
      if (!r.ok) return bad("vt", j.error?.message || "VirusTotal menolak permintaan", 502);
      return Response.json({ id: j.data.id });
    }
    if (op === "report") {
      const id = q.get("id") || "";
      if (!/^[\w=-]+$/.test(id)) return bad("id", "ID tidak valid");
      const j = await (await vt("/analyses/" + id)).json();
      return Response.json({ status: j.data?.attributes?.status, stats: j.data?.attributes?.stats });
    }
    if (op === "hash") {
      const { r } = await get(url);
      const hash = createHash("sha256");
      let n = 0;
      for await (const chunk of r.body as any) {
        n += chunk.length;
        if (n > MAX_HASH) return Response.json({ skipped: "Berkas lebih dari 50 MB, isinya tidak dihitung" });
        hash.update(chunk);
      }
      const sha = hash.digest("hex");
      const v = await vt("/files/" + sha);
      if (v.status === 404) return Response.json({ found: false, sha });
      const j = await v.json();
      return Response.json({ found: true, sha, stats: j.data.attributes.last_analysis_stats });
    }
    return bad("op", "Perintah tidak dikenal");
  } catch (e: any) {
    return bad("fail", e.message || "Terjadi kesalahan", 502);
  }
};

export const config = { path: "/api" };
