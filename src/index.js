/* =================================================================
 *  Cloudflare Worker — Linux Kernel Update Email Notifier
 *
 *  Secrets needed (set via Dashboard or `wrangler secret put`):
 *    BREVO_API_KEY      – Brevo (Sendinblue) API key
 *    MAIL_FROM          – Verified sender, e.g. noreply@example.com
 *    MAIL_TO            – Comma-separated recipients
 *    TRIGGER_PASSWORD   – Password for manual web trigger
 *    CSRF_SECRET        – Random hex string ≥ 32 chars
 * ================================================================= */

// ─── Hex helpers ─────────────────────────────────────────────────
const buf2hex = b =>
  [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");

const hex2buf = h => {
  const a = new Uint8Array(h.length / 2);
  for (let i = 0; i < h.length; i += 2)
    a[i >> 1] = parseInt(h.substring(i, i + 2), 16);
  return a;
};

// ─── HTML escape ─────────────────────────────────────────────────
const esc = s =>
  String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

// ─── CSRF token: timestamp.HMAC-SHA256(timestamp, secret) ───────
async function csrfSign(secret) {
  const ts = Date.now().toString();
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(ts)
  );
  return `${ts}.${buf2hex(sig)}`;
}

async function csrfVerify(token, secret, maxMs = 600_000) {
  if (!token) return false;
  const dot = token.indexOf(".");
  if (dot < 1) return false;
  const ts = token.substring(0, dot);
  const hex = token.substring(dot + 1);
  if (Date.now() - Number(ts) > maxMs) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  return crypto.subtle.verify(
    "HMAC",
    key,
    hex2buf(hex),
    new TextEncoder().encode(ts)
  );
}

// ─── Timing-safe password compare (SHA-256 then constant-time XOR)
async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(String(a))),
    crypto.subtle.digest("SHA-256", enc.encode(String(b))),
  ]);
  const ua = new Uint8Array(ha),
    ub = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < ua.length; i++) diff |= ua[i] ^ ub[i];
  return diff === 0;
}

// ─── Beijing time (UTC+8) ────────────────────────────────────────
function beijing() {
  const d = new Date(Date.now() + 8 * 3600_000);
  const p = n => String(n).padStart(2, "0");
  const date = `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}`;
  const time = `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}`;
  return { date, time, full: `${date} ${time}` };
}

// ─── Fetch first 3 releases from kernel.org ──────────────────────
async function fetchReleases() {
  const res = await fetch("https://www.kernel.org/releases.json", {
    headers: { "User-Agent": "CF-Worker-Kernel-Notifier/1.0" },
  });
  if (!res.ok) throw new Error(`kernel.org responded ${res.status}`);
  const json = await res.json();
  return json.releases.slice(0, 3).map(r => ({
    moniker: r.moniker || "unknown",
    version: r.version || "N/A",
    isodate: r.released?.isodate ?? "N/A",
  }));
}

// ─── Email HTML builder ──────────────────────────────────────────
function emailHTML(releases, bj) {
  const palette = {
    mainline: { bg: "#DBEAFE", fg: "#2563EB" },
    stable:   { bg: "#D1FAE5", fg: "#059669" },
    longterm: { bg: "#EDE9FE", fg: "#7C3AED" },
  };
  const fallbackPalette = { bg: "#F3F4F6", fg: "#6B7280" };

  const releaseCards = releases
    .map(r => {
      const p = palette[r.moniker] || fallbackPalette;
      return `
      <!-- release: ${esc(r.moniker)} -->
      <table width="100%" cellpadding="0" cellspacing="0" role="presentation"
        style="width:100%;table-layout:fixed;">
        <tr><td style="padding:0 0 10px 0;">
          <table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="
            width:100%;table-layout:fixed;
            background-color:#FFFFFF;
            border-radius:12px;
            border-left:4px solid ${p.fg};
          ">
            <tr>
              <!-- moniker badge -->
              <td width="30%" align="center" valign="middle"
                style="padding:18px 4px;border-right:1px solid #F3F4F6;">
                <span style="
                  display:inline-block;
                  background:${p.bg};color:${p.fg};
                  font-size:11px;font-weight:700;
                  text-transform:uppercase;
                  padding:4px 9px;border-radius:8px;
                  letter-spacing:0.3px;
                ">${esc(r.moniker)}</span>
              </td>
              <!-- version -->
              <td width="30%" align="center" valign="middle" style="
                padding:18px 4px;
                border-right:1px solid #F3F4F6;
                font-family:'SF Mono',Menlo,Consolas,monospace;
                font-size:16px;font-weight:700;
                color:#111827;
                word-break:break-all;
                word-wrap:break-word;
              ">${esc(r.version)}</td>
              <!-- date -->
              <td width="40%" align="center" valign="middle" style="
                padding:18px 4px;
                font-family:'SF Mono',Menlo,Consolas,monospace;
                font-size:15px;font-weight:700;
                color:#111827;
                word-break:break-all;
                word-wrap:break-word;
              ">${esc(r.isodate)}</td>
            </tr>
          </table>
        </td></tr>
      </table>`;
    })
    .join("\n");

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta name="x-apple-disable-message-reformatting">
<meta name="format-detection" content="telephone=no,address=no,email=no,date=no,url=no">
<title>Linux Kernel Update</title>
<!--[if mso]>
<style type="text/css">
  body,table,td{font-family:Arial,Helvetica,sans-serif !important;}
</style>
<noscript><xml>
  <o:OfficeDocumentSettings>
    <o:PixelsPerInch>96</o:PixelsPerInch>
  </o:OfficeDocumentSettings>
</xml></noscript>
<![endif]-->
<style type="text/css">
  body{
    margin:0 !important;padding:0 !important;
    width:100% !important;min-width:100% !important;
    -webkit-text-size-adjust:100% !important;
    -ms-text-size-adjust:100% !important;
  }
  table{
    border-spacing:0 !important;
    border-collapse:collapse !important;
    mso-table-lspace:0pt !important;
    mso-table-rspace:0pt !important;
  }
  td{padding:0;}
  img{border:0;height:auto;line-height:100%;outline:none;text-decoration:none;}
</style>
</head>
<body style="
  margin:0;padding:0;width:100%;
  background-color:#F2F2F7;
  font-family:-apple-system,BlinkMacSystemFont,'SF Pro Text',
              'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
">

<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
  style="width:100%;table-layout:fixed;background-color:#F2F2F7;">
<tr>
<td align="center" valign="top" style="padding:0;">

<!--[if (gte mso 9)|(IE)]>
<table role="presentation" width="480" align="center"
  cellpadding="0" cellspacing="0" border="0"><tr><td>
<![endif]-->

<table role="presentation" cellpadding="0" cellspacing="0" border="0"
  style="width:100%;max-width:480px;table-layout:fixed;">

  <!-- ===== HEADER ===== -->
  <tr>
    <td align="center" style="
      background-color:#0F172A;
      background-image:linear-gradient(135deg,#0F172A 0%,#1E293B 100%);
      padding:36px 20px 28px;
    ">
      <div style="font-size:52px;line-height:62px;margin-bottom:12px;">&#x1F427;</div>
      <h1 style="
        margin:0;font-size:28px;font-weight:700;
        color:#FFFFFF;letter-spacing:-0.5px;line-height:30px;
      ">Linux Kernel</h1>
      <p style="
        margin:6px 0 0;font-size:11px;font-weight:600;
        color:#94A3B8;text-transform:uppercase;
        letter-spacing:1.5px;line-height:16px;
      ">Latest Releases</p>
    </td>
  </tr>

  <!-- ===== BODY ===== -->
  <tr>
    <td style="padding:16px 24px 8px;background-color:#F2F2F7;">
      ${releaseCards}
    </td>
  </tr>

  <!-- ===== FOOTER ===== -->
  <tr>
    <td align="center" style="
      background-color:#0F172A;
      background-image:linear-gradient(135deg,#1E293B 0%,#0F172A 100%);
      padding:20px 16px;
    ">
      <p style="margin:0;font-size:12px;color:#94A3B8;line-height:18px;">
        Updated at ${esc(bj.full)} UTC+8
      </p>
      <p style="margin:4px 0 0;font-size:12px;color:#64748B;line-height:18px;">
        Data source: kernel.org
      </p>
    </td>
  </tr>

</table>

<!--[if (gte mso 9)|(IE)]></td></tr></table><![endif]-->

</td>
</tr>
</table>

</body>
</html>`;
}

// ─── Send mail via Brevo API ─────────────────────────────────────
async function sendMail(env, subject, html) {
  const to = env.MAIL_TO.split(",").map(e => ({ email: e.trim() }));

  const res = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      accept: "application/json",
      "api-key": env.BREVO_API_KEY,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      sender: { name: "Newsletter", email: env.MAIL_FROM },
      to,
      subject,
      htmlContent: html,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Brevo ${res.status}: ${body}`);
  }
}

// ─── Core: fetch + build + send ──────────────────────────────────
async function sendKernelUpdate(env) {
  const releases = await fetchReleases();
  const bj = beijing();
  const subject = `⚙️Linux Kernel Update - ${bj.date}`;
  await sendMail(env, subject, emailHTML(releases, bj));
}

// ─── Web UI: trigger form ────────────────────────────────────────
function triggerPage(csrfToken) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kernel Notifier</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html{height:100%}
body{
  min-height:100%;display:flex;align-items:center;justify-content:center;
  background:linear-gradient(160deg,#0F172A 0%,#1E293B 50%,#0F172A 100%);
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  padding:24px;
}
.card{
  background:#fff;border-radius:20px;
  box-shadow:0 25px 60px rgba(0,0,0,.35);
  padding:48px 40px 44px;width:100%;max-width:420px;text-align:center;
}
.icon{font-size:48px;margin-bottom:16px}
h1{font-size:21px;color:#0F172A;margin-bottom:6px;font-weight:700}
.sub{color:#64748B;font-size:14px;margin-bottom:32px;line-height:1.5}
label{display:block;text-align:left;font-size:13px;font-weight:600;color:#334155;margin-bottom:8px}
input[type=password]{
  width:100%;padding:14px 18px;border:2px solid #E2E8F0;border-radius:10px;
  font-size:15px;outline:none;transition:border .2s,box-shadow .2s;
  background:#F8FAFC;
}
input[type=password]:focus{border-color:#3B82F6;box-shadow:0 0 0 3px rgba(59,130,246,.15);background:#fff}
button{
  margin-top:24px;width:100%;padding:16px;
  background:linear-gradient(135deg,#3B82F6,#2563EB);
  color:#fff;border:none;border-radius:10px;
  font-size:15px;font-weight:600;cursor:pointer;
  transition:transform .15s,box-shadow .15s;
  box-shadow:0 4px 14px rgba(37,99,235,.3);
}
button:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(37,99,235,.4)}
button:active{transform:translateY(0)}
.footer{margin-top:28px;color:#94A3B8;font-size:12px}
</style>
</head>
<body>
<div class="card">
  <div class="icon">&#x1F427;</div>
  <h1>Kernel Update Notifier</h1>
  <p class="sub">Enter password to manually trigger email</p>
  <form method="POST" autocomplete="off">
    <input type="hidden" name="_csrf" value="${esc(csrfToken)}">
    <label for="pw">Password</label>
    <input type="password" id="pw" name="password" required
           placeholder="Enter trigger password" autofocus>
    <button type="submit">Send Notification&ensp;&#x1F680;</button>
  </form>
  <p class="footer">Protected by CSRF &amp; password</p>
</div>
</body>
</html>`;
}

// ─── Web UI: result page ─────────────────────────────────────────
function resultPage(ok, msg) {
  const icon = ok ? "&#x2705;" : "&#x274C;";
  const title = ok ? "Success!" : "Error";
  const accent = ok ? "#059669" : "#DC2626";
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html{height:100%}
body{
  min-height:100%;display:flex;align-items:center;justify-content:center;
  background:linear-gradient(160deg,#0F172A 0%,#1E293B 50%,#0F172A 100%);
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  padding:24px;
}
.card{
  background:#fff;border-radius:20px;
  box-shadow:0 25px 60px rgba(0,0,0,.35);
  padding:48px 40px 44px;width:100%;max-width:420px;text-align:center;
}
.icon{font-size:52px;margin-bottom:18px}
h1{font-size:22px;color:#0F172A;margin-bottom:14px;font-weight:700}
p{color:#64748B;font-size:14px;margin-bottom:30px;line-height:1.6;word-break:break-word}
a{
  display:inline-block;padding:14px 36px;
  background:${accent};color:#fff;
  border-radius:10px;text-decoration:none;
  font-weight:600;font-size:14px;
  transition:transform .15s,box-shadow .15s;
  box-shadow:0 4px 14px ${accent}44;
}
a:hover{transform:translateY(-1px);box-shadow:0 6px 20px ${accent}55}
</style>
</head>
<body>
<div class="card">
  <div class="icon">${icon}</div>
  <h1>${title}</h1>
  <p>${esc(msg)}</p>
  <a href="./">&larr;&ensp;Back</a>
</div>
</body>
</html>`;
}

// ─── Security response headers ───────────────────────────────────
const SEC_HEADERS = {
  "Content-Type": "text/html;charset=utf-8",
  "Cache-Control": "no-store, no-cache, must-revalidate",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy":
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
};

// ─── Worker entry ────────────────────────────────────────────────
export default {
  /* ---------- HTTP trigger (manual) ---------- */
  async fetch(request, env) {
    if (request.method === "GET") {
      const token = await csrfSign(env.CSRF_SECRET);
      return new Response(triggerPage(token), { headers: SEC_HEADERS });
    }

    if (request.method === "POST") {
      let fd;
      try {
        fd = await request.formData();
      } catch {
        return new Response(resultPage(false, "Invalid request."), {
          status: 400,
          headers: SEC_HEADERS,
        });
      }

      const csrfOk = await csrfVerify(fd.get("_csrf"), env.CSRF_SECRET);
      if (!csrfOk) {
        return new Response(
          resultPage(false, "Session expired or invalid token. Please go back and refresh the page."),
          { status: 403, headers: SEC_HEADERS }
        );
      }

      const pwOk = await safeEqual(fd.get("password") ?? "", env.TRIGGER_PASSWORD);
      if (!pwOk) {
        return new Response(resultPage(false, "Incorrect password."), {
          status: 403,
          headers: SEC_HEADERS,
        });
      }

      try {
        await sendKernelUpdate(env);
        return new Response(
          resultPage(true, "Kernel update email has been sent successfully!"),
          { headers: SEC_HEADERS }
        );
      } catch (err) {
        return new Response(
          resultPage(false, `Failed to send: ${err.message}`),
          { status: 502, headers: SEC_HEADERS }
        );
      }
    }

    return new Response("Method Not Allowed", { status: 405 });
  },

  /* ---------- Cron trigger (scheduled) ---------- */
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(sendKernelUpdate(env));
  },
};
