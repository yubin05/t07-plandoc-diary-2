// T07 플랜두씨 다이어리 2 — 인증 + 소유권 + 5일 지표 추적
// 비밀키 없음: 세션은 서명이 필요없는 순수 조회형 토큰(랜덤 바이트)이라 어떤 비밀키도 쓰지 않는다.
// 비밀번호: Workers 런타임 내장 Web Crypto(crypto.subtle)의 PBKDF2-SHA256, 계정마다 랜덤 salt.

const PBKDF2_ITERATIONS = 150000;
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7일

function json(data, status, extraHeaders) {
  const headers = Object.assign({ "content-type": "application/json; charset=utf-8" }, extraHeaders || {});
  return new Response(JSON.stringify(data), { status: status || 200, headers });
}
function badRequest(message) { return json({ error: message }, 400); }
function unauthorized() { return json({ error: "로그인이 필요합니다." }, 401); }
function forbidden() { return json({ error: "권한이 없습니다." }, 403); }
function notFound() { return json({ error: "not found" }, 404); }
function newId() { return crypto.randomUUID(); }
function nowIso() { return new Date().toISOString(); }

function todayKst() {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Seoul", year: "numeric", month: "2-digit", day: "2-digit"
  }).formatToParts(new Date());
  const by = {};
  parts.forEach((p) => { by[p.type] = p.value; });
  return `${by.year}-${by.month}-${by.day}`;
}
function kstDateOf(isoString) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Seoul", year: "numeric", month: "2-digit", day: "2-digit"
  }).formatToParts(new Date(isoString));
  const by = {};
  parts.forEach((p) => { by[p.type] = p.value; });
  return `${by.year}-${by.month}-${by.day}`;
}

async function readJson(request) {
  try { return await request.json(); } catch (e) { return null; }
}

// ---------------- 비밀번호 (PBKDF2, Web Crypto 내장 — 추가 라이브러리/비밀키 없음) ----------------

function bytesToBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
async function pbkdf2(password, saltBytes, iterations) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    keyMaterial, 256
  );
  return new Uint8Array(bits);
}
async function hashNewPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return {
    algo: "PBKDF2-SHA256",
    iterations: PBKDF2_ITERATIONS,
    salt: bytesToBase64(salt),
    hash: bytesToBase64(hash)
  };
}
function timingSafeEqualBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
async function verifyPassword(password, user) {
  const salt = base64ToBytes(user.password_salt);
  const computed = await pbkdf2(password, salt, user.password_iterations);
  const stored = base64ToBytes(user.password_hash);
  return timingSafeEqualBytes(computed, stored);
}
// 이메일이 존재하지 않을 때도 같은 시간이 걸리도록, 더미 해시 계산을 한 번 해 준다 (완벽한 상수시간은 아니지만 완화책).
async function dummyPasswordCheck(password) {
  const salt = new Uint8Array(16); // 고정 더미 salt
  await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return false;
}

// ---------------- 세션(쿠키) ----------------

function parseCookies(request) {
  const header = request.headers.get("cookie") || "";
  const out = {};
  header.split(";").forEach((pair) => {
    const idx = pair.indexOf("=");
    if (idx === -1) return;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}
function sessionCookieHeader(token, maxAgeSeconds, isHttps) {
  let c = `session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
  if (isHttps) c += "; Secure";
  return c;
}
function clearSessionCookieHeader(isHttps) {
  let c = "session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
  if (isHttps) c += "; Secure";
  return c;
}

async function createSession(env, userId) {
  const token = bytesToBase64(crypto.getRandomValues(new Uint8Array(32))).replace(/[^a-zA-Z0-9]/g, "");
  const now = nowIso();
  const expires = new Date(Date.now() + SESSION_TTL_SECONDS * 1000).toISOString();
  await env.DB.prepare("INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
    .bind(token, userId, now, expires).run();
  return { token, expires };
}
async function getSessionUser(env, request) {
  const cookies = parseCookies(request);
  const token = cookies["session"];
  if (!token) return null;
  const session = await env.DB.prepare("SELECT * FROM sessions WHERE id = ?").bind(token).first();
  if (!session) return null;
  if (new Date(session.expires_at).getTime() <= Date.now()) return null;
  const user = await env.DB.prepare("SELECT id, email FROM users WHERE id = ?").bind(session.user_id).first();
  if (!user) return null;
  return { userId: user.id, email: user.email, sessionToken: token };
}

// ---------------- Auth 라우트 ----------------

function isValidEmail(email) {
  return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function signup(env, body, isHttps) {
  if (!body || !isValidEmail(body.email) || typeof body.password !== "string" || body.password.length < 8) {
    return badRequest("이메일 형식과 8자 이상 비밀번호가 필요합니다.");
  }
  const email = body.email.trim().toLowerCase();
  const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
  if (existing) return badRequest("이미 가입된 이메일입니다.");

  const h = await hashNewPassword(body.password);
  const id = newId();
  await env.DB.prepare(
    `INSERT INTO users (id, email, password_algo, password_iterations, password_salt, password_hash, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, email, h.algo, h.iterations, h.salt, h.hash, nowIso()).run();

  const session = await createSession(env, id);
  return json({ user: { id, email } }, 201, { "set-cookie": sessionCookieHeader(session.token, SESSION_TTL_SECONDS, isHttps) });
}

async function login(env, body, isHttps) {
  const GENERIC_ERROR = "이메일 또는 비밀번호가 올바르지 않습니다.";
  if (!body || !isValidEmail(body.email) || typeof body.password !== "string") {
    return badRequest(GENERIC_ERROR);
  }
  const email = body.email.trim().toLowerCase();
  const user = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
  if (!user) {
    await dummyPasswordCheck(body.password); // 존재 유무에 따라 응답 시간이 크게 달라지지 않도록
    return json({ error: GENERIC_ERROR }, 401);
  }
  const ok = await verifyPassword(body.password, user);
  if (!ok) return json({ error: GENERIC_ERROR }, 401);

  const session = await createSession(env, user.id);
  return json({ user: { id: user.id, email: user.email } }, 200, { "set-cookie": sessionCookieHeader(session.token, SESSION_TTL_SECONDS, isHttps) });
}

async function logout(env, request, isHttps) {
  const cookies = parseCookies(request);
  const token = cookies["session"];
  if (token) {
    await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(token).run(); // 서버에서 진짜로 끊는다
  }
  return json({ ok: true }, 200, { "set-cookie": clearSessionCookieHeader(isHttps) });
}

async function me(env, auth) {
  if (!auth) return unauthorized();
  return json({ user: { id: auth.userId, email: auth.email } });
}

async function changePassword(env, auth, body, isHttps) {
  if (!auth) return unauthorized();
  if (!body || typeof body.current_password !== "string" || typeof body.new_password !== "string" || body.new_password.length < 8) {
    return badRequest("현재 비밀번호와 8자 이상의 새 비밀번호가 필요합니다.");
  }
  const user = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(auth.userId).first();
  const ok = await verifyPassword(body.current_password, user);
  if (!ok) return badRequest("현재 비밀번호가 올바르지 않습니다.");

  const h = await hashNewPassword(body.new_password);
  await env.DB.prepare(
    "UPDATE users SET password_algo=?, password_iterations=?, password_salt=?, password_hash=? WHERE id=?"
  ).bind(h.algo, h.iterations, h.salt, h.hash, auth.userId).run();

  // 이전에 발급된 모든 세션을 끊는다 (지금 요청용 새 세션만 새로 발급)
  await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(auth.userId).run();
  const session = await createSession(env, auth.userId);
  return json({ ok: true }, 200, { "set-cookie": sessionCookieHeader(session.token, SESSION_TTL_SECONDS, isHttps) });
}

async function deleteAccount(env, auth, isHttps) {
  if (!auth) return unauthorized();
  const uid = auth.userId;
  const tables = ["plan_history", "completion_events", "execution_logs", "tasks", "plans", "reflections", "daily_metrics", "rule_changes", "metric_config", "sessions"];
  for (const t of tables) {
    await env.DB.prepare(`DELETE FROM ${t} WHERE user_id = ?`).bind(uid).run();
  }
  await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(uid).run();
  return json({ ok: true }, 200, { "set-cookie": clearSessionCookieHeader(isHttps) });
}

// ---------------- Plans (소유자 필터 적용) ----------------

async function listPlans(env, auth) {
  const { results } = await env.DB.prepare("SELECT * FROM plans WHERE user_id = ? ORDER BY created_at DESC").bind(auth.userId).all();
  return json({ plans: results });
}
async function createPlan(env, auth, body) {
  if (!body || !body.title || !body.period_start || !body.period_end || !body.priority || !body.success_criteria || body.estimated_hours == null) {
    return badRequest("title, period_start, period_end, priority, success_criteria, estimated_hours가 모두 필요합니다.");
  }
  const id = newId();
  const now = nowIso();
  await env.DB.prepare(
    `INSERT INTO plans (id, title, period_start, period_end, priority, success_criteria, estimated_hours, source_reflection_id, user_id, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, body.title, body.period_start, body.period_end, body.priority, body.success_criteria, Number(body.estimated_hours), body.source_reflection_id || null, auth.userId, now, now).run();
  const row = await env.DB.prepare("SELECT * FROM plans WHERE id = ?").bind(id).first();
  return json({ plan: row }, 201);
}
async function updatePlan(env, auth, id, body) {
  const existing = await env.DB.prepare("SELECT * FROM plans WHERE id = ? AND user_id = ?").bind(id, auth.userId).first();
  if (!existing) return notFound(); // 존재 자체를 감춤 (내 것이 아니어도, 없어도 404)

  await env.DB.prepare(
    `INSERT INTO plan_history (id, plan_id, title, period_start, period_end, priority, success_criteria, estimated_hours, user_id, snapshot_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(newId(), existing.id, existing.title, existing.period_start, existing.period_end, existing.priority, existing.success_criteria, existing.estimated_hours, auth.userId, nowIso()).run();

  const next = {
    title: body.title != null ? body.title : existing.title,
    period_start: body.period_start != null ? body.period_start : existing.period_start,
    period_end: body.period_end != null ? body.period_end : existing.period_end,
    priority: body.priority != null ? body.priority : existing.priority,
    success_criteria: body.success_criteria != null ? body.success_criteria : existing.success_criteria,
    estimated_hours: body.estimated_hours != null ? Number(body.estimated_hours) : existing.estimated_hours
  };
  await env.DB.prepare(
    `UPDATE plans SET title=?, period_start=?, period_end=?, priority=?, success_criteria=?, estimated_hours=?, updated_at=? WHERE id=? AND user_id=?`
  ).bind(next.title, next.period_start, next.period_end, next.priority, next.success_criteria, next.estimated_hours, nowIso(), id, auth.userId).run();

  const row = await env.DB.prepare("SELECT * FROM plans WHERE id = ?").bind(id).first();
  return json({ plan: row });
}
async function planHistory(env, auth, id) {
  const owner = await env.DB.prepare("SELECT id FROM plans WHERE id = ? AND user_id = ?").bind(id, auth.userId).first();
  if (!owner) return notFound();
  const { results } = await env.DB.prepare("SELECT * FROM plan_history WHERE plan_id = ? AND user_id = ? ORDER BY snapshot_at DESC").bind(id, auth.userId).all();
  return json({ history: results });
}

// ---------------- Tasks ----------------

async function listTasks(env, auth, url) {
  const planId = url.searchParams.get("plan_id");
  const q = url.searchParams.get("q");
  const status = url.searchParams.get("status");
  const overdue = url.searchParams.get("overdue");
  const blocked = url.searchParams.get("blocked");
  const sort = url.searchParams.get("sort") || "due_date_asc";

  let sql = `SELECT tasks.*,
      (SELECT COUNT(*) FROM execution_logs WHERE execution_logs.task_id = tasks.id) AS log_count,
      (SELECT json_group_array(json_object(
          'id', id, 'started_at', started_at, 'ended_at', ended_at,
          'actual_minutes', actual_minutes, 'blocked_reason', blocked_reason
        )) FROM execution_logs WHERE execution_logs.task_id = tasks.id) AS logs_json
    FROM tasks WHERE deleted_at IS NULL AND user_id = ?`;
  const params = [auth.userId];
  if (planId) { sql += " AND plan_id = ?"; params.push(planId); }
  if (status) { sql += " AND status = ?"; params.push(status); }
  if (q) { sql += " AND title LIKE ?"; params.push("%" + q + "%"); }
  if (overdue === "true") {
    sql += " AND status != 'done' AND due_date IS NOT NULL AND due_date < ?";
    params.push(todayKst());
  }
  const SORTS = {
    due_date_asc: "due_date ASC, created_at ASC",
    due_date_desc: "due_date DESC, created_at ASC",
    priority: "CASE priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END ASC, due_date ASC, id ASC",
    created_desc: "created_at DESC, id ASC"
  };
  sql += " ORDER BY " + (SORTS[sort] || SORTS.due_date_asc);

  const { results } = await env.DB.prepare(sql).bind(...params).all();
  let rows = results;
  if (blocked === "true") {
    const ids = rows.map((r) => r.id);
    const blockedSet = await taskIdsWithBlockedReason(env, auth.userId, ids);
    rows = rows.filter((r) => blockedSet.has(r.id));
  }
  return json({ tasks: rows, sort_applied: sort });
}
async function taskIdsWithBlockedReason(env, userId, taskIds) {
  if (taskIds.length === 0) return new Set();
  const placeholders = taskIds.map(() => "?").join(",");
  const { results } = await env.DB.prepare(
    `SELECT DISTINCT task_id FROM execution_logs WHERE user_id = ? AND blocked_reason IS NOT NULL AND TRIM(blocked_reason) != '' AND task_id IN (${placeholders})`
  ).bind(userId, ...taskIds).all();
  return new Set(results.map((r) => r.task_id));
}
async function createTask(env, auth, body) {
  if (!body || !body.plan_id || !body.title) return badRequest("plan_id, title가 필요합니다.");
  const plan = await env.DB.prepare("SELECT id FROM plans WHERE id = ? AND user_id = ?").bind(body.plan_id, auth.userId).first();
  if (!plan) return badRequest("존재하지 않는 plan_id입니다.");
  const id = newId();
  const now = nowIso();
  await env.DB.prepare(
    `INSERT INTO tasks (id, plan_id, title, status, due_date, priority, tags, estimated_hours, user_id, created_at, updated_at)
     VALUES (?, ?, ?, 'in_progress', ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, body.plan_id, body.title, body.due_date || null, body.priority || "medium", JSON.stringify(parseTags(body.tags)), Number(body.estimated_hours || 0), auth.userId, now, now).run();
  const row = await env.DB.prepare("SELECT * FROM tasks WHERE id = ?").bind(id).first();
  return json({ task: row }, 201);
}
function parseTags(raw) {
  if (Array.isArray(raw)) return raw.filter((t) => typeof t === "string" && t.trim() !== "");
  if (typeof raw === "string") return raw.split(",").map((t) => t.trim()).filter(Boolean);
  return [];
}
async function updateTask(env, auth, id, body) {
  const existing = await env.DB.prepare("SELECT * FROM tasks WHERE id = ? AND user_id = ? AND deleted_at IS NULL").bind(id, auth.userId).first();
  if (!existing) return notFound();
  const next = {
    title: body.title != null ? body.title : existing.title,
    due_date: body.due_date !== undefined ? body.due_date : existing.due_date,
    priority: body.priority != null ? body.priority : existing.priority,
    tags: body.tags != null ? JSON.stringify(parseTags(body.tags)) : existing.tags,
    estimated_hours: body.estimated_hours != null ? Number(body.estimated_hours) : existing.estimated_hours
  };
  await env.DB.prepare(
    `UPDATE tasks SET title=?, due_date=?, priority=?, tags=?, estimated_hours=?, updated_at=? WHERE id=? AND user_id=?`
  ).bind(next.title, next.due_date, next.priority, next.tags, next.estimated_hours, nowIso(), id, auth.userId).run();
  const row = await env.DB.prepare("SELECT * FROM tasks WHERE id = ?").bind(id).first();
  return json({ task: row });
}
async function deleteTask(env, auth, id) {
  const existing = await env.DB.prepare("SELECT * FROM tasks WHERE id = ? AND user_id = ? AND deleted_at IS NULL").bind(id, auth.userId).first();
  if (!existing) return notFound();
  await env.DB.prepare("UPDATE tasks SET deleted_at=?, updated_at=? WHERE id=? AND user_id=?").bind(nowIso(), nowIso(), id, auth.userId).run();
  return json({ ok: true });
}
async function completeTask(env, auth, id) {
  const now = nowIso();
  const res = await env.DB.prepare(
    "UPDATE tasks SET status='done', completed_at=?, updated_at=? WHERE id=? AND user_id=? AND deleted_at IS NULL AND status != 'done'"
  ).bind(now, now, id, auth.userId).run();
  const changed = res.meta && res.meta.changes ? res.meta.changes : 0;
  if (changed > 0) {
    await env.DB.prepare("INSERT INTO completion_events (id, task_id, user_id, completed_at) VALUES (?, ?, ?, ?)").bind(newId(), id, auth.userId, now).run();
  }
  const row = await env.DB.prepare("SELECT * FROM tasks WHERE id = ? AND user_id = ?").bind(id, auth.userId).first();
  if (!row) return notFound();
  return json({ task: row, newly_completed: changed > 0 });
}
async function reopenTask(env, auth, id) {
  await env.DB.prepare(
    "UPDATE tasks SET status='in_progress', completed_at=NULL, updated_at=? WHERE id=? AND user_id=? AND deleted_at IS NULL AND status = 'done'"
  ).bind(nowIso(), id, auth.userId).run();
  const row = await env.DB.prepare("SELECT * FROM tasks WHERE id = ? AND user_id = ?").bind(id, auth.userId).first();
  if (!row) return notFound();
  return json({ task: row });
}

// ---------------- Execution logs ----------------

async function createLog(env, auth, taskId, body) {
  if (!body || !body.started_at || !body.ended_at) return badRequest("started_at, ended_at이 필요합니다.");
  const task = await env.DB.prepare("SELECT id FROM tasks WHERE id = ? AND user_id = ? AND deleted_at IS NULL").bind(taskId, auth.userId).first();
  if (!task) return notFound();
  const actualMinutes = body.actual_minutes != null
    ? Number(body.actual_minutes)
    : Math.max(0, (new Date(body.ended_at).getTime() - new Date(body.started_at).getTime()) / 60000);
  const id = newId();
  await env.DB.prepare(
    `INSERT INTO execution_logs (id, task_id, started_at, ended_at, actual_minutes, blocked_reason, user_id, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, taskId, body.started_at, body.ended_at, actualMinutes, body.blocked_reason || null, auth.userId, nowIso()).run();
  const row = await env.DB.prepare("SELECT * FROM execution_logs WHERE id = ?").bind(id).first();
  return json({ log: row }, 201);
}
async function listLogs(env, auth, taskId) {
  const task = await env.DB.prepare("SELECT id FROM tasks WHERE id = ? AND user_id = ?").bind(taskId, auth.userId).first();
  if (!task) return notFound();
  const { results } = await env.DB.prepare("SELECT * FROM execution_logs WHERE task_id = ? AND user_id = ? ORDER BY started_at DESC").bind(taskId, auth.userId).all();
  return json({ logs: results });
}

// ---------------- Review ----------------

async function review(env, auth, url) {
  const planId = url.searchParams.get("plan_id");
  let sql = "SELECT * FROM tasks WHERE deleted_at IS NULL AND user_id = ?";
  const params = [auth.userId];
  if (planId) { sql += " AND plan_id = ?"; params.push(planId); }
  const { results: tasks } = await env.DB.prepare(sql).bind(...params).all();

  const today = todayKst();
  const plannedCount = tasks.length;
  const doneCount = tasks.filter((t) => t.status === "done").length;
  const overdueCount = tasks.filter((t) => t.status !== "done" && t.due_date && t.due_date < today).length;

  const taskIds = tasks.map((t) => t.id);
  const blockedSet = await taskIdsWithBlockedReason(env, auth.userId, taskIds);
  const blockedCount = tasks.filter((t) => blockedSet.has(t.id)).length;

  const estimatedHoursSum = tasks.reduce((sum, t) => sum + (t.estimated_hours || 0), 0);
  let actualMinutesSum = 0;
  if (taskIds.length > 0) {
    const placeholders = taskIds.map(() => "?").join(",");
    const { results: logRows } = await env.DB.prepare(
      `SELECT COALESCE(SUM(actual_minutes),0) AS total FROM execution_logs WHERE user_id = ? AND task_id IN (${placeholders})`
    ).bind(auth.userId, ...taskIds).all();
    actualMinutesSum = (logRows[0] && logRows[0].total) || 0;
  }
  const actualHoursSum = actualMinutesSum / 60;
  const diffHours = actualHoursSum - estimatedHoursSum;

  return json({
    plan_id: planId || null,
    today_kst: today,
    planned_count: plannedCount,
    done_count: doneCount,
    overdue_count: overdueCount,
    blocked_count: blockedCount,
    estimated_hours_sum: round2(estimatedHoursSum),
    actual_hours_sum: round2(actualHoursSum),
    diff_hours: round2(diffHours)
  });
}
function round2(n) { return Math.round(n * 100) / 100; }

// ---------------- Reflections ----------------

async function createReflection(env, auth, body) {
  if (!body || !body.plan_id || !body.note) return badRequest("plan_id, note가 필요합니다.");
  const plan = await env.DB.prepare("SELECT id FROM plans WHERE id = ? AND user_id = ?").bind(body.plan_id, auth.userId).first();
  if (!plan) return badRequest("존재하지 않는 plan_id입니다.");
  const id = newId();
  await env.DB.prepare("INSERT INTO reflections (id, plan_id, note, user_id, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(id, body.plan_id, body.note, auth.userId, nowIso()).run();
  const row = await env.DB.prepare("SELECT * FROM reflections WHERE id = ?").bind(id).first();
  return json({ reflection: row }, 201);
}
async function latestUnusedReflection(env, auth) {
  const row = await env.DB.prepare(
    `SELECT r.* FROM reflections r
     WHERE r.user_id = ? AND NOT EXISTS (SELECT 1 FROM plans p WHERE p.source_reflection_id = r.id)
     ORDER BY r.created_at DESC LIMIT 1`
  ).bind(auth.userId).first();
  return json({ reflection: row || null });
}

// ---------------- Export / Import ----------------

async function exportAll(env, auth) {
  const uid = auth.userId;
  const [plans, planHist, tasks, logs, reflections] = await Promise.all([
    env.DB.prepare("SELECT * FROM plans WHERE user_id = ? ORDER BY created_at").bind(uid).all(),
    env.DB.prepare("SELECT * FROM plan_history WHERE user_id = ? ORDER BY snapshot_at").bind(uid).all(),
    env.DB.prepare("SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at").bind(uid).all(),
    env.DB.prepare("SELECT * FROM execution_logs WHERE user_id = ? ORDER BY created_at").bind(uid).all(),
    env.DB.prepare("SELECT * FROM reflections WHERE user_id = ? ORDER BY created_at").bind(uid).all()
  ]);
  const payload = {
    exported_at: nowIso(), owner_email: auth.email,
    plans: plans.results, plan_history: planHist.results, tasks: tasks.results,
    execution_logs: logs.results, reflections: reflections.results
  };
  return new Response(JSON.stringify(payload, null, 2), {
    status: 200,
    headers: { "content-type": "application/json; charset=utf-8", "content-disposition": "attachment; filename=plandoc-export.json" }
  });
}

// T06에서 내보낸 파일을 그대로 가져와 지금 로그인한 계정 소유로 넣는다 (T07-C100)
async function importFromT06(env, auth, body) {
  if (!body || !Array.isArray(body.plans)) return badRequest("올바른 내보내기 파일이 아닙니다.");
  const uid = auth.userId;
  let importedPlans = 0, importedTasks = 0, importedLogs = 0, importedReflections = 0;

  for (const p of body.plans) {
    await env.DB.prepare(
      `INSERT OR IGNORE INTO plans (id, title, period_start, period_end, priority, success_criteria, estimated_hours, source_reflection_id, user_id, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(p.id, p.title, p.period_start, p.period_end, p.priority, p.success_criteria, p.estimated_hours, null, uid, p.created_at, p.updated_at).run();
    importedPlans++;
  }
  for (const t of (body.tasks || [])) {
    await env.DB.prepare(
      `INSERT OR IGNORE INTO tasks (id, plan_id, title, status, due_date, priority, tags, estimated_hours, completed_at, deleted_at, user_id, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(t.id, t.plan_id, t.title, t.status, t.due_date, t.priority, t.tags, t.estimated_hours, t.completed_at, t.deleted_at, uid, t.created_at, t.updated_at).run();
    importedTasks++;
  }
  for (const l of (body.execution_logs || [])) {
    await env.DB.prepare(
      `INSERT OR IGNORE INTO execution_logs (id, task_id, started_at, ended_at, actual_minutes, blocked_reason, user_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(l.id, l.task_id, l.started_at, l.ended_at, l.actual_minutes, l.blocked_reason, uid, l.created_at).run();
    importedLogs++;
  }
  for (const r of (body.reflections || [])) {
    await env.DB.prepare(
      `INSERT OR IGNORE INTO reflections (id, plan_id, note, user_id, created_at) VALUES (?, ?, ?, ?, ?)`
    ).bind(r.id, r.plan_id, r.note, uid, r.created_at).run();
    importedReflections++;
  }
  return json({ imported: { plans: importedPlans, tasks: importedTasks, execution_logs: importedLogs, reflections: importedReflections } });
}

// ---------------- 5일 지표 추적 ----------------

async function getMetricConfig(env, auth) {
  const row = await env.DB.prepare("SELECT * FROM metric_config WHERE user_id = ?").bind(auth.userId).first();
  return json({ config: row || null });
}
async function createMetricConfig(env, auth, body) {
  const existing = await env.DB.prepare("SELECT user_id FROM metric_config WHERE user_id = ?").bind(auth.userId).first();
  if (existing) return badRequest("이미 1일차 설정이 고정되어 있습니다.");
  const required = ["question_text", "metric_name", "unit", "calc_rule_text", "missing_rule_text", "duplicate_rule_text", "outlier_rule_text", "rounding_rule_text", "week_start_text", "planning_rule_text"];
  for (const f of required) {
    if (!body || !body[f]) return badRequest(f + " 항목이 필요합니다.");
  }
  await env.DB.prepare(
    `INSERT INTO metric_config (user_id, question_text, metric_name, unit, calc_rule_text, missing_rule_text, duplicate_rule_text, outlier_rule_text, rounding_rule_text, week_start_text, planning_rule_text, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(auth.userId, body.question_text, body.metric_name, body.unit, body.calc_rule_text, body.missing_rule_text, body.duplicate_rule_text, body.outlier_rule_text, body.rounding_rule_text, body.week_start_text, body.planning_rule_text, nowIso()).run();
  const row = await env.DB.prepare("SELECT * FROM metric_config WHERE user_id = ?").bind(auth.userId).first();
  return json({ config: row }, 201);
}

// 오늘(Asia/Seoul) 완료한 할 일 개수를 오늘 날짜의 지표값으로 upsert
async function recordTodayMetric(env, auth) {
  const config = await env.DB.prepare("SELECT * FROM metric_config WHERE user_id = ?").bind(auth.userId).first();
  if (!config) return badRequest("먼저 1일차 설정을 저장하세요.");
  const today = todayKst();

  const { results: events } = await env.DB.prepare("SELECT completed_at FROM completion_events WHERE user_id = ?").bind(auth.userId).all();
  const count = events.filter((e) => kstDateOf(e.completed_at) === today).length;

  const existing = await env.DB.prepare("SELECT id FROM daily_metrics WHERE user_id = ? AND record_date = ?").bind(auth.userId, today).first();
  const now = nowIso();
  if (existing) {
    await env.DB.prepare("UPDATE daily_metrics SET metric_value=?, updated_at=? WHERE id=?").bind(count, now, existing.id).run();
  } else {
    await env.DB.prepare("INSERT INTO daily_metrics (id, user_id, record_date, metric_value, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(newId(), auth.userId, today, count, now, now).run();
  }
  const row = await env.DB.prepare("SELECT * FROM daily_metrics WHERE user_id = ? AND record_date = ?").bind(auth.userId, today).first();
  return json({ daily_metric: row });
}
async function listDailyMetrics(env, auth) {
  const { results } = await env.DB.prepare("SELECT * FROM daily_metrics WHERE user_id = ? ORDER BY record_date ASC").bind(auth.userId).all();
  return json({ daily_metrics: results });
}
async function createRuleChange(env, auth, body) {
  if (!body || !body.reason_text || !body.new_planning_rule_text) return badRequest("reason_text, new_planning_rule_text가 필요합니다.");
  const config = await env.DB.prepare("SELECT * FROM metric_config WHERE user_id = ?").bind(auth.userId).first();
  if (!config) return badRequest("먼저 1일차 설정을 저장하세요.");
  const id = newId();
  const now = nowIso();
  await env.DB.prepare("INSERT INTO rule_changes (id, user_id, changed_at, reason_text, new_planning_rule_text) VALUES (?, ?, ?, ?, ?)")
    .bind(id, auth.userId, now, body.reason_text, body.new_planning_rule_text).run();
  await env.DB.prepare("UPDATE metric_config SET planning_rule_text = ? WHERE user_id = ?").bind(body.new_planning_rule_text, auth.userId).run();
  return json({ rule_change: { id, changed_at: now, reason_text: body.reason_text, new_planning_rule_text: body.new_planning_rule_text } }, 201);
}
async function listRuleChanges(env, auth) {
  const { results } = await env.DB.prepare("SELECT * FROM rule_changes WHERE user_id = ? ORDER BY changed_at ASC").bind(auth.userId).all();
  return json({ rule_changes: results });
}

// ---------------- Router ----------------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const isHttps = url.protocol === "https:";

    try {
      // ---- 인증 불필요 ----
      if (path === "/api/auth/signup" && method === "POST") return await signup(env, await readJson(request), isHttps);
      if (path === "/api/auth/login" && method === "POST") return await login(env, await readJson(request), isHttps);
      if (path === "/api/auth/logout" && method === "POST") return await logout(env, request, isHttps);

      if (path.startsWith("/api/")) {
        // ---- 여기부터는 전부 인증 필요 ----
        const auth = await getSessionUser(env, request);

        if (path === "/api/auth/me" && method === "GET") return await me(env, auth);
        if (!auth) return unauthorized();

        if (path === "/api/auth/change-password" && method === "POST") return await changePassword(env, auth, await readJson(request), isHttps);
        if (path === "/api/auth/account" && method === "DELETE") return await deleteAccount(env, auth, isHttps);

        if (path === "/api/plans" && method === "GET") return await listPlans(env, auth);
        if (path === "/api/plans" && method === "POST") return await createPlan(env, auth, await readJson(request));
        const planMatch = path.match(/^\/api\/plans\/([^/]+)$/);
        if (planMatch && method === "PUT") return await updatePlan(env, auth, planMatch[1], await readJson(request) || {});
        const planHistMatch = path.match(/^\/api\/plans\/([^/]+)\/history$/);
        if (planHistMatch && method === "GET") return await planHistory(env, auth, planHistMatch[1]);

        if (path === "/api/tasks" && method === "GET") return await listTasks(env, auth, url);
        if (path === "/api/tasks" && method === "POST") return await createTask(env, auth, await readJson(request));
        const taskMatch = path.match(/^\/api\/tasks\/([^/]+)$/);
        if (taskMatch && method === "PUT") return await updateTask(env, auth, taskMatch[1], await readJson(request) || {});
        if (taskMatch && method === "DELETE") return await deleteTask(env, auth, taskMatch[1]);
        const completeMatch = path.match(/^\/api\/tasks\/([^/]+)\/complete$/);
        if (completeMatch && method === "POST") return await completeTask(env, auth, completeMatch[1]);
        const reopenMatch = path.match(/^\/api\/tasks\/([^/]+)\/reopen$/);
        if (reopenMatch && method === "POST") return await reopenTask(env, auth, reopenMatch[1]);
        const logsMatch = path.match(/^\/api\/tasks\/([^/]+)\/logs$/);
        if (logsMatch && method === "GET") return await listLogs(env, auth, logsMatch[1]);
        if (logsMatch && method === "POST") return await createLog(env, auth, logsMatch[1], await readJson(request));

        if (path === "/api/review" && method === "GET") return await review(env, auth, url);

        if (path === "/api/reflections" && method === "POST") return await createReflection(env, auth, await readJson(request));
        if (path === "/api/reflections/latest-unused" && method === "GET") return await latestUnusedReflection(env, auth);

        if (path === "/api/export" && method === "GET") return await exportAll(env, auth);
        if (path === "/api/import" && method === "POST") return await importFromT06(env, auth, await readJson(request));

        if (path === "/api/metric/config" && method === "GET") return await getMetricConfig(env, auth);
        if (path === "/api/metric/config" && method === "POST") return await createMetricConfig(env, auth, await readJson(request));
        if (path === "/api/metric/record-today" && method === "POST") return await recordTodayMetric(env, auth);
        if (path === "/api/metric/daily" && method === "GET") return await listDailyMetrics(env, auth);
        if (path === "/api/metric/rule-change" && method === "POST") return await createRuleChange(env, auth, await readJson(request));
        if (path === "/api/metric/rule-changes" && method === "GET") return await listRuleChanges(env, auth);

        return notFound();
      }

      return env.ASSETS.fetch(request);
    } catch (err) {
      return json({ error: String((err && err.message) || err) }, 500);
    }
  }
};
