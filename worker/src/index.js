// T06 플랜두씨 다이어리 — Cloudflare Worker API + 정적 프론트 서빙
// 비밀키를 전혀 쓰지 않음: D1은 env.DB 바인딩으로만 접근하고 클라이언트에 어떤 키도 내려주지 않는다.

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { "content-type": "application/json; charset=utf-8" }
  });
}
function badRequest(message) {
  return json({ error: message }, 400);
}
function notFound() {
  return json({ error: "not found" }, 404);
}
function newId() {
  return crypto.randomUUID();
}
function nowIso() {
  return new Date().toISOString();
}
function todayKst() {
  // Asia/Seoul 기준 오늘 날짜(YYYY-MM-DD). Seoul은 DST 없는 UTC+9 고정.
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Seoul", year: "numeric", month: "2-digit", day: "2-digit"
  }).formatToParts(new Date());
  const by = {};
  parts.forEach(p => { by[p.type] = p.value; });
  return `${by.year}-${by.month}-${by.day}`;
}

async function readJson(request) {
  try { return await request.json(); } catch (e) { return null; }
}

function parseTags(raw) {
  if (Array.isArray(raw)) return raw.filter(t => typeof t === "string" && t.trim() !== "");
  if (typeof raw === "string") return raw.split(",").map(t => t.trim()).filter(Boolean);
  return [];
}

// ---------------- Plans ----------------

async function listPlans(env) {
  const { results } = await env.DB.prepare(
    "SELECT * FROM plans ORDER BY created_at DESC"
  ).all();
  return json({ plans: results });
}

async function createPlan(env, body) {
  if (!body || !body.title || !body.period_start || !body.period_end || !body.priority || !body.success_criteria || body.estimated_hours == null) {
    return badRequest("title, period_start, period_end, priority, success_criteria, estimated_hours가 모두 필요합니다.");
  }
  const id = newId();
  const now = nowIso();
  await env.DB.prepare(
    `INSERT INTO plans (id, title, period_start, period_end, priority, success_criteria, estimated_hours, source_reflection_id, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, body.title, body.period_start, body.period_end, body.priority, body.success_criteria, Number(body.estimated_hours), body.source_reflection_id || null, now, now).run();
  const row = await env.DB.prepare("SELECT * FROM plans WHERE id = ?").bind(id).first();
  return json({ plan: row }, 201);
}

async function updatePlan(env, id, body) {
  const existing = await env.DB.prepare("SELECT * FROM plans WHERE id = ?").bind(id).first();
  if (!existing) return notFound();

  // 고치기 전 값을 먼저 스냅샷으로 남긴다 (T06-C08)
  await env.DB.prepare(
    `INSERT INTO plan_history (id, plan_id, title, period_start, period_end, priority, success_criteria, estimated_hours, snapshot_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(newId(), existing.id, existing.title, existing.period_start, existing.period_end, existing.priority, existing.success_criteria, existing.estimated_hours, nowIso()).run();

  const next = {
    title: body.title != null ? body.title : existing.title,
    period_start: body.period_start != null ? body.period_start : existing.period_start,
    period_end: body.period_end != null ? body.period_end : existing.period_end,
    priority: body.priority != null ? body.priority : existing.priority,
    success_criteria: body.success_criteria != null ? body.success_criteria : existing.success_criteria,
    estimated_hours: body.estimated_hours != null ? Number(body.estimated_hours) : existing.estimated_hours
  };
  await env.DB.prepare(
    `UPDATE plans SET title=?, period_start=?, period_end=?, priority=?, success_criteria=?, estimated_hours=?, updated_at=? WHERE id=?`
  ).bind(next.title, next.period_start, next.period_end, next.priority, next.success_criteria, next.estimated_hours, nowIso(), id).run();

  const row = await env.DB.prepare("SELECT * FROM plans WHERE id = ?").bind(id).first();
  return json({ plan: row });
}

async function planHistory(env, id) {
  const { results } = await env.DB.prepare(
    "SELECT * FROM plan_history WHERE plan_id = ? ORDER BY snapshot_at DESC"
  ).bind(id).all();
  return json({ history: results });
}

// ---------------- Tasks ----------------

async function listTasks(env, url) {
  const planId = url.searchParams.get("plan_id");
  const q = url.searchParams.get("q");
  const status = url.searchParams.get("status");      // 'in_progress' | 'done'
  const overdue = url.searchParams.get("overdue");     // 'true'
  const blocked = url.searchParams.get("blocked");     // 'true'
  const tag = url.searchParams.get("tag");
  const sort = url.searchParams.get("sort") || "due_date_asc";

  let sql = `SELECT tasks.*,
      (SELECT COUNT(*) FROM execution_logs WHERE execution_logs.task_id = tasks.id) AS log_count,
      (SELECT json_group_array(json_object(
          'id', id, 'started_at', started_at, 'ended_at', ended_at,
          'actual_minutes', actual_minutes, 'blocked_reason', blocked_reason
        )) FROM execution_logs WHERE execution_logs.task_id = tasks.id) AS logs_json
    FROM tasks WHERE deleted_at IS NULL`;
  const params = [];
  if (planId) { sql += " AND plan_id = ?"; params.push(planId); }
  if (status) { sql += " AND status = ?"; params.push(status); }
  if (q) { sql += " AND title LIKE ?"; params.push("%" + q + "%"); }
  if (tag) { sql += " AND tags LIKE ?"; params.push("%\"" + tag + "\"%"); }
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
  const orderBy = SORTS[sort] || SORTS.due_date_asc;
  sql += " ORDER BY " + orderBy;

  const { results } = await env.DB.prepare(sql).bind(...params).all();
  let rows = results;

  if (blocked === "true") {
    const ids = rows.map(r => r.id);
    const blockedSet = await taskIdsWithBlockedReason(env, ids);
    rows = rows.filter(r => blockedSet.has(r.id));
  }

  return json({ tasks: rows, sort_applied: sort });
}

async function taskIdsWithBlockedReason(env, taskIds) {
  if (taskIds.length === 0) return new Set();
  const placeholders = taskIds.map(() => "?").join(",");
  const { results } = await env.DB.prepare(
    `SELECT DISTINCT task_id FROM execution_logs WHERE blocked_reason IS NOT NULL AND TRIM(blocked_reason) != '' AND task_id IN (${placeholders})`
  ).bind(...taskIds).all();
  return new Set(results.map(r => r.task_id));
}

async function createTask(env, body) {
  if (!body || !body.plan_id || !body.title) return badRequest("plan_id, title가 필요합니다.");
  const plan = await env.DB.prepare("SELECT id FROM plans WHERE id = ?").bind(body.plan_id).first();
  if (!plan) return badRequest("존재하지 않는 plan_id입니다.");
  const id = newId();
  const now = nowIso();
  await env.DB.prepare(
    `INSERT INTO tasks (id, plan_id, title, status, due_date, priority, tags, estimated_hours, created_at, updated_at)
     VALUES (?, ?, ?, 'in_progress', ?, ?, ?, ?, ?, ?)`
  ).bind(id, body.plan_id, body.title, body.due_date || null, body.priority || "medium", JSON.stringify(parseTags(body.tags)), Number(body.estimated_hours || 0), now, now).run();
  const row = await env.DB.prepare("SELECT * FROM tasks WHERE id = ?").bind(id).first();
  return json({ task: row }, 201);
}

async function updateTask(env, id, body) {
  const existing = await env.DB.prepare("SELECT * FROM tasks WHERE id = ? AND deleted_at IS NULL").bind(id).first();
  if (!existing) return notFound();
  const next = {
    title: body.title != null ? body.title : existing.title,
    due_date: body.due_date !== undefined ? body.due_date : existing.due_date,
    priority: body.priority != null ? body.priority : existing.priority,
    tags: body.tags != null ? JSON.stringify(parseTags(body.tags)) : existing.tags,
    estimated_hours: body.estimated_hours != null ? Number(body.estimated_hours) : existing.estimated_hours
  };
  await env.DB.prepare(
    `UPDATE tasks SET title=?, due_date=?, priority=?, tags=?, estimated_hours=?, updated_at=? WHERE id=?`
  ).bind(next.title, next.due_date, next.priority, next.tags, next.estimated_hours, nowIso(), id).run();
  const row = await env.DB.prepare("SELECT * FROM tasks WHERE id = ?").bind(id).first();
  return json({ task: row });
}

async function deleteTask(env, id) {
  const existing = await env.DB.prepare("SELECT * FROM tasks WHERE id = ? AND deleted_at IS NULL").bind(id).first();
  if (!existing) return notFound();
  await env.DB.prepare("UPDATE tasks SET deleted_at=?, updated_at=? WHERE id=?").bind(nowIso(), nowIso(), id).run();
  return json({ ok: true });
}

// 완료: 같은 순간의 중복 클릭은 UPDATE...WHERE status!='done' 로 막는다 (T06-C21, C22)
async function completeTask(env, id) {
  const now = nowIso();
  const res = await env.DB.prepare(
    "UPDATE tasks SET status='done', completed_at=?, updated_at=? WHERE id=? AND deleted_at IS NULL AND status != 'done'"
  ).bind(now, now, id).run();
  const changed = res.meta && res.meta.changes ? res.meta.changes : 0;
  if (changed > 0) {
    await env.DB.prepare(
      "INSERT INTO completion_events (id, task_id, completed_at) VALUES (?, ?, ?)"
    ).bind(newId(), id, now).run();
  }
  const row = await env.DB.prepare("SELECT * FROM tasks WHERE id = ?").bind(id).first();
  if (!row) return notFound();
  return json({ task: row, newly_completed: changed > 0 });
}

async function reopenTask(env, id) {
  const res = await env.DB.prepare(
    "UPDATE tasks SET status='in_progress', completed_at=NULL, updated_at=? WHERE id=? AND deleted_at IS NULL AND status = 'done'"
  ).bind(nowIso(), id).run();
  const row = await env.DB.prepare("SELECT * FROM tasks WHERE id = ?").bind(id).first();
  if (!row) return notFound();
  return json({ task: row });
}

// ---------------- Execution logs ----------------

async function createLog(env, taskId, body) {
  if (!body || !body.started_at || !body.ended_at) return badRequest("started_at, ended_at이 필요합니다.");
  const task = await env.DB.prepare("SELECT id FROM tasks WHERE id = ? AND deleted_at IS NULL").bind(taskId).first();
  if (!task) return notFound();
  const actualMinutes = body.actual_minutes != null
    ? Number(body.actual_minutes)
    : Math.max(0, (new Date(body.ended_at).getTime() - new Date(body.started_at).getTime()) / 60000);
  const id = newId();
  await env.DB.prepare(
    `INSERT INTO execution_logs (id, task_id, started_at, ended_at, actual_minutes, blocked_reason, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, taskId, body.started_at, body.ended_at, actualMinutes, body.blocked_reason || null, nowIso()).run();
  const row = await env.DB.prepare("SELECT * FROM execution_logs WHERE id = ?").bind(id).first();
  return json({ log: row }, 201);
}

async function listLogs(env, taskId) {
  const { results } = await env.DB.prepare(
    "SELECT * FROM execution_logs WHERE task_id = ? ORDER BY started_at DESC"
  ).bind(taskId).all();
  return json({ logs: results });
}

// ---------------- Review (돌아보기) ----------------

async function review(env, url) {
  const planId = url.searchParams.get("plan_id");
  let sql = "SELECT * FROM tasks WHERE deleted_at IS NULL";
  const params = [];
  if (planId) { sql += " AND plan_id = ?"; params.push(planId); }
  const { results: tasks } = await env.DB.prepare(sql).bind(...params).all();

  const today = todayKst();
  const plannedCount = tasks.length;
  const doneCount = tasks.filter(t => t.status === "done").length;
  const overdueCount = tasks.filter(t => t.status !== "done" && t.due_date && t.due_date < today).length;

  const taskIds = tasks.map(t => t.id);
  const blockedSet = await taskIdsWithBlockedReason(env, taskIds);
  const blockedCount = tasks.filter(t => blockedSet.has(t.id)).length;

  const estimatedHoursSum = tasks.reduce((sum, t) => sum + (t.estimated_hours || 0), 0);

  let actualMinutesSum = 0;
  if (taskIds.length > 0) {
    const placeholders = taskIds.map(() => "?").join(",");
    const { results: logRows } = await env.DB.prepare(
      `SELECT COALESCE(SUM(actual_minutes),0) AS total FROM execution_logs WHERE task_id IN (${placeholders})`
    ).bind(...taskIds).all();
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
    diff_hours: round2(diffHours),
    drilldown: {
      planned: taskListUrl({ plan_id: planId }),
      done: taskListUrl({ plan_id: planId, status: "done" }),
      overdue: taskListUrl({ plan_id: planId, overdue: "true" }),
      blocked: taskListUrl({ plan_id: planId, blocked: "true" })
    }
  });
}
function round2(n) { return Math.round(n * 100) / 100; }
function taskListUrl(params) {
  const usp = new URLSearchParams();
  Object.keys(params).forEach(k => { if (params[k]) usp.set(k, params[k]); });
  return "/api/tasks?" + usp.toString();
}

// ---------------- Reflections ----------------

async function createReflection(env, body) {
  if (!body || !body.plan_id || !body.note) return badRequest("plan_id, note가 필요합니다.");
  const id = newId();
  await env.DB.prepare(
    "INSERT INTO reflections (id, plan_id, note, created_at) VALUES (?, ?, ?, ?)"
  ).bind(id, body.plan_id, body.note, nowIso()).run();
  const row = await env.DB.prepare("SELECT * FROM reflections WHERE id = ?").bind(id).first();
  return json({ reflection: row }, 201);
}

async function latestUnusedReflection(env) {
  // 아직 어떤 계획의 source_reflection_id로도 연결되지 않은 가장 최근 메모 (다음 계획 작성 폼에 제안용)
  const row = await env.DB.prepare(
    `SELECT r.* FROM reflections r
     WHERE NOT EXISTS (SELECT 1 FROM plans p WHERE p.source_reflection_id = r.id)
     ORDER BY r.created_at DESC LIMIT 1`
  ).first();
  return json({ reflection: row || null });
}

// ---------------- Export ----------------

async function exportAll(env) {
  const [plans, planHistory, tasks, logs, reflections] = await Promise.all([
    env.DB.prepare("SELECT * FROM plans ORDER BY created_at").all(),
    env.DB.prepare("SELECT * FROM plan_history ORDER BY snapshot_at").all(),
    env.DB.prepare("SELECT * FROM tasks ORDER BY created_at").all(),
    env.DB.prepare("SELECT * FROM execution_logs ORDER BY created_at").all(),
    env.DB.prepare("SELECT * FROM reflections ORDER BY created_at").all()
  ]);
  const payload = {
    exported_at: nowIso(),
    plans: plans.results,
    plan_history: planHistory.results,
    tasks: tasks.results,
    execution_logs: logs.results,
    reflections: reflections.results
  };
  return new Response(JSON.stringify(payload, null, 2), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "content-disposition": "attachment; filename=plandoc-export.json"
    }
  });
}

// ---------------- Router ----------------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      if (path === "/api/plans" && method === "GET") return await listPlans(env);
      if (path === "/api/plans" && method === "POST") return await createPlan(env, await readJson(request));
      const planMatch = path.match(/^\/api\/plans\/([^/]+)$/);
      if (planMatch && method === "PUT") return await updatePlan(env, planMatch[1], await readJson(request) || {});
      const planHistMatch = path.match(/^\/api\/plans\/([^/]+)\/history$/);
      if (planHistMatch && method === "GET") return await planHistory(env, planHistMatch[1]);

      if (path === "/api/tasks" && method === "GET") return await listTasks(env, url);
      if (path === "/api/tasks" && method === "POST") return await createTask(env, await readJson(request));
      const taskMatch = path.match(/^\/api\/tasks\/([^/]+)$/);
      if (taskMatch && method === "PUT") return await updateTask(env, taskMatch[1], await readJson(request) || {});
      if (taskMatch && method === "DELETE") return await deleteTask(env, taskMatch[1]);
      const completeMatch = path.match(/^\/api\/tasks\/([^/]+)\/complete$/);
      if (completeMatch && method === "POST") return await completeTask(env, completeMatch[1]);
      const reopenMatch = path.match(/^\/api\/tasks\/([^/]+)\/reopen$/);
      if (reopenMatch && method === "POST") return await reopenTask(env, reopenMatch[1]);
      const logsMatch = path.match(/^\/api\/tasks\/([^/]+)\/logs$/);
      if (logsMatch && method === "GET") return await listLogs(env, logsMatch[1]);
      if (logsMatch && method === "POST") return await createLog(env, logsMatch[1], await readJson(request));

      if (path === "/api/review" && method === "GET") return await review(env, url);

      if (path === "/api/reflections" && method === "POST") return await createReflection(env, await readJson(request));
      if (path === "/api/reflections/latest-unused" && method === "GET") return await latestUnusedReflection(env);

      if (path === "/api/export" && method === "GET") return await exportAll(env);

      if (path.startsWith("/api/")) return notFound();

      // API가 아니면 정적 파일(프론트) 서빙
      return env.ASSETS.fetch(request);
    } catch (err) {
      return json({ error: String((err && err.message) || err) }, 500);
    }
  }
};
