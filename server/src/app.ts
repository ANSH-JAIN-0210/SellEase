import express, {
  type Request,
  type Response,
  type NextFunction,
} from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import { rateLimit } from "express-rate-limit";
import { z, ZodError } from "zod";
import mongoose from "mongoose";
import { randomUUID } from "node:crypto";
import { User, Org, RecordModel, Session } from "./models.js";
import {
  authenticate,
  register,
  login,
  logout,
  recover,
  reset,
  passwordHash,
  hash,
  type AuthRequest,
} from "./auth.js";
import { authorize, kinds, roles, transact, readable } from "./service.js";
import {
  DomainError,
  fail,
  type Actor,
  type Kind,
  type Data,
} from "./types.js";
import { settingsSchema } from "./validation.js";
import { financialReport, builtInAccounts } from "./accounting.js";
import { ageingReport } from "./ageing.js";

const actor = (req: AuthRequest) => req.actor ?? fail("Sign in required", 401);
const param = (req: Request, key: string) => String(req.params[key]);
const key = (req: Request) => req.get("Idempotency-Key") ?? "";
const financial: Kind[] = [
  "journals",
  "payments",
  "expenses",
  "audit",
  "creditNotes",
  "debitNotes",
];
const canFinance = (a: Actor) =>
  ["owner", "admin", "accountant"].includes(a.role);
function readAccess(a: Actor, kind: Kind) {
  authorize(a, "read");
  if (!readable(a, kind)) fail("Module access denied", 403);
  if (financial.includes(kind) && !canFinance(a))
    fail("Financial access required", 403);
  if (kind === "staff" && !["owner", "admin"].includes(a.role))
    fail("Staff administration access required", 403);
}
function kindParam(req: Request): Kind {
  const k = param(req, "kind");
  if (!kinds.includes(k as Kind)) fail("Unknown module", 404);
  return k as Kind;
}
function redact<
  T extends {
    kind: Kind;
    data: Data;
  },
>(entries: T[], a: Actor) {
  if (
    [
      "owner",
      "admin",
      "accountant",
      "production",
      "purchasing",
      "inventory",
    ].includes(a.role)
  )
    return entries;
  return entries.map((e) => {
    const data = { ...e.data };
    delete data.cost;
    delete data.actualCost;
    delete data.costLines;
    if (data.lines)
      data.lines = data.lines.map((line) => {
        const safe = { ...line };
        delete safe.costValue;
        return safe;
      });
    if ("value" in data) delete (data as Record<string, unknown>).value;
    return { ...e, data };
  });
}
export function createApp() {
  const app = express();
  app.disable("x-powered-by");
  app.use(helmet());
  const origin = process.env.CLIENT_ORIGIN ?? "http://localhost:4200";
  app.use(
    cors({
      origin,
      credentials: true,
      allowedHeaders: ["Content-Type", "X-SellEase", "Idempotency-Key"],
    }),
  );
  app.use(express.json({ limit: "1mb" }));
  app.use(cookieParser());
  app.use((req, res, next) => {
    res.setHeader("X-Request-ID", randomUUID());
    if (!["GET", "HEAD", "OPTIONS"].includes(req.method)) {
      if (req.get("X-SellEase") !== "1")
        return next(new DomainError(403, "Required request header missing"));
      if (req.get("Origin") && req.get("Origin") !== origin)
        return next(new DomainError(403, "Origin rejected"));
    }
    next();
  });
  app.use(
    "/api",
    rateLimit({
      windowMs: 60_000,
      limit: 500,
      standardHeaders: "draft-8",
      legacyHeaders: false,
    }),
  );
  app.get("/api/health", (_req, res) =>
    res.status(mongoose.connection.readyState === 1 ? 200 : 503).json({
      status: mongoose.connection.readyState === 1 ? "ready" : "unavailable",
    }),
  );
  const authLimit = rateLimit({
    windowMs: 15 * 60_000,
    limit: 60,
    standardHeaders: "draft-8",
    legacyHeaders: false,
  });
  app.post("/api/auth/register", authLimit, register);
  app.post("/api/auth/login", authLimit, login);
  app.post("/api/auth/recover", authLimit, recover);
  app.post("/api/auth/reset", authLimit, reset);
  app.post("/api/auth/logout", logout);
  app.get("/api/catalog/:org", async (req, res) => {
    const org = await Org.findOne({
      id: param(req, "org"),
      "settings.catalogEnabled": true,
    }).lean();
    if (!org) fail("Catalog unavailable", 404);
    const page = z.coerce
      .number()
      .int()
      .min(1)
      .max(10000)
      .parse(req.query.page ?? 1);
    const records = await RecordModel.find({
      org: org!.id,
      kind: "products",
      "data.published": true,
      "data.status": "active",
    })
      .sort({ id: 1 })
      .skip((page - 1) * 24)
      .limit(24)
      .lean();
    res.json({
      name: org!.settings.name,
      currency: org!.settings.currency,
      page,
      items: records.map((e) => ({
        id: e.id,
        name: e.data.name,
        sku: e.data.sku,
        description: e.data.description,
        color: e.data.color,
        size: e.data.size,
        price: e.data.price,
        unit: e.data.unit,
      })),
    });
  });
  app.use("/api", authenticate);
  app.get("/api/me", async (req: AuthRequest, res) => {
    const a = actor(req);
    const org = await Org.findOne({ id: a.org }).lean();
    res.json({
      user: a,
      settings: org!.settings,
      permissions: roles[a.role] ?? [],
      readable: kinds.filter((k) => readable(a, k)),
    });
  });
  app.put("/api/settings", async (req: AuthRequest, res) => {
    const a = actor(req);
    authorize(a, "settings");
    const settings = settingsSchema.parse(req.body);
    res.json(
      await transact(a, key(req), { path: req.path, settings }, async (b) => {
        const previous = await Org.findOne({ id: a.org })
          .session(b.session)
          .lean();
        if (
          settings.currency !== previous!.settings.currency &&
          (await RecordModel.exists({
            org: a.org,
            kind: {
              $in: [
                "products",
                "materials",
                "invoices",
                "supplierInvoices",
                "expenses",
                "payments",
                "journals",
              ],
            },
          }).session(b.session))
        )
          fail(
            "Currency is locked after monetary records exist. Use a reviewed migration or a separate business.",
            409,
          );
        if (
          settings.financialYearStart !==
            previous!.settings.financialYearStart &&
          (await RecordModel.exists({
            org: a.org,
            "data.number": { $exists: true },
          }).session(b.session))
        )
          fail(
            "Financial-year configuration is locked after document numbering begins.",
            409,
          );
        await Org.updateOne(
          { id: a.org },
          {
            $set: {
              settings: {
                ...settings,
                ...(previous?.settings.closedThrough
                  ? { closedThrough: previous.settings.closedThrough }
                  : {}),
                onboarding: {
                  isMobileVerified: false,
                  isPersonalInfoSaved: true,
                  isBusinessInfoSaved: true,
                  isAddressDetailSaved: !!settings.address,
                  isTransactionInfoSaved: true,
                },
              },
            },
          },
          { session: b.session },
        );
        return { success: true };
      }),
    );
  });
  app.get("/api/reports/financial", async (req: AuthRequest, res) => {
    const a = actor(req);
    if (!canFinance(a)) fail("Accounting permission required", 403);
    const q = z
      .object({
        from: z.string().date().optional(),
        to: z.string().date().optional(),
      })
      .parse(req.query);
    if (q.from && q.to && q.from > q.to)
      fail("From date must be on or before to date");
    res.json(await financialReport(a, q.from, q.to));
  });
  app.get("/api/reports/ageing", async (req: AuthRequest, res) => {
    const a = actor(req);
    if (!canFinance(a)) fail("Accounting permission required", 403);
    const org = await Org.findOne({ id: a.org }).lean();
    const asOf = z
      .string()
      .date()
      .parse(
        req.query.asOf ??
          new Date().toLocaleDateString("en-CA", {
            timeZone: org!.settings.timezone,
          }),
      );
    res.json(await ageingReport(a, asOf));
  });
  app.post("/api/accounting/close", async (req: AuthRequest, res) => {
    const a = actor(req);
    authorize(a, "settings");
    const p = z.object({ through: z.string().date() }).strict().parse(req.body);
    res.json(
      await transact(a, key(req), { path: req.path, ...p }, async (b) => {
        const org = await Org.findOne({ id: a.org }).session(b.session).lean();
        const today = new Date().toLocaleDateString("en-CA", {
          timeZone: org!.settings.timezone,
        });
        if (p.through > today) fail("Cannot close a future period");
        if (
          org!.settings.closedThrough &&
          p.through <= org!.settings.closedThrough
        )
          fail("The close date must advance the existing lock");
        const pending = await RecordModel.countDocuments({
          org: a.org,
          kind: {
            $in: [
              "invoices",
              "supplierInvoices",
              "payments",
              "expenses",
              "journals",
              "creditNotes",
              "debitNotes",
              "customerReturns",
              "supplierReturns",
            ],
          },
          "data.status": "draft",
          "data.date": { $lte: p.through },
        }).session(b.session);
        if (pending)
          fail(
            "Finalize or void dated financial/return drafts before closing the period",
            409,
          );
        const rows = await RecordModel.aggregate<{
          debit: number;
          credit: number;
        }>([
          {
            $match: {
              org: a.org,
              kind: "journals",
              "data.status": "posted",
              "data.date": { $lte: p.through },
            },
          },
          { $unwind: "$data.journalLines" },
          {
            $group: {
              _id: null,
              debit: { $sum: "$data.journalLines.debit" },
              credit: { $sum: "$data.journalLines.credit" },
            },
          },
        ]).session(b.session);
        if (rows[0] && rows[0].debit !== rows[0].credit)
          fail("Journal totals do not balance", 409);
        const chart = { ...builtInAccounts };
        for (const account of await b.all("accounts"))
          chart[account.data.name!] = account.data.accountType!;
        const unmapped = new Set<string>();
        for (const journal of await b.all("journals"))
          if (
            journal.data.status === "posted" &&
            journal.data.date! <= p.through
          )
            for (const line of journal.data.journalLines ?? [])
              if (!chart[line.account] && !line.account.startsWith("Expense: "))
                unmapped.add(line.account);
        if (unmapped.size)
          fail(
            "Classify these accounts before closing: " +
              [...unmapped].join(", "),
            409,
          );
        await Org.updateOne(
          { id: a.org },
          { $set: { "settings.closedThrough": p.through } },
          { session: b.session },
        );
        await b.add("notifications", {
          name: "Accounting period closed",
          date: p.through,
          actor: a.id,
        });
        return { closedThrough: p.through };
      }),
    );
  });
  app.get("/api/users", async (req: AuthRequest, res) => {
    const a = actor(req);
    authorize(a, "users");
    res.json({
      data: await User.find({ org: a.org })
        .select("id name email role active")
        .lean(),
    });
  });
  app.post("/api/users", async (req: AuthRequest, res) => {
    const a = actor(req);
    authorize(a, "users");
    const p = z
      .object({
        name: z.string().min(1).max(120),
        email: z
          .string()
          .email()
          .transform((v) => v.toLowerCase()),
        password: z.string().min(12).max(128),
        role: z.enum([
          "admin",
          "accountant",
          "sales",
          "purchasing",
          "production",
          "inventory",
          "staff",
        ]),
      })
      .strict()
      .parse(req.body);
    const password = await passwordHash(p.password);
    const result = await transact(
      a,
      key(req),
      {
        path: req.path,
        name: p.name,
        email: p.email,
        role: p.role,
        passwordFingerprint: hash(p.password),
      },
      async (b) => {
        const u = {
          id: randomUUID(),
          org: a.org,
          ...p,
          password,
          active: true,
        };
        await User.create([u], { session: b.session });
        return {
          id: u.id,
          name: u.name,
          email: u.email,
          role: u.role,
          active: u.active,
        };
      },
    );
    res.status(201).json(result);
  });
  app.put("/api/users/:id", async (req: AuthRequest, res) => {
    const a = actor(req);
    authorize(a, "users");
    const p = z
      .object({
        active: z.boolean(),
        role: z.enum([
          "admin",
          "accountant",
          "sales",
          "purchasing",
          "production",
          "inventory",
          "staff",
        ]),
      })
      .strict()
      .parse(req.body);
    res.json(
      await transact(a, key(req), { path: req.path, ...p }, async (b) => {
        const target = await User.findOne({
          id: param(req, "id"),
          org: a.org,
        }).session(b.session);
        if (!target) fail("User not found", 404);
        if (target!.role === "owner" || target!.id === a.id)
          fail("Owner/self changes are not allowed");
        target!.active = p.active;
        target!.role = p.role;
        await target!.save({ session: b.session });
        await Session.deleteMany(
          { userId: target!.id },
          { session: b.session },
        );
        return { success: true };
      }),
    );
  });
  app.get("/api/records/:kind", async (req: AuthRequest, res) => {
    const a = actor(req),
      kind = kindParam(req);
    readAccess(a, kind);
    const q = z
      .object({
        page: z.coerce.number().int().min(1).max(100000).default(1),
        limit: z.coerce.number().int().min(1).max(100).default(20),
        search: z.string().max(100).default(""),
        status: z.string().max(40).optional(),
        from: z.string().date().optional(),
        to: z.string().date().optional(),
        sort: z
          .enum(["createdAt", "data.name", "data.date", "data.total"])
          .default("createdAt"),
        direction: z.enum(["asc", "desc"]).default("desc"),
      })
      .parse(req.query);
    const escaped = q.search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const filter: mongoose.FilterQuery<unknown> = { org: a.org, kind };
    if (q.search)
      filter.$or = ["name", "sku", "number", "subject", "reference"].map(
        (f) => ({ [`data.${f}`]: { $regex: escaped, $options: "i" } }),
      );
    if (q.status) filter["data.status"] = q.status;
    if (q.from || q.to)
      filter["data.date"] = {
        ...(q.from ? { $gte: q.from } : {}),
        ...(q.to ? { $lte: q.to } : {}),
      };
    const [data, total] = await Promise.all([
      RecordModel.find(filter)
        .sort({ [q.sort]: q.direction === "asc" ? 1 : -1, id: 1 })
        .skip((q.page - 1) * q.limit)
        .limit(q.limit)
        .lean(),
      RecordModel.countDocuments(filter),
    ]);
    res.json({ data: redact(data, a), total, page: q.page, limit: q.limit });
  });
  app.get("/api/records/:kind/:id", async (req: AuthRequest, res) => {
    const a = actor(req),
      kind = kindParam(req);
    readAccess(a, kind);
    const e = await RecordModel.findOne({
      org: a.org,
      kind,
      id: param(req, "id"),
    }).lean();
    if (!e) fail("Record not found", 404);
    res.json(redact([e!], a)[0]);
  });
  app.post("/api/records/:kind", async (req: AuthRequest, res) => {
    const a = actor(req),
      kind = kindParam(req);
    authorize(a, kind);
    const result = await transact(
      a,
      key(req),
      { path: req.path, data: req.body },
      (b) => b.create(kind, req.body),
    );
    res.status(201).json(redact([result], a)[0]);
  });
  app.put("/api/records/:kind/:id", async (req: AuthRequest, res) => {
    const a = actor(req),
      kind = kindParam(req);
    authorize(a, kind);
    const result = await transact(
      a,
      key(req),
      { path: req.path, data: req.body },
      (b) => b.update(kind, param(req, "id"), req.body),
    );
    res.json(redact([result], a)[0]);
  });
  app.post("/api/records/:kind/:id/actions", async (req: AuthRequest, res) => {
    const a = actor(req),
      kind = kindParam(req);
    authorize(a, kind);
    const result = await transact(
      a,
      key(req),
      { path: req.path, data: req.body },
      (b) => b.act(kind, param(req, "id"), req.body),
    );
    res.json(redact([result], a)[0]);
  });
  app.post("/api/stock/adjust", async (req: AuthRequest, res) => {
    authorize(actor(req), "movements");
    res.json(
      await transact(
        actor(req),
        key(req),
        { path: req.path, data: req.body },
        (b) => b.adjust(req.body),
      ),
    );
  });
  app.post("/api/stock/transfer", async (req: AuthRequest, res) => {
    authorize(actor(req), "movements");
    res.json(
      await transact(
        actor(req),
        key(req),
        { path: req.path, data: req.body },
        (b) => b.transfer(req.body),
      ),
    );
  });
  app.get("/api/stock", async (req: AuthRequest, res) => {
    const a = actor(req);
    authorize(a, "read");
    const data = await RecordModel.aggregate([
      { $match: { org: a.org, kind: "movements" } },
      {
        $group: {
          _id: { itemId: "$data.itemId", warehouseId: "$data.warehouseId" },
          quantityMilli: { $sum: "$data.quantityMilli" },
          value: { $sum: "$data.value" },
        },
      },
      { $set: { quantity: { $divide: ["$quantityMilli", 1000] } } },
    ]);
    if (
      ![
        "owner",
        "admin",
        "accountant",
        "inventory",
        "purchasing",
        "production",
      ].includes(a.role)
    )
      for (const row of data) delete row.value;
    res.json({ data });
  });
  app.get("/api/dashboard", async (req: AuthRequest, res) => {
    const a = actor(req);
    authorize(a, "read");
    const [summary, lowStock, recent] = await Promise.all([
      RecordModel.aggregate([
        {
          $match: {
            org: a.org,
            kind: {
              $in: ["invoices", "purchases", "expenses", "production", "sales"],
            },
          },
        },
        {
          $group: {
            _id: { kind: "$kind", status: "$data.status" },
            count: { $sum: 1 },
            total: { $sum: { $ifNull: ["$data.total", "$data.amount"] } },
            paid: { $sum: "$data.paid" },
            credited: { $sum: "$data.credited" },
            refunded: { $sum: "$data.refunded" },
          },
        },
      ]),
      RecordModel.aggregate([
        {
          $match: {
            org: a.org,
            kind: { $in: ["products", "materials"] },
            "data.status": "active",
          },
        },
        {
          $lookup: {
            from: RecordModel.collection.name,
            let: { item: "$id", org: "$org" },
            pipeline: [
              {
                $match: {
                  $expr: {
                    $and: [
                      { $eq: ["$org", "$$org"] },
                      { $eq: ["$kind", "movements"] },
                      { $eq: ["$data.itemId", "$$item"] },
                    ],
                  },
                },
              },
              {
                $group: {
                  _id: null,
                  quantityMilli: { $sum: "$data.quantityMilli" },
                },
              },
            ],
            as: "stock",
          },
        },
        {
          $set: {
            quantity: {
              $divide: [
                { $ifNull: [{ $first: "$stock.quantityMilli" }, 0] },
                1000,
              ],
            },
          },
        },
        { $match: { $expr: { $lte: ["$quantity", "$data.reorder"] } } },
        { $project: { id: 1, "data.name": 1, "data.sku": 1, quantity: 1 } },
        { $limit: 8 },
      ]),
      RecordModel.find({ org: a.org, kind: "audit" })
        .sort({ createdAt: -1 })
        .limit(6)
        .select("createdAt data.name")
        .lean(),
    ]);
    res.json({
      summary: canFinance(a)
        ? summary
        : summary.filter((x) => ["production", "sales"].includes(x._id.kind)),
      lowStock,
      recent,
    });
  });
  app.get("/api/reports/ledger", async (req: AuthRequest, res) => {
    const a = actor(req);
    if (!canFinance(a)) fail("Accounting permission required", 403);
    const q = z
      .object({
        partyId: z.string().uuid().optional(),
        account: z.string().max(100).optional(),
        from: z.string().date().optional(),
        to: z.string().date().optional(),
      })
      .parse(req.query);
    const match: Record<string, unknown> = {
      org: a.org,
      kind: "journals",
      "data.status": "posted",
    };
    if (q.to) match["data.date"] = { $lte: q.to };
    const rows = await RecordModel.aggregate([
      { $match: match },
      { $unwind: "$data.journalLines" },
      {
        $match: {
          ...(q.partyId ? { "data.journalLines.partyId": q.partyId } : {}),
          ...(q.account ? { "data.journalLines.account": q.account } : {}),
        },
      },
      {
        $project: {
          id: 1,
          date: "$data.date",
          description: "$data.description",
          sourceId: "$data.sourceId",
          account: "$data.journalLines.account",
          partyId: "$data.journalLines.partyId",
          debit: "$data.journalLines.debit",
          credit: "$data.journalLines.credit",
          createdAt: 1,
        },
      },
      { $sort: { date: 1, createdAt: 1, id: 1 } },
    ]);
    let balance = 0,
      opening = 0;
    const data = [];
    for (const r of rows) {
      balance += r.debit - r.credit;
      if (q.from && r.date < q.from) {
        opening = balance;
        continue;
      }
      data.push({ ...r, balance });
    }
    res.json({ data, opening, closing: balance });
  });
  app.get("/api/reports/trial-balance", async (req: AuthRequest, res) => {
    const a = actor(req);
    if (!canFinance(a)) fail("Accounting permission required", 403);
    const q = z
      .object({
        from: z.string().date().optional(),
        to: z.string().date().optional(),
      })
      .parse(req.query);
    res.json({
      data: await RecordModel.aggregate([
        {
          $match: {
            org: a.org,
            kind: "journals",
            "data.status": "posted",
            ...(q.from || q.to
              ? {
                  "data.date": {
                    ...(q.from ? { $gte: q.from } : {}),
                    ...(q.to ? { $lte: q.to } : {}),
                  },
                }
              : {}),
          },
        },
        { $unwind: "$data.journalLines" },
        {
          $group: {
            _id: "$data.journalLines.account",
            debit: { $sum: "$data.journalLines.debit" },
            credit: { $sum: "$data.journalLines.credit" },
          },
        },
        { $sort: { _id: 1 } },
      ]),
    });
  });
  app.use("/api", (_req, res) =>
    res.status(404).json({ message: "API endpoint not found" }),
  );
  app.use(
    (error: unknown, _req: Request, res: Response, _next: NextFunction) => {
      if (error instanceof ZodError) {
        res.status(400).json({
          message: error.errors
            .map((e) => `${e.path.join(".")}: ${e.message}`)
            .join("; "),
        });
        return;
      }
      if (error instanceof DomainError) {
        res.status(error.status).json({ message: error.message });
        return;
      }
      if (
        error instanceof mongoose.mongo.MongoServerError &&
        error.code === 11000
      ) {
        res
          .status(409)
          .json({ message: "A record with this unique value already exists" });
        return;
      }
      if (error instanceof SyntaxError) {
        res.status(400).json({ message: "Invalid JSON body" });
        return;
      }
      console.error(
        "Request failed",
        error instanceof Error ? error.name : "UnknownError",
      );
      res.status(500).json({
        message:
          "Unable to complete the operation. No partial business posting was saved.",
      });
    },
  );
  return app;
}
