import {
  returnKinds,
  createReturn,
  actReturn,
  validateRefund,
  finalizeRefund,
  reverseRefund,
} from "./returns.js";
import { builtInAccounts } from "./accounting.js";
import { createHash, randomUUID } from "node:crypto";
import mongoose, { type ClientSession } from "mongoose";
import { z } from "zod";
import { Idempotency, Org, RecordModel, Sequence } from "./models.js";
import {
  fail,
  type Actor,
  type Data,
  type Entry,
  type Kind,
  type JournalLine,
  type Line,
} from "./types.js";
import * as v from "./validation.js";
import {
  fiscalYear,
  integer,
  journalBalance,
  totals,
  roundedRatio,
  quantityMilli,
  quantityAdd,
  quantityValue,
  supplierBillLine,
  changeBilledTotals,
} from "./calculations.js";

export const kinds: Kind[] = [
  ...returnKinds,
  "accounts",
  "products",
  "materials",
  "parties",
  "warehouses",
  "categories",
  "staff",
  "purchases",
  "sales",
  "production",
  "cutting",
  "jobwork",
  "invoices",
  "supplierInvoices",
  "challans",
  "expenses",
  "payments",
  "movements",
  "journals",
  "tickets",
  "notifications",
  "audit",
];
export const roles: Record<string, string[]> = {
  owner: ["*"],
  admin: ["*"],
  accountant: [
    ...returnKinds,
    "accounts",
    "read",
    "invoices",
    "supplierInvoices",
    "expenses",
    "payments",
    "journals",
  ],
  sales: ["customerReturns", "read", "sales", "challans", "parties"],
  purchasing: [
    "supplierReturns",
    "read",
    "purchases",
    "supplierInvoices",
    "parties",
    "materials",
  ],
  production: ["read", "production", "cutting", "jobwork"],
  inventory: ["read", "products", "materials", "movements", "warehouses"],
  staff: ["read", "tickets"],
};
export function authorize(actor: Actor, permission: string) {
  if (!(roles[actor.role] ?? []).some((p) => p === "*" || p === permission))
    fail("Permission denied", 403);
}
const readModules: Record<string, Kind[]> = {
  sales: [
    "customerReturns",
    "products",
    "parties",
    "sales",
    "invoices",
    "challans",
    "warehouses",
    "tickets",
    "notifications",
  ],
  purchasing: [
    "supplierReturns",
    "products",
    "materials",
    "parties",
    "purchases",
    "supplierInvoices",
    "warehouses",
    "movements",
    "tickets",
    "notifications",
  ],
  production: [
    "products",
    "materials",
    "parties",
    "production",
    "cutting",
    "jobwork",
    "movements",
    "warehouses",
    "tickets",
    "notifications",
  ],
  inventory: [
    "products",
    "materials",
    "parties",
    "warehouses",
    "movements",
    "categories",
    "tickets",
    "notifications",
  ],
  staff: ["products", "parties", "tickets", "notifications"],
};
export function readable(actor: Actor, kind: Kind) {
  if (["owner", "admin"].includes(actor.role)) return true;
  if (actor.role === "accountant") return kind !== "staff";
  return (readModules[actor.role] ?? []).includes(kind);
}
const masters: Kind[] = [
  "accounts",
  "products",
  "materials",
  "parties",
  "warehouses",
  "categories",
  "staff",
];
export class Business {
  constructor(
    readonly actor: Actor,
    readonly session: ClientSession,
  ) {}
  async assertOpen(date: string) {
    const org = await Org.findOne({ id: this.actor.org })
      .session(this.session)
      .lean();
    const closed = org?.settings.closedThrough;
    if (closed && date <= closed)
      fail(`The accounting period is closed through ${closed}`, 409);
    return date;
  }
  async all(kind: Kind) {
    return RecordModel.find({ org: this.actor.org, kind })
      .session(this.session)
      .lean() as Promise<Entry[]>;
  }
  async get(kind: Kind, id: string) {
    const record = await RecordModel.findOne({ org: this.actor.org, kind, id })
      .session(this.session)
      .lean();
    return record ?? fail("Record not found", 404);
  }
  async add(kind: Kind, data: Data) {
    const now = new Date().toISOString();
    const entry: Entry = {
      id: randomUUID(),
      org: this.actor.org,
      kind,
      data,
      version: 1,
      createdAt: now,
      updatedAt: now,
    };
    await RecordModel.create([entry], { session: this.session });
    return entry;
  }
  async save(entry: Entry) {
    entry.version++;
    entry.updatedAt = new Date().toISOString();
    await RecordModel.updateOne(
      { org: this.actor.org, kind: entry.kind, id: entry.id },
      {
        $set: {
          data: entry.data,
          version: entry.version,
          updatedAt: entry.updatedAt,
        },
      },
      { session: this.session },
    );
    return entry;
  }
  async number(prefix: string, date: string) {
    const org = await Org.findOne({ id: this.actor.org })
      .session(this.session)
      .lean();
    if (!org) fail("Organization not found", 404);
    const year = fiscalYear(date, org!.settings.financialYearStart);
    const seq = await Sequence.findOneAndUpdate(
      { org: this.actor.org, scope: `${prefix}/${year}` },
      { $inc: { value: 1 } },
      { upsert: true, new: true, session: this.session },
    );
    return `${prefix}/${year}/${String(seq!.value).padStart(5, "0")}`;
  }
  async item(id: string) {
    const result = await RecordModel.findOne({
      org: this.actor.org,
      id,
      kind: { $in: ["products", "materials"] },
    })
      .session(this.session)
      .lean();
    if (!result || result.data.status === "archived")
      fail("Active inventory item not found", 404);
    return result!;
  }
  async party(id: string, kind?: string) {
    const p = await this.get("parties", id);
    if (p.data.status === "archived") fail("Party is archived");
    if (kind && ![kind, "both"].includes(p.data.kind ?? ""))
      fail(`A ${kind} is required`);
    return p;
  }
  async balance(itemId: string, warehouseId = "default") {
    const result = await RecordModel.aggregate<{ quantity: number }>([
      {
        $match: {
          org: this.actor.org,
          kind: "movements",
          "data.itemId": itemId,
          "data.warehouseId": warehouseId,
        },
      },
      { $group: { _id: null, quantity: { $sum: "$data.quantityMilli" } } },
    ]).session(this.session);
    return (result[0]?.quantity ?? 0) / 1000;
  }
  async issueValue(itemId: string, quantity: number, warehouseId = "default") {
    const values = await RecordModel.aggregate<{
      quantity: number;
      value: number;
    }>([
      {
        $match: {
          org: this.actor.org,
          kind: "movements",
          "data.itemId": itemId,
          "data.warehouseId": warehouseId,
        },
      },
      {
        $group: {
          _id: null,
          quantity: { $sum: "$data.quantityMilli" },
          value: { $sum: "$data.value" },
        },
      },
    ]).session(this.session);
    const stock = values[0];
    if (!stock || stock.quantity < quantityMilli(quantity))
      fail("Insufficient stock", 409);
    if (stock.value < 0)
      fail("Inventory valuation requires reconciliation", 409);
    return roundedRatio(stock.value, quantityMilli(quantity), stock.quantity);
  }
  async movement(
    itemId: string,
    quantity: number,
    source: Entry,
    reason: string,
    warehouseId = "default",
    value = 0,
  ) {
    await this.assertOpen(source.data.postingDate ?? source.data.date!);
    const item = await this.item(itemId);
    if (item.data.unit === "piece" && !Number.isInteger(quantity))
      fail("Piece quantities must be whole numbers");
    quantityMilli(quantity);
    if (!quantity) fail("Movement quantity cannot be zero");
    if (warehouseId !== "default") await this.get("warehouses", warehouseId);
    const balance = await this.balance(itemId, warehouseId);
    if (quantityAdd(balance, quantity) < 0) fail("Insufficient stock", 409);
    return this.add("movements", {
      itemId,
      quantity,
      quantityMilli: quantityMilli(quantity),
      warehouseId,
      sourceId: source.id,
      sourceKind: source.kind,
      reason,
      value,
      actor: this.actor.id,
      date:
        source.data.postingDate ??
        source.data.date ??
        new Date().toISOString().slice(0, 10),
    });
  }
  async journal(source: Entry, lines: JournalLine[], description: string) {
    await this.assertOpen(source.data.postingDate ?? source.data.date!);
    journalBalance(lines);
    return this.add("journals", {
      sourceId: source.id,
      sourceKind: source.kind,
      date: source.data.postingDate ?? source.data.date,
      description,
      journalLines: lines,
      status: "posted",
      actor: this.actor.id,
    });
  }
  async validateLines(lines: Line[]) {
    const ids = new Set<string>();
    for (const l of lines) {
      if (ids.has(l.itemId)) fail("Combine duplicate item rows");
      ids.add(l.itemId);
      const item = await this.item(l.itemId);
      if (item.data.unit === "piece" && !Number.isInteger(l.quantity))
        fail("Piece quantities must be whole numbers");
    }
    return totals(lines);
  }
  async snapshot(data: Data) {
    const org = await Org.findOne({ id: this.actor.org })
      .session(this.session)
      .lean();
    data.businessSnapshot = {
      name: org!.settings.name,
      address: org!.settings.address,
      gstin: org!.settings.gstin,
    };
    if (data.partyId) {
      const party = await this.get("parties", data.partyId);
      data.partySnapshot = {
        name: party.data.name!,
        address: party.data.address ?? "",
        gstin: party.data.gstin ?? "",
      };
    }
    for (const l of data.lines ?? []) {
      const item = await this.item(l.itemId);
      l.name = item.data.name;
      l.sku = item.data.sku;
      l.hsn = item.data.hsn;
      l.unit = item.data.unit;
    }
    return data;
  }
  async create(kind: Kind, input: unknown) {
    authorize(this.actor, kind);
    if (returnKinds.includes(kind)) return createReturn(this, kind, input);
    let data: Data;
    if (kind === "accounts")
      data = z
        .object({
          name: z.string().trim().min(1).max(100),
          accountType: z.enum([
            "asset",
            "liability",
            "equity",
            "revenue",
            "expense",
          ]),
          description: z.string().max(1000).default(""),
          status: z.enum(["active", "archived"]).default("active"),
        })
        .strict()
        .parse(input);
    else if (kind === "products" || kind === "materials")
      data = v.itemSchema.parse(input);
    else if (kind === "parties") data = v.partySchema.parse(input);
    else if (kind === "warehouses" || kind === "categories")
      data = v.masterSchema.parse(input);
    else if (kind === "staff")
      data = z
        .object({
          name: z.string().min(1).max(120),
          email: z.string().email(),
          phone: z.string().max(30),
          role: z.string().max(80),
          active: z.boolean().default(true),
        })
        .strict()
        .parse(input);
    else if (kind === "sales" || kind === "purchases") {
      data = v.orderSchema.parse(input);
      await this.party(
        data.partyId!,
        kind === "sales" ? "customer" : "supplier",
      );
      data = {
        ...data,
        ...(await this.validateLines(data.lines!)),
        status: "draft",
        number: await this.number(kind === "sales" ? "SO" : "PO", data.date!),
      };
    } else if (kind === "production") {
      data = v.productionSchema.parse(input);
      const output = await this.item(data.outputItemId!);
      if (output.kind !== "products")
        fail("Production output must be a product");
      for (const l of data.materialLines!) await this.item(l.itemId);
      const org = await Org.findOne({ id: this.actor.org })
        .session(this.session)
        .lean();
      data = {
        ...data,
        status: "draft",
        stage: 0,
        stages: org!.settings.stages,
        number: await this.number("JOB", data.date!),
      };
    } else if (kind === "cutting") {
      data = v.cuttingSchema.parse(input);
      const job = await this.get("production", data.sourceId!);
      if (job.data.completed) fail("Production already completed");
      const item = await this.item(data.itemId!);
      if (item.kind !== "materials") fail("Cutting requires a material lot");
      if (data.sizes!.some((s) => s.rejected > s.actual))
        fail("Rejected quantity exceeds actual");
      data.status = "draft";
    } else if (kind === "expenses") {
      data = v.expenseSchema.parse(input);
      if (data.partyId) await this.party(data.partyId);
      if (data.sourceId) await this.get("production", data.sourceId);
      data.status = "draft";
    } else if (kind === "invoices") {
      const parsed = z
        .object({
          sourceId: v.id,
          date: z.string().date(),
          dueDate: z.string().date().optional(),
        })
        .strict()
        .parse(input);
      const source = await this.get("sales", parsed.sourceId);
      if (source.data.status !== "confirmed") fail("Confirm sales order first");
      data = {
        ...parsed,
        partyId: source.data.partyId,
        lines: source.data.lines!.map((l) => ({ ...l })),
        ...totals(source.data.lines!),
        status: "draft",
        paid: 0,
      };
    } else if (kind === "supplierInvoices") {
      const p = z
        .object({
          sourceId: v.id,
          date: z.string().date(),
          dueDate: z.string().date().optional(),
          reference: z.string().trim().min(1).max(100),
        })
        .strict()
        .parse(input);
      const source = await this.get("purchases", p.sourceId);
      if (source.data.status !== "confirmed")
        fail("Confirm and receive the purchase first");
      const billLines: Line[] = source.data
        .lines!.filter((l) => (l.received ?? 0) > (l.invoiced ?? 0))
        .map((l) =>
          supplierBillLine(l, quantityAdd(l.received ?? 0, -(l.invoiced ?? 0))),
        );
      if (!billLines.length) fail("No received, unbilled quantities remain");
      data = {
        ...p,
        sourceVersion: source.version,
        partyId: source.data.partyId,
        lines: billLines,
        ...totals(billLines),
        status: "draft",
        paid: 0,
      };
    } else if (kind === "jobwork") {
      const p = z
        .object({
          name: z.string().trim().min(1).max(120),
          sourceId: v.id,
          partyId: v.id,
          quantity: v.qty,
          rate: v.money,
          date: z.string().date(),
          notes: z.string().max(1000).default(""),
        })
        .strict()
        .parse(input);
      const job = await this.get("production", p.sourceId);
      if (job.data.completed) fail("Production job already completed");
      await this.party(p.partyId);
      data = {
        ...p,
        status: "draft",
        returned: 0,
        accepted: 0,
        rejected: 0,
        total: quantityValue(p.quantity, p.rate),
        number: await this.number("JW", p.date),
      };
    } else if (kind === "journals") {
      const p = z
        .object({
          description: z.string().trim().min(3).max(500),
          date: z.string().date(),
          journalLines: z
            .array(
              z
                .object({
                  account: z.string().trim().min(1).max(100),
                  debit: v.money,
                  credit: v.money,
                  partyId: v.id.optional(),
                })
                .strict(),
            )
            .min(2)
            .max(100),
        })
        .strict()
        .parse(input);
      journalBalance(p.journalLines);
      for (const l of p.journalLines)
        if (l.partyId) await this.party(l.partyId);
      data = { ...p, status: "draft" };
    } else if (kind === "payments") {
      data = v.paymentSchema.parse(input);
      await validateRefund(this, data);
      await this.party(data.partyId!);
      if (data.method === "cheque")
        fail(
          "Record cleared cheques as bank payments with cheque reference; pending cheque handling is not configured",
        );
      data.status = "draft";
    } else if (kind === "tickets") {
      data = z
        .object({
          subject: z.string().min(1).max(160),
          message: z.string().min(1).max(5000),
          priority: z.enum(["normal", "high"]).default("normal"),
        })
        .strict()
        .parse(input);
      data.status = "open";
    } else fail("This record is created through its source workflow");
    if (
      kind === "accounts" &&
      builtInAccounts[data!.name!] &&
      builtInAccounts[data!.name!] !== data!.accountType
    )
      fail("The classification of a built-in posting account is fixed");
    return this.add(kind, data!);
  }
  async update(kind: Kind, id: string, input: unknown) {
    authorize(this.actor, kind);
    const e = await this.get(kind, id);
    const p = z
      .object({ version: z.number().int().positive(), data: z.unknown() })
      .strict()
      .parse(input);
    if (p.version !== e.version)
      fail("Record changed. Refresh and retry.", 409);
    if (!masters.includes(kind))
      fail("Posted/workflow records cannot be edited through master data");
    const schema =
      kind === "products" || kind === "materials"
        ? v.itemSchema
        : kind === "parties"
          ? v.partySchema
          : kind === "staff"
            ? z
                .object({
                  name: z.string().min(1),
                  email: z.string().email(),
                  phone: z.string(),
                  role: z.string(),
                  active: z.boolean(),
                })
                .strict()
            : v.masterSchema;
    if (kind === "accounts") {
      const data = z
        .object({
          name: z.string().trim().min(1).max(100),
          accountType: z.enum([
            "asset",
            "liability",
            "equity",
            "revenue",
            "expense",
          ]),
          description: z.string().max(1000),
          status: z.enum(["active", "archived"]),
        })
        .strict()
        .parse(p.data);
      if (data.name !== e.data.name)
        fail("Account names are immutable; create a new account instead");
      const used = await RecordModel.findOne({
        org: this.actor.org,
        kind: "journals",
        "data.status": "posted",
        "data.journalLines.account": e.data.name,
      }).session(this.session);
      if (used && data.accountType !== e.data.accountType)
        fail(
          "Used account classifications cannot be changed; post an approved reclassification",
        );
      e.data = data;
    } else e.data = schema.parse(p.data);
    return this.save(e);
  }
  async adjust(input: unknown) {
    authorize(this.actor, "movements");
    const d = z
      .object({
        itemId: v.id,
        quantity: z
          .number()
          .min(-1_000_000_000)
          .max(1_000_000_000)
          .multipleOf(0.001)
          .refine((q) => q !== 0),
        warehouseId: z.string().default("default"),
        reason: z.string().min(3).max(500),
        date: z.string().date(),
      })
      .strict()
      .parse(input);
    const source = await this.add("notifications", {
      name: "Stock adjustment",
      ...d,
      actor: this.actor.id,
    });
    const item = await this.item(d.itemId);
    const value =
      d.quantity > 0
        ? quantityValue(d.quantity, item.data.cost ?? 0)
        : -(await this.issueValue(d.itemId, -d.quantity, d.warehouseId));
    const movement = await this.movement(
      d.itemId,
      d.quantity,
      source,
      d.reason,
      d.warehouseId,
      value,
    );
    if (value)
      await this.journal(
        source,
        value > 0
          ? [
              { account: "Inventory", debit: value, credit: 0 },
              { account: "Inventory adjustments", debit: 0, credit: value },
            ]
          : [
              { account: "Inventory adjustments", debit: -value, credit: 0 },
              { account: "Inventory", debit: 0, credit: -value },
            ],
        "Stock adjustment at configured standard cost",
      );
    return movement;
  }
  async transfer(input: unknown) {
    authorize(this.actor, "movements");
    const p = z
      .object({
        itemId: v.id,
        quantity: v.qty,
        sourceWarehouseId: z.string().min(1),
        destinationWarehouseId: z.string().min(1),
        reason: z.string().trim().min(3).max(500),
        date: z.string().date(),
      })
      .strict()
      .parse(input);
    if (p.sourceWarehouseId === p.destinationWarehouseId)
      fail("Choose two different locations");
    const source = await this.add("notifications", {
      name: "Warehouse transfer",
      ...p,
      actor: this.actor.id,
    });
    const value = await this.issueValue(
      p.itemId,
      p.quantity,
      p.sourceWarehouseId,
    );
    await this.movement(
      p.itemId,
      -p.quantity,
      source,
      "Transfer out: " + p.reason,
      p.sourceWarehouseId,
      -value,
    );
    await this.movement(
      p.itemId,
      p.quantity,
      source,
      "Transfer in: " + p.reason,
      p.destinationWarehouseId,
      value,
    );
    return source;
  }
  async act(kind: Kind, id: string, input: unknown) {
    authorize(this.actor, kind);
    const a = v.actionSchema.parse(input);
    const e = await this.get(kind, id);
    const d = e.data;
    if (
      [
        "receive",
        "dispatch",
        "finalize",
        "reverse",
        "issue",
        "complete",
        "return",
      ].includes(a.action)
    ) {
      d.postingDate = await this.assertOpen(a.postingDate ?? d.date!);
      if (kind === "journals" && a.action === "finalize")
        d.date = d.postingDate;
    }
    if (returnKinds.includes(kind)) return actReturn(this, e, input);
    if ((kind === "sales" || kind === "purchases") && a.action === "confirm") {
      if (d.status !== "draft") fail("Only draft orders may be confirmed");
      d.status = "confirmed";
    } else if (kind === "purchases" && a.action === "receive") {
      if (d.status !== "confirmed") fail("Confirm purchase order first");
      const quantities = a.quantities ?? [];
      if (!quantities.length) fail("Enter received quantities");
      const seen = new Set<string>();
      const receiptLines: Line[] = [];
      for (const q of quantities) {
        if (seen.has(q.itemId)) fail("Duplicate receipt line");
        seen.add(q.itemId);
        const l = d.lines!.find((l) => l.itemId === q.itemId);
        if (!l || q.quantity > quantityAdd(l.quantity, -(l.received ?? 0)))
          fail("Receipt exceeds pending quantity");
        const old = l.received ?? 0;
        l.received = quantityAdd(old, q.quantity);
        const discount =
          roundedRatio(
            l.discount,
            quantityMilli(l.received),
            quantityMilli(l.quantity),
          ) -
          roundedRatio(
            l.discount,
            quantityMilli(old),
            quantityMilli(l.quantity),
          );
        const full = totals([l]);
        const fullNet = full.subtotal - full.discount;
        const net =
          roundedRatio(
            fullNet,
            quantityMilli(l.received),
            quantityMilli(l.quantity),
          ) -
          roundedRatio(fullNet, quantityMilli(old), quantityMilli(l.quantity));
        await this.movement(
          l.itemId,
          q.quantity,
          e,
          "purchase receipt",
          d.warehouseId,
          net,
        );
        receiptLines.push({
          ...l,
          quantity: q.quantity,
          discount,
          gross: integer(net + discount),
          taxAmount: 0,
          taxMode: "none",
        });
      }
      const receipt = await this.add("notifications", {
        name: "Goods receipt",
        postingDate: d.postingDate,
        sourceId: e.id,
        date: d.date,
        lines: receiptLines,
      });
      const amount = totals(receiptLines).total;
      if (amount)
        await this.journal(
          receipt,
          [
            { account: "Inventory", debit: amount, credit: 0 },
            {
              account: "Goods received not invoiced",
              debit: 0,
              credit: amount,
              partyId: d.partyId,
            },
          ],
          "Purchase receipt at net order cost",
        );
    } else if (kind === "sales" && a.action === "dispatch") {
      authorize(this.actor, "challans");
      if (d.status !== "confirmed") fail("Confirm sales order first");
      const quantities = a.quantities ?? [];
      if (!quantities.length) fail("Enter dispatch quantities");
      const seen = new Set<string>();
      const dispatchLines: Line[] = [];
      for (const q of quantities) {
        if (seen.has(q.itemId)) fail("Duplicate dispatch line");
        seen.add(q.itemId);
        const l = d.lines!.find((l) => l.itemId === q.itemId);
        if (!l || q.quantity > quantityAdd(l.quantity, -(l.dispatched ?? 0)))
          fail("Dispatch exceeds pending quantity");
        l.dispatched = quantityAdd(l.dispatched ?? 0, q.quantity);
        const cost = await this.issueValue(l.itemId, q.quantity, d.warehouseId);
        await this.movement(
          l.itemId,
          -q.quantity,
          e,
          "sales dispatch",
          d.warehouseId,
          -cost,
        );
        dispatchLines.push({
          ...l,
          quantity: q.quantity,
          discount: 0,
          costValue: cost,
        });
        if (cost)
          await this.journal(
            e,
            [
              { account: "Cost of goods sold", debit: cost, credit: 0 },
              { account: "Inventory", debit: 0, credit: cost },
            ],
            "Dispatch at moving-average stock cost",
          );
      }
      await this.add(
        "challans",
        await this.snapshot({
          sourceId: e.id,
          warehouseId: d.warehouseId,
          partyId: d.partyId,
          date: d.date,
          number: await this.number("DC", d.date!),
          lines: dispatchLines,
          status: "dispatched",
          vehicle: a.vehicle ?? "",
          eway: a.eway ?? "",
          transport: a.transport ?? "",
          ...totals(dispatchLines),
        }),
      );
    } else if (kind === "invoices" && a.action === "finalize") {
      if (d.status !== "draft") fail("Invoice is already finalized");
      const source = await this.get("sales", d.sourceId!);
      for (const l of d.lines!) {
        const orderLine = source.data.lines!.find(
          (row) => row.itemId === l.itemId,
        );
        if (
          !orderLine ||
          l.quantity >
            quantityAdd(orderLine.quantity, -(orderLine.invoiced ?? 0))
        )
          fail("Invoice exceeds uninvoiced order quantity");
        orderLine.invoiced = quantityAdd(orderLine.invoiced ?? 0, l.quantity);
      }
      await this.save(source);
      await this.snapshot(d);
      d.number = await this.number("INV", d.date!);
      d.status = "posted";
      const t = totals(d.lines!);
      Object.assign(d, t);
      const journal: JournalLine[] = [
        {
          account: "Accounts receivable",
          debit: t.total,
          credit: 0,
          partyId: d.partyId,
        },
        { account: "Sales", debit: 0, credit: t.subtotal - t.discount },
      ];
      for (const l of d.lines!) {
        const lt = totals([l]).tax;
        if (!lt) continue;
        if (l.taxMode === "split") {
          const cgst = Math.floor(lt / 2);
          journal.push(
            { account: "CGST payable", debit: 0, credit: cgst },
            { account: "SGST payable", debit: 0, credit: lt - cgst },
          );
        } else journal.push({ account: "IGST payable", debit: 0, credit: lt });
      }
      await this.journal(e, journal, "Sales invoice");
    } else if (kind === "supplierInvoices" && a.action === "finalize") {
      if (d.status !== "draft") fail("Supplier invoice already finalized");
      const source = await this.get("purchases", d.sourceId!);
      if (d.sourceVersion !== undefined && source.version !== d.sourceVersion)
        fail(
          "Purchase changed after this bill was drafted. Void and recreate the draft for review.",
          409,
        );
      const duplicate = await RecordModel.findOne({
        org: this.actor.org,
        kind: "supplierInvoices",
        "data.partyId": d.partyId,
        "data.reference": d.reference,
        "data.status": "posted",
      }).session(this.session);
      if (duplicate) fail("Supplier invoice reference already posted", 409);
      for (const l of d.lines!) {
        const orderLine = source.data.lines!.find((x) => x.itemId === l.itemId);
        if (
          !orderLine ||
          l.quantity >
            quantityAdd(orderLine.received ?? 0, -(orderLine.invoiced ?? 0))
        )
          fail("Supplier invoice exceeds received, unbilled quantity");
        changeBilledTotals(orderLine, l, 1);
        orderLine.invoiced = quantityAdd(orderLine.invoiced ?? 0, l.quantity);
      }
      await this.save(source);
      const t = totals(d.lines!);
      Object.assign(d, t);
      await this.snapshot(d);
      d.status = "posted";
      d.number = await this.number("BILL", d.date!);
      const jl: JournalLine[] = [
        {
          account: "Goods received not invoiced",
          debit: t.subtotal - t.discount,
          credit: 0,
          partyId: d.partyId,
        },
        {
          account: "Accounts payable",
          debit: 0,
          credit: t.total,
          partyId: d.partyId,
        },
      ];
      if (t.tax)
        jl.push({
          account: "Input tax pending validation",
          debit: t.tax,
          credit: 0,
        });
      if (t.total)
        await this.journal(e, jl, "Supplier invoice matched to goods received");
    } else if (kind === "journals" && a.action === "finalize") {
      if (d.status !== "draft") fail("Journal already posted");
      journalBalance(d.journalLines!);
      d.status = "posted";
      d.number = await this.number("JE", d.date!);
    } else if (kind === "jobwork" && a.action === "issue") {
      if (d.status !== "draft") fail("Job work already assigned");
      const job = await this.get("production", d.sourceId!);
      if (job.data.status !== "in_progress")
        fail("Issue production materials first");
      const assigned = (await this.all("jobwork"))
        .filter(
          (j) =>
            j.id !== e.id &&
            j.data.sourceId === d.sourceId &&
            j.data.status !== "draft" &&
            j.data.status !== "void",
        )
        .reduce((s, j) => s + j.data.quantity!, 0);
      if (assigned + d.quantity! > job.data.quantity!)
        fail("Assignments exceed production quantity");
      d.status = "in_progress";
    } else if (kind === "jobwork" && a.action === "receive") {
      if (d.status !== "in_progress") fail("Assign job work first");
      const accepted = a.finished ?? 0,
        rejected = a.rejected ?? 0;
      const returned = accepted + rejected;
      if (!returned || returned > d.quantity! - (d.returned ?? 0))
        fail("Return exceeds pending job-work quantity");
      const job = await this.get("production", d.sourceId!);
      if (job.data.completed) fail("Production is already completed");
      d.returned = (d.returned ?? 0) + returned;
      d.accepted = (d.accepted ?? 0) + accepted;
      d.rejected = (d.rejected ?? 0) + rejected;
      const amount = quantityValue(accepted, d.rate!);
      if (amount) {
        await this.journal(
          e,
          [
            { account: "Work in progress", debit: amount, credit: 0 },
            {
              account: "Accounts payable",
              debit: 0,
              credit: amount,
              partyId: d.partyId,
            },
          ],
          "Accepted contractor job work",
        );
        d.amount = (d.amount ?? 0) + amount;
      }
      if (d.returned === d.quantity) d.status = "completed";
    } else if (kind === "production" && a.action === "issue") {
      if (d.issued || d.status !== "draft") fail("Materials already issued");
      let cost = 0;
      for (const l of d.materialLines!) {
        const value = await this.issueValue(l.itemId, l.quantity);
        cost = integer(cost + value);
        await this.movement(
          l.itemId,
          -l.quantity,
          e,
          "production issue",
          "default",
          -value,
        );
      }
      d.actualCost = cost;
      d.issued = true;
      d.status = "in_progress";
      if (cost)
        await this.journal(
          e,
          [
            { account: "Work in progress", debit: cost, credit: 0 },
            { account: "Inventory", debit: 0, credit: cost },
          ],
          "Production material issue",
        );
    } else if (kind === "production" && a.action === "advance") {
      if (d.status !== "in_progress") fail("Issue materials first");
      if ((d.stage ?? 0) >= d.stages!.length - 1)
        fail("Last stage reached; complete with accepted quantities");
      d.stage = (d.stage ?? 0) + 1;
    } else if (kind === "production" && a.action === "return") {
      if (d.status !== "in_progress")
        fail("Materials may be returned only from open production");
      const quantities = a.quantities ?? [];
      if (!quantities.length) fail("Enter quantities to return");
      const seen = new Set<string>();
      let totalValue = 0;
      for (const q of quantities) {
        if (seen.has(q.itemId)) fail("Combine duplicate return rows");
        seen.add(q.itemId);
        const movements = (await this.all("movements")).filter(
          (m) => m.data.sourceId === e.id && m.data.itemId === q.itemId,
        );
        const issued = movements.filter(
          (m) => m.data.reason === "production issue",
        );
        const returned = movements.filter(
          (m) => m.data.reason === "production return",
        );
        const issuedQty = issued.reduce(
          (s, m) => s - (m.data.quantityMilli ?? 0),
          0,
        );
        const returnedQty = returned.reduce(
          (s, m) => s + (m.data.quantityMilli ?? 0),
          0,
        );
        const consumed = (await this.all("cutting"))
          .filter(
            (c) =>
              c.data.sourceId === e.id &&
              c.data.itemId === q.itemId &&
              c.data.status === "confirmed",
          )
          .reduce((s, c) => s + quantityMilli(c.data.quantity!), 0);
        if (quantityMilli(q.quantity) > issuedQty - returnedQty - consumed)
          fail("Return exceeds unconsumed issued material");
        const originalValue = issued.reduce(
          (s, m) => s - (m.data.value ?? 0),
          0,
        );
        const value =
          roundedRatio(
            originalValue,
            returnedQty + quantityMilli(q.quantity),
            issuedQty,
          ) - roundedRatio(originalValue, returnedQty, issuedQty);
        totalValue = integer(totalValue + value);
        await this.movement(
          q.itemId,
          q.quantity,
          e,
          "production return",
          "default",
          value,
        );
      }
      d.actualCost = integer((d.actualCost ?? 0) - totalValue);
      if (totalValue)
        await this.journal(
          e,
          [
            { account: "Inventory", debit: totalValue, credit: 0 },
            { account: "Work in progress", debit: 0, credit: totalValue },
          ],
          "Unused production material return",
        );
    } else if (kind === "production" && a.action === "complete") {
      if (d.status !== "in_progress" || d.completed)
        fail("Production is not open");
      if (
        (await this.all("jobwork")).some(
          (j) => j.data.sourceId === e.id && j.data.status === "in_progress",
        )
      )
        fail("Receive outstanding job work before completing production");
      const accepted = a.finished ?? 0,
        rejected = a.rejected ?? 0;
      if (accepted + rejected !== d.quantity)
        fail("Accepted plus rejected must equal planned quantity");
      if (accepted === 0)
        fail("Zero accepted output requires an approved write-off workflow");
      const contractorCost = (await this.all("jobwork"))
        .filter((j) => j.data.sourceId === e.id)
        .reduce((sum, j) => integer(sum + (j.data.amount ?? 0)), 0);
      const extra = (d.costLines ?? []).reduce(
        (s, l) => integer(s + l.amount),
        0,
      );
      const expenses = (await this.all("expenses"))
        .filter((x) => x.data.sourceId === e.id && x.data.status === "posted")
        .reduce((s, x) => integer(s + x.data.amount!), 0);
      d.finished = accepted;
      d.rejected = rejected;
      d.completed = true;
      d.status = "completed";
      d.stage = d.stages!.length - 1;
      d.actualCost = integer(
        (d.actualCost ?? 0) + extra + expenses + contractorCost,
      );
      await this.movement(
        d.outputItemId!,
        accepted,
        e,
        "finished goods receipt",
        "default",
        d.actualCost,
      );
      if (d.actualCost)
        await this.journal(
          e,
          [
            { account: "Inventory", debit: d.actualCost, credit: 0 },
            { account: "Work in progress", debit: 0, credit: d.actualCost },
          ],
          "Finished goods receipt",
        );
      if (extra)
        await this.journal(
          e,
          [
            { account: "Work in progress", debit: extra, credit: 0 },
            { account: "Accrued production costs", debit: 0, credit: extra },
          ],
          "Confirmed job cost lines",
        );
    } else if (kind === "cutting" && a.action === "confirm") {
      if (d.status !== "draft") fail("Cutting plan already confirmed");
      const job = await this.get("production", d.sourceId!);
      if (!job.data.issued) fail("Issue job materials first");
      const material = job.data
        .materialLines!.filter((l) => l.itemId === d.itemId)
        .reduce((s, l) => s + l.quantity, 0);
      const returned = (await this.all("movements"))
        .filter(
          (m) =>
            m.data.sourceId === job.id &&
            m.data.itemId === d.itemId &&
            m.data.reason === "production return",
        )
        .reduce((sum, m) => quantityAdd(sum, m.data.quantity ?? 0), 0);
      const prior = (await this.all("cutting"))
        .filter(
          (c) =>
            c.id !== e.id &&
            c.data.sourceId === d.sourceId &&
            c.data.itemId === d.itemId &&
            c.data.status === "confirmed",
        )
        .reduce((s, c) => quantityAdd(s, c.data.quantity!), 0);
      if (quantityAdd(d.quantity!, prior) > quantityAdd(material, -returned))
        fail("Cutting consumption exceeds material issued to job");
      d.status = "confirmed";
    } else if (kind === "expenses" && a.action === "finalize") {
      if (d.status !== "draft") fail("Expense already posted");
      if (d.sourceId) {
        const job = await this.get("production", d.sourceId);
        if (job.data.completed)
          fail("Cannot add costs to completed production");
      }
      d.status = "posted";
      await this.journal(
        e,
        [
          {
            account: d.sourceId ? "Work in progress" : `Expense: ${d.category}`,
            debit: d.amount!,
            credit: 0,
            partyId: d.partyId,
          },
          {
            account: d.method === "cash" ? "Cash" : "Bank",
            debit: 0,
            credit: d.amount!,
          },
        ],
        "Paid expense",
      );
    } else if (kind === "payments" && a.action === "finalize") {
      if (d.status !== "draft") fail("Payment already posted");
      if (d.flow?.endsWith("_refund")) return finalizeRefund(this, e);
      let sum = 0;
      const seen = new Set<string>();
      for (const allocation of d.allocations!) {
        if (seen.has(allocation.invoiceId)) fail("Duplicate allocation");
        seen.add(allocation.invoiceId);
        const invoice = await this.get(
          d.flow === "receipt" ? "invoices" : "supplierInvoices",
          allocation.invoiceId,
        );
        if (
          invoice.data.partyId !== d.partyId ||
          invoice.data.status !== "posted"
        )
          fail("Allocation invoice/party mismatch");
        if (
          allocation.amount >
          invoice.data.total! -
            (invoice.data.credited ?? 0) -
            (invoice.data.paid ?? 0) +
            (invoice.data.refunded ?? 0)
        )
          fail("Payment allocation exceeds outstanding invoice");
        sum = integer(sum + allocation.amount);
        invoice.data.paid = (invoice.data.paid ?? 0) + allocation.amount;
        await this.save(invoice);
      }
      if (sum > d.amount!) fail("Allocations exceed payment");
      d.status = "posted";
      const cash = d.method === "cash" ? "Cash" : "Bank";
      await this.journal(
        e,
        d.flow === "receipt"
          ? [
              { account: cash, debit: d.amount!, credit: 0 },
              {
                account: "Accounts receivable",
                debit: 0,
                credit: d.amount!,
                partyId: d.partyId,
              },
            ]
          : [
              {
                account: "Accounts payable",
                debit: d.amount!,
                credit: 0,
                partyId: d.partyId,
              },
              { account: cash, debit: 0, credit: d.amount! },
            ],
        "Party payment",
      );
    } else if (
      ["invoices", "supplierInvoices", "payments", "expenses"].includes(kind) &&
      a.action === "reverse"
    ) {
      if (d.status !== "posted") fail("Only posted records can be reversed");
      if (
        ["invoices", "supplierInvoices"].includes(kind) &&
        (d.credited ?? 0) > 0
      )
        fail("Reverse linked credit/debit notes first");
      if (
        kind === "supplierInvoices" &&
        (await this.all("supplierReturns")).some(
          (r) => r.data.sourceId === d.sourceId && r.data.status === "posted",
        )
      )
        fail(
          "Use a supplier debit note for returned goods instead of reversing the bill",
        );
      if (kind === "payments" && d.flow?.endsWith("_refund"))
        await reverseRefund(this, e);
      if (!a.reason?.trim()) fail("A reversal reason is required");
      if (["invoices", "supplierInvoices"].includes(kind) && (d.paid ?? 0) > 0)
        fail("Reverse allocated payments first");
      if (
        kind === "expenses" &&
        d.sourceId &&
        (await this.get("production", d.sourceId)).data.completed
      )
        fail("Completed job cost requires a controlled cost adjustment");
      const journals = (await this.all("journals")).filter(
        (j) => j.data.sourceId === e.id && !j.data.reversed,
      );
      for (const j of journals) {
        await this.journal(
          e,
          j.data.journalLines!.map((l) => ({
            ...l,
            debit: l.credit,
            credit: l.debit,
          })),
          `Reversal: ${a.reason}`,
        );
        j.data.reversed = true;
        await this.save(j);
      }
      if (kind === "payments")
        for (const allocation of d.allocations ?? []) {
          const invoice = await this.get(
            d.flow === "receipt" ? "invoices" : "supplierInvoices",
            allocation.invoiceId,
          );
          invoice.data.paid = (invoice.data.paid ?? 0) - allocation.amount;
          await this.save(invoice);
        }
      if (kind === "invoices" || kind === "supplierInvoices") {
        const source = await this.get(
          kind === "invoices" ? "sales" : "purchases",
          d.sourceId!,
        );
        for (const l of d.lines!) {
          const ol = source.data.lines!.find((x) => x.itemId === l.itemId)!;
          if (kind === "supplierInvoices") changeBilledTotals(ol, l, -1);
          ol.invoiced = quantityAdd(ol.invoiced ?? 0, -l.quantity);
        }
        await this.save(source);
      }
      d.status = "reversed";
      d.reason = a.reason;
    } else if (kind === "challans" && a.action === "acknowledge") {
      if (d.status !== "dispatched")
        fail("Challan is not awaiting acknowledgement");
      d.acknowledged = true;
      d.status = "delivered";
    } else if (kind === "tickets" && a.action === "close") {
      d.status = "closed";
    } else if (a.action === "void" && d.status === "draft") {
      d.status = "void";
    } else fail("Action is not valid for this record and state");
    return this.save(e);
  }
}

export async function transact<T>(
  actor: Actor,
  key: string,
  body: unknown,
  operation: (b: Business) => Promise<T>,
): Promise<T> {
  if (!/^[a-zA-Z0-9_-]{12,100}$/.test(key))
    fail("A valid Idempotency-Key is required");
  const hash = createHash("sha256")
    .update(JSON.stringify({ actor: actor.id, body }))
    .digest("hex");
  const session = await mongoose.startSession();
  let result: T | undefined;
  try {
    await session.withTransaction(async () => {
      const org = await Org.findOneAndUpdate(
        { id: actor.org },
        { $inc: { revision: 1 } },
        { session, new: true },
      );
      if (!org) fail("Organization not found", 404);
      const previous = await Idempotency.findOne({ org: actor.org, key })
        .session(session)
        .lean();
      if (previous) {
        if (previous.hash !== hash)
          fail("Idempotency key reused with different request", 409);
        result = previous.result as T;
        return;
      }
      const b = new Business(actor, session);
      result = await operation(b);
      await b.add("audit", {
        actor: actor.id,
        name: "Business operation",
        description:
          typeof body === "object" && body !== null && "path" in body
            ? String(body.path)
            : "Business operation",
        date: new Date().toISOString().slice(0, 10),
      });
      await Idempotency.create([{ org: actor.org, key, hash, result }], {
        session,
      });
    });
    return result!;
  } finally {
    await session.endSession();
  }
}
