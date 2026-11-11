import { z } from "zod";
export const id = z.string().uuid();
const text = z.string().trim().max(1000);
export const money = z.number().int().min(0).max(100_000_000_000);
export const qty = z.number().positive().max(1_000_000_000).multipleOf(0.001);
export const line = z
  .object({
    itemId: id,
    quantity: qty,
    rate: money,
    discount: money.default(0),
    taxBps: z.number().int().min(0).max(10000).default(0),
    taxMode: z.enum(["split", "integrated", "none"]).default("none"),
  })
  .strict();
export const lines = z.array(line).min(1).max(200);
export const itemSchema = z
  .object({
    name: text.min(1),
    sku: z.string().trim().min(1).max(80),
    description: text.default(""),
    category: text.default(""),
    unit: z.enum(["piece", "metre", "kg", "roll"]).default("piece"),
    price: money.default(0),
    cost: money.default(0),
    reorder: z.number().int().min(0).default(0),
    hsn: text.default(""),
    color: text.default(""),
    size: text.default(""),
    style: text.default(""),
    width: z.number().nonnegative().optional(),
    gsm: z.number().nonnegative().optional(),
    lot: text.default(""),
    tags: z.array(z.string().max(60)).max(30).default([]),
    published: z.boolean().default(false),
    status: z.enum(["active", "archived"]).default("active"),
  })
  .strict();
export const partySchema = z
  .object({
    name: text.min(1),
    kind: z.enum(["customer", "supplier", "both", "contractor"]),
    email: z.union([z.string().email(), z.literal("")]).default(""),
    phone: text.default(""),
    address: text.default(""),
    gstin: text.default(""),
    notes: text.default(""),
    status: z.enum(["active", "archived"]).default("active"),
  })
  .strict();
export const masterSchema = z
  .object({
    name: text.min(1),
    description: text.default(""),
    status: z.enum(["active", "archived"]).default("active"),
  })
  .strict();
export const orderSchema = z
  .object({
    partyId: id,
    date: z.string().date(),
    dueDate: z.string().date().optional(),
    lines,
    notes: text.default(""),
    warehouseId: id.optional(),
  })
  .strict();
export const sizes = z
  .array(
    z
      .object({
        size: text.min(1),
        color: text.default(""),
        planned: z.number().int().nonnegative(),
        actual: z.number().int().nonnegative(),
        rejected: z.number().int().nonnegative(),
      })
      .strict(),
  )
  .min(1)
  .max(200);
export const productionSchema = z
  .object({
    name: text.min(1),
    outputItemId: id,
    quantity: qty,
    materialLines: z
      .array(z.object({ itemId: id, quantity: qty }).strict())
      .min(1)
      .max(100),
    date: z.string().date(),
    notes: text.default(""),
    costLines: z
      .array(z.object({ name: text.min(1), amount: money }).strict())
      .max(100)
      .default([]),
  })
  .strict();
export const cuttingSchema = z
  .object({
    name: text.min(1),
    sourceId: id,
    itemId: id,
    quantity: qty,
    sizes,
    date: z.string().date(),
    notes: text.default(""),
  })
  .strict();
export const expenseSchema = z
  .object({
    name: text.min(1),
    category: text.min(1),
    amount: money.refine((v) => v > 0),
    date: z.string().date(),
    method: z.enum(["cash", "bank"]),
    partyId: id.optional(),
    sourceId: id.optional(),
    notes: text.default(""),
  })
  .strict();
export const paymentSchema = z
  .object({
    partyId: id,
    amount: money.refine((v) => v > 0),
    date: z.string().date(),
    method: z.enum(["cash", "bank", "upi", "cheque"]),
    flow: z.enum(["receipt", "payment", "customer_refund", "supplier_refund"]),
    sourceId: id.optional(),
    reference: text.min(1),
    allocations: z
      .array(
        z
          .object({ invoiceId: id, amount: money.refine((v) => v > 0) })
          .strict(),
      )
      .max(100),
    notes: text.default(""),
  })
  .strict();
export const actionSchema = z
  .object({
    action: z.enum([
      "confirm",
      "receive",
      "dispatch",
      "finalize",
      "void",
      "reverse",
      "issue",
      "advance",
      "complete",
      "acknowledge",
      "close",
      "return",
    ]),
    quantities: z
      .array(z.object({ itemId: id, quantity: qty }).strict())
      .max(200)
      .optional(),
    finished: z.number().int().nonnegative().optional(),
    rejected: z.number().int().nonnegative().optional(),
    vehicle: text.optional(),
    eway: text.optional(),
    transport: text.optional(),
    reason: text.optional(),
    postingDate: z.string().date().optional(),
  })
  .strict();
export const settingsSchema = z
  .object({
    name: text.min(1),
    address: text,
    gstin: text,
    currency: z.enum(["INR", "USD", "EUR", "GBP", "AUD", "CAD", "SGD", "AED"]),
    timezone: z.string().refine((v) => {
      try {
        new Intl.DateTimeFormat("en", { timeZone: v });
        return true;
      } catch {
        return false;
      }
    }, "Invalid timezone"),
    financialYearStart: z.number().int().min(1).max(12),
    businessType: z.enum(["garment", "wholesale", "retail"]),
    stages: z.array(text.min(1)).min(1).max(12),
    catalogEnabled: z.boolean(),
  })
  .strict();
