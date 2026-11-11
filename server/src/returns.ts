import { z } from "zod";
import type { Business } from "./service.js";
import {
  fail,
  type Data,
  type Entry,
  type JournalLine,
  type Kind,
  type Line,
} from "./types.js";
import {
  integer,
  quantityAdd,
  quantityMilli,
  roundedRatio,
  totals,
} from "./calculations.js";
import { id, qty, actionSchema } from "./validation.js";

export const returnKinds: Kind[] = [
  "customerReturns",
  "supplierReturns",
  "creditNotes",
  "debitNotes",
];
const schema = z
  .object({
    sourceId: id,
    returnId: id.optional(),
    date: z.string().date(),
    reason: z.string().trim().min(3).max(1000),
    quantities: z
      .array(z.object({ itemId: id, quantity: qty }).strict())
      .min(1)
      .max(200),
  })
  .strict();
const isNote = (kind: Kind) => kind === "creditNotes" || kind === "debitNotes";
const sourceKind = (kind: Kind): Kind =>
  kind === "customerReturns"
    ? "challans"
    : kind === "supplierReturns"
      ? "purchases"
      : kind === "creditNotes"
        ? "invoices"
        : "supplierInvoices";
function unique(quantities: { itemId: string; quantity: number }[]) {
  if (new Set(quantities.map((q) => q.itemId)).size !== quantities.length)
    fail("Combine duplicate item rows");
}
function portion(
  value: number,
  before: number,
  quantity: number,
  total: number,
) {
  return (
    roundedRatio(
      value,
      quantityMilli(quantityAdd(before, quantity)),
      quantityMilli(total),
    ) - roundedRatio(value, quantityMilli(before), quantityMilli(total))
  );
}
function creditLine(line: Line, quantity: number): Line {
  const original = totals([line]);
  const remaining = quantityMilli(
    quantityAdd(line.quantity, -(line.creditedQuantity ?? 0)),
  );
  if (remaining <= 0) fail("No uncredited quantity remains");
  const allocate = (amount: number) =>
    roundedRatio(amount, quantityMilli(quantity), remaining);
  const remainingDiscount = line.discount - (line.creditedDiscount ?? 0);
  const remainingGross = original.subtotal - (line.creditedGross ?? 0);
  const discount = allocate(remainingDiscount);
  const gross = integer(
    allocate(remainingGross - remainingDiscount) + discount,
  );
  const cgstAmount =
    line.taxMode === "split"
      ? allocate(Math.floor(original.tax / 2) - (line.creditedCgst ?? 0))
      : 0;
  const sgstAmount =
    line.taxMode === "split"
      ? allocate(
          original.tax -
            Math.floor(original.tax / 2) -
            (line.creditedSgst ?? 0),
        )
      : 0;
  const igstAmount =
    line.taxMode === "integrated"
      ? allocate(original.tax - (line.creditedIgst ?? 0))
      : 0;
  return {
    ...line,
    quantity,
    gross,
    discount,
    taxAmount: cgstAmount + sgstAmount + igstAmount,
    cgstAmount,
    sgstAmount,
    igstAmount,
    creditedQuantity: undefined,
  };
}
function changeCreditTotals(source: Line, note: Line, direction: 1 | -1) {
  source.creditedGross = integer(
    (source.creditedGross ?? 0) + direction * (note.gross ?? 0),
  );
  source.creditedDiscount = integer(
    (source.creditedDiscount ?? 0) + direction * note.discount,
  );
  source.creditedCgst = integer(
    (source.creditedCgst ?? 0) + direction * (note.cgstAmount ?? 0),
  );
  source.creditedSgst = integer(
    (source.creditedSgst ?? 0) + direction * (note.sgstAmount ?? 0),
  );
  source.creditedIgst = integer(
    (source.creditedIgst ?? 0) + direction * (note.igstAmount ?? 0),
  );
}

export async function createReturn(b: Business, kind: Kind, input: unknown) {
  const p = schema.parse(input);
  unique(p.quantities);
  const source = await b.get(sourceKind(kind), p.sourceId);
  const note = isNote(kind);
  if (note && source.data.status !== "posted")
    fail("A posted source invoice is required");
  if (
    kind === "customerReturns" &&
    !["dispatched", "delivered"].includes(source.data.status ?? "")
  )
    fail("A dispatched challan is required");
  if (kind === "supplierReturns" && source.data.status !== "confirmed")
    fail("A confirmed purchase is required");
  const lines: Line[] = [];
  for (const q of p.quantities) {
    const line = source.data.lines?.find((l) => l.itemId === q.itemId);
    if (!line) fail("Item does not belong to the source document");
    const limit = note
      ? quantityAdd(line.quantity, -(line.creditedQuantity ?? 0))
      : quantityAdd(
          kind === "supplierReturns"
            ? Math.min(line.received ?? 0, line.invoiced ?? 0)
            : line.quantity,
          -(line.returned ?? 0),
        );
    if (q.quantity > limit)
      fail(
        note
          ? "Note exceeds uncredited invoice quantity"
          : "Return exceeds received/dispatched quantity",
      );
    if (note) lines.push(creditLine(line, q.quantity));
    else {
      if (kind === "customerReturns" && line.costValue === undefined)
        fail(
          "Dispatch cost snapshot missing; a reviewed migration is required",
        );
      lines.push({
        ...line,
        quantity: q.quantity,
        rate: 0,
        discount: 0,
        taxBps: 0,
        taxMode: "none",
        gross: undefined,
        taxAmount: undefined,
        costValue:
          kind === "customerReturns"
            ? portion(
                line.costValue!,
                line.returned ?? 0,
                q.quantity,
                line.quantity,
              )
            : undefined,
      });
    }
  }
  const data: Data = {
    name: `${({ customerReturns: "Customer return", supplierReturns: "Supplier return", creditNotes: "Credit note", debitNotes: "Debit note" } as Record<string, string>)[kind]} · ${source.data.number ?? source.id.slice(0, 8)}`,
    sourceId: p.sourceId,
    returnId: p.returnId,
    date: p.date,
    reason: p.reason,
    partyId: source.data.partyId,
    warehouseId: source.data.warehouseId,
    status: "draft",
    lines,
    ...(note ? totals(lines) : {}),
    businessSnapshot: source.data.businessSnapshot,
    partySnapshot: source.data.partySnapshot,
    ...(note ? { refunded: 0 } : {}),
  };
  if (!note) await b.snapshot(data);
  if (p.returnId) {
    if (!note) fail("A physical return cannot reference another return");
    const physical = await b.get(
      kind === "creditNotes" ? "customerReturns" : "supplierReturns",
      p.returnId,
    );
    if (
      physical.data.status !== "posted" ||
      physical.data.partyId !== data.partyId ||
      physical.data.noted
    )
      fail("Choose an unmatched posted return for the same party");
    if (!sameQuantities(lines, physical.data.lines ?? []))
      fail("Linked note must match all quantities of the physical return");
    if (
      kind === "debitNotes" &&
      physical.data.sourceId !== source.data.sourceId
    )
      fail("Supplier return belongs to a different purchase");
    if (kind === "creditNotes") {
      const dispatch = await b.get("challans", physical.data.sourceId!);
      if (dispatch.data.sourceId !== source.data.sourceId)
        fail("Customer return belongs to a different sales order");
    }
  }
  return b.add(kind, data);
}
function sameQuantities(a: Line[], b: Line[]) {
  return (
    a.length === b.length &&
    a.every((l) =>
      b.some(
        (r) =>
          r.itemId === l.itemId &&
          quantityMilli(r.quantity) === quantityMilli(l.quantity),
      ),
    )
  );
}

export async function actReturn(b: Business, e: Entry, input: unknown) {
  const a = actionSchema.parse(input),
    d = e.data,
    note = isNote(e.kind);
  if (a.action === "void" && d.status === "draft") {
    d.status = "void";
    return b.save(e);
  }
  if (a.action === "reverse" && note) {
    if (d.status !== "posted" || !a.reason?.trim())
      fail("A posted note and reversal reason are required");
    if ((d.refunded ?? 0) > 0)
      fail("Reverse linked refunds before reversing the note");
    const source = await b.get(sourceKind(e.kind), d.sourceId!);
    for (const line of d.lines!) {
      const sl = source.data.lines!.find((l) => l.itemId === line.itemId)!;
      changeCreditTotals(sl, line, -1);
      sl.creditedQuantity = quantityAdd(
        sl.creditedQuantity ?? 0,
        -line.quantity,
      );
    }
    source.data.credited = integer((source.data.credited ?? 0) - d.total!);
    await b.save(source);
    for (const journal of (await b.all("journals")).filter(
      (j) => j.data.sourceId === e.id && !j.data.reversed,
    )) {
      await b.journal(
        e,
        journal.data.journalLines!.map((l) => ({
          ...l,
          debit: l.credit,
          credit: l.debit,
        })),
        "Note reversal: " + a.reason,
      );
      journal.data.reversed = true;
      await b.save(journal);
    }
    if (d.returnId) {
      const physical = await b.get(
        e.kind === "creditNotes" ? "customerReturns" : "supplierReturns",
        d.returnId,
      );
      physical.data.noted = false;
      await b.save(physical);
    }
    d.status = "reversed";
    d.reason = a.reason;
    return b.save(e);
  }
  if (a.action !== "finalize" || d.status !== "draft")
    fail("Only draft returns/notes can be finalized");
  const source = await b.get(sourceKind(e.kind), d.sourceId!);
  if (note && source.data.status !== "posted")
    fail("Source invoice is no longer posted");
  if (note) {
    // Recompute cumulative portions at posting time so concurrent drafts cannot consume the same rounding remainder.
    const lines: Line[] = [];
    for (const line of d.lines!) {
      const sl = source.data.lines!.find((l) => l.itemId === line.itemId)!;
      if (line.quantity > quantityAdd(sl.quantity, -(sl.creditedQuantity ?? 0)))
        fail("Note exceeds uncredited quantity");
      const credited = creditLine(sl, line.quantity);
      lines.push(credited);
      changeCreditTotals(sl, credited, 1);
      sl.creditedQuantity = quantityAdd(
        sl.creditedQuantity ?? 0,
        line.quantity,
      );
    }
    d.lines = lines;
    Object.assign(d, totals(lines));
    source.data.credited = integer((source.data.credited ?? 0) + d.total!);
    let physical: Entry | undefined;
    if (d.returnId) {
      physical = await b.get(
        e.kind === "creditNotes" ? "customerReturns" : "supplierReturns",
        d.returnId,
      );
      if (
        physical.data.status !== "posted" ||
        physical.data.noted ||
        !sameQuantities(lines, physical.data.lines ?? [])
      )
        fail("Physical return has already been matched or changed");
      physical.data.noted = true;
      await b.save(physical);
    }
    const net = d.subtotal! - d.discount!;
    const jl: JournalLine[] =
      e.kind === "creditNotes"
        ? [
            { account: "Sales returns", debit: net, credit: 0 },
            {
              account: "Accounts receivable",
              debit: 0,
              credit: d.total!,
              partyId: d.partyId,
            },
          ]
        : [
            {
              account: "Accounts payable",
              debit: d.total!,
              credit: 0,
              partyId: d.partyId,
            },
            {
              account: physical
                ? "Supplier returns clearing"
                : "Purchase adjustments",
              debit: 0,
              credit: physical ? physical.data.value! : net,
            },
          ];
    if (e.kind === "creditNotes") {
      for (const line of lines) {
        const tax = totals([line]).tax;
        if (!tax) continue;
        if (line.taxMode === "split") {
          jl.push(
            { account: "CGST payable", debit: line.cgstAmount ?? 0, credit: 0 },
            { account: "SGST payable", debit: line.sgstAmount ?? 0, credit: 0 },
          );
        } else jl.push({ account: "IGST payable", debit: tax, credit: 0 });
      }
    } else {
      if (d.tax)
        jl.push({
          account: "Input tax pending validation",
          debit: 0,
          credit: d.tax,
        });
      if (physical) {
        const difference = net - physical.data.value!;
        if (difference)
          jl.push({
            account: "Purchase return variance",
            debit: difference < 0 ? -difference : 0,
            credit: difference > 0 ? difference : 0,
          });
      }
    }
    await b.journal(
      e,
      jl,
      e.kind === "creditNotes" ? "Customer credit note" : "Supplier debit note",
    );
    await b.save(source);
  } else {
    let value = 0;
    for (const line of d.lines!) {
      const sl = source.data.lines!.find((l) => l.itemId === line.itemId)!;
      const available = quantityAdd(
        e.kind === "supplierReturns"
          ? Math.min(sl.received ?? 0, sl.invoiced ?? 0)
          : sl.quantity,
        -(sl.returned ?? 0),
      );
      if (line.quantity > available)
        fail("Return exceeds remaining source quantity");
      const cost =
        e.kind === "customerReturns"
          ? portion(sl.costValue!, sl.returned ?? 0, line.quantity, sl.quantity)
          : await b.issueValue(line.itemId, line.quantity, d.warehouseId);
      line.costValue = cost;
      sl.returned = quantityAdd(sl.returned ?? 0, line.quantity);
      value = integer(value + cost);
      await b.movement(
        line.itemId,
        e.kind === "customerReturns" ? line.quantity : -line.quantity,
        e,
        e.kind === "customerReturns" ? "customer return" : "supplier return",
        d.warehouseId,
        e.kind === "customerReturns" ? cost : -cost,
      );
    }
    d.value = value;
    await b.save(source);
    if (value)
      await b.journal(
        e,
        e.kind === "customerReturns"
          ? [
              { account: "Inventory", debit: value, credit: 0 },
              { account: "Cost of goods sold", debit: 0, credit: value },
            ]
          : [
              { account: "Supplier returns clearing", debit: value, credit: 0 },
              { account: "Inventory", debit: 0, credit: value },
            ],
        "Physical " +
          (e.kind === "customerReturns" ? "customer" : "supplier") +
          " return",
      );
  }
  d.number = await b.number(
    (
      {
        customerReturns: "CR",
        supplierReturns: "SR",
        creditNotes: "CN",
        debitNotes: "DN",
      } as Record<string, string>
    )[e.kind],
    d.date!,
  );
  d.status = "posted";
  return b.save(e);
}

export async function validateRefund(b: Business, data: Data) {
  if (!data.flow?.endsWith("_refund")) {
    if (data.sourceId) fail("Source note is valid only for a refund");
    return;
  }
  if (!data.sourceId)
    fail("A posted credit/debit note is required for a refund");
  if (data.allocations?.length)
    fail(
      "Refunds reference a credit/debit note rather than invoice allocations",
    );
  const note = await b.get(
    data.flow === "customer_refund" ? "creditNotes" : "debitNotes",
    data.sourceId,
  );
  if (note.data.status !== "posted" || note.data.partyId !== data.partyId)
    fail("Refund note must be posted for the same party");
}
export async function finalizeRefund(b: Business, e: Entry) {
  const d = e.data;
  await validateRefund(b, d);
  const note = await b.get(
    d.flow === "customer_refund" ? "creditNotes" : "debitNotes",
    d.sourceId!,
  );
  const invoice = await b.get(
    d.flow === "customer_refund" ? "invoices" : "supplierInvoices",
    note.data.sourceId!,
  );
  const available = Math.max(
    0,
    (invoice.data.paid ?? 0) +
      (invoice.data.credited ?? 0) -
      invoice.data.total! -
      (invoice.data.refunded ?? 0),
  );
  if (
    d.amount! > available ||
    d.amount! > note.data.total! - (note.data.refunded ?? 0)
  )
    fail("Refund exceeds the available credit balance");
  note.data.refunded = integer((note.data.refunded ?? 0) + d.amount!);
  invoice.data.refunded = integer((invoice.data.refunded ?? 0) + d.amount!);
  await b.save(note);
  await b.save(invoice);
  const cash = d.method === "cash" ? "Cash" : "Bank";
  await b.journal(
    e,
    d.flow === "customer_refund"
      ? [
          {
            account: "Accounts receivable",
            debit: d.amount!,
            credit: 0,
            partyId: d.partyId,
          },
          { account: cash, debit: 0, credit: d.amount! },
        ]
      : [
          { account: cash, debit: d.amount!, credit: 0 },
          {
            account: "Accounts payable",
            debit: 0,
            credit: d.amount!,
            partyId: d.partyId,
          },
        ],
    "Credit/debit note refund",
  );
  d.status = "posted";
  return b.save(e);
}
export async function reverseRefund(b: Business, e: Entry) {
  const d = e.data;
  const note = await b.get(
    d.flow === "customer_refund" ? "creditNotes" : "debitNotes",
    d.sourceId!,
  );
  const invoice = await b.get(
    d.flow === "customer_refund" ? "invoices" : "supplierInvoices",
    note.data.sourceId!,
  );
  note.data.refunded = integer((note.data.refunded ?? 0) - d.amount!);
  invoice.data.refunded = integer((invoice.data.refunded ?? 0) - d.amount!);
  if (note.data.refunded < 0 || invoice.data.refunded < 0)
    fail("Refund balances require reconciliation");
  await b.save(note);
  await b.save(invoice);
}
