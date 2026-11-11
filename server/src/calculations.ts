import { fail, type Line, type JournalLine } from "./types.js";
export function integer(v: number) {
  if (!Number.isSafeInteger(v)) fail("Unsafe numeric amount");
  return v;
}
export function quantityMilli(value: number) {
  if (!Number.isFinite(value)) fail("Invalid quantity");
  const scaled = Math.round(value * 1000);
  if (Math.abs(scaled / 1000 - value) > 1e-9)
    fail("Quantities support at most three decimal places");
  return integer(scaled);
}
export function quantityAdd(a: number, b: number) {
  return integer(quantityMilli(a) + quantityMilli(b)) / 1000;
}
export function quantityValue(quantity: number, rate: number) {
  return roundedRatio(rate, quantityMilli(quantity), 1000);
}
export function roundedRatio(
  value: number,
  numerator: number,
  denominator: number,
) {
  const n = BigInt(integer(value)) * BigInt(integer(numerator));
  return integer(Number((n + BigInt(denominator) / 2n) / BigInt(denominator)));
}
export function totals(lines: Line[]) {
  let subtotal = 0,
    discount = 0,
    tax = 0;
  for (const l of lines) {
    const gross = l.gross ?? quantityValue(l.quantity, l.rate);
    if (l.discount > gross) fail("Discount exceeds line value");
    subtotal = integer(subtotal + gross);
    discount = integer(discount + l.discount);
    tax = integer(
      tax +
        (l.taxAmount ??
          (l.taxMode === "none"
            ? 0
            : roundedRatio(gross - l.discount, l.taxBps, 10000))),
    );
  }
  return { subtotal, discount, tax, total: integer(subtotal - discount + tax) };
}
export function supplierBillLine(line: Line, quantity: number): Line {
  if ((line.invoiced ?? 0) > 0 && line.billedNet === undefined)
    fail(
      "Historical supplier billing allocations require a reviewed migration",
      409,
    );
  const remaining = quantityMilli(
    quantityAdd(line.received ?? 0, -(line.invoiced ?? 0)),
  );
  if (remaining <= 0 || quantityMilli(quantity) > remaining)
    fail("Supplier bill exceeds received, unbilled quantity");
  const full = totals([line]);
  const received = quantityMilli(line.received ?? 0),
    ordered = quantityMilli(line.quantity);
  const availableNet =
    roundedRatio(full.subtotal - full.discount, received, ordered) -
    (line.billedNet ?? 0);
  const availableDiscount =
    roundedRatio(line.discount, received, ordered) - (line.billedDiscount ?? 0);
  const availableTax =
    roundedRatio(full.tax, received, ordered) - (line.billedTax ?? 0);
  if (Math.min(availableNet, availableDiscount, availableTax) < 0)
    fail("Supplier billing values require reconciliation", 409);
  const allocate = (amount: number) =>
    roundedRatio(amount, quantityMilli(quantity), remaining);
  const discount = allocate(availableDiscount);
  const net = allocate(availableNet);
  return {
    ...line,
    quantity,
    gross: integer(net + discount),
    discount,
    taxAmount: allocate(availableTax),
  };
}
export function changeBilledTotals(
  source: Line,
  bill: Line,
  direction: 1 | -1,
) {
  if (direction === -1 && source.billedNet === undefined)
    fail(
      "Historical supplier billing allocations require a reviewed migration",
      409,
    );
  const value = totals([bill]);
  source.billedNet = integer(
    (source.billedNet ?? 0) + direction * (value.subtotal - value.discount),
  );
  source.billedDiscount = integer(
    (source.billedDiscount ?? 0) + direction * value.discount,
  );
  source.billedTax = integer((source.billedTax ?? 0) + direction * value.tax);
  if (Math.min(source.billedNet, source.billedDiscount, source.billedTax) < 0)
    fail("Supplier billing values require reconciliation", 409);
}
export function journalBalance(lines: JournalLine[]) {
  if (lines.length < 2) fail("At least two journal lines required");
  let debit = 0,
    credit = 0;
  for (const l of lines) {
    integer(l.debit);
    integer(l.credit);
    if (l.debit < 0 || l.credit < 0 || (l.debit > 0 && l.credit > 0))
      fail("Invalid journal line");
    debit = integer(debit + l.debit);
    credit = integer(credit + l.credit);
  }
  if (debit !== credit || debit === 0) fail("Journal must balance");
  return debit;
}
export function fiscalYear(date: string, startMonth: number) {
  const d = new Date(date + "T00:00:00Z");
  const y = d.getUTCFullYear() - (d.getUTCMonth() + 1 < startMonth ? 1 : 0);
  return `${y}-${String(y + 1).slice(-2)}`;
}
