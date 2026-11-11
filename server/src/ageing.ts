import { RecordModel } from "./models.js";
import { fail, type Actor, type Entry } from "./types.js";
import { integer } from "./calculations.js";
export async function ageingReport(actor: Actor, asOf: string) {
  const [records, journals] = await Promise.all([
    RecordModel.find({
      org: actor.org,
      kind: {
        $in: [
          "invoices",
          "supplierInvoices",
          "creditNotes",
          "debitNotes",
          "payments",
          "parties",
        ],
      },
    }).lean(),
    RecordModel.find({
      org: actor.org,
      kind: "journals",
      "data.status": "posted",
      "data.date": { $lte: asOf },
    }).lean(),
  ]);
  const impact = new Map<string, { receivable: number; payable: number }>();
  for (const journal of journals) {
    const source = journal.data.sourceId ?? journal.id;
    const balance = impact.get(source) ?? { receivable: 0, payable: 0 };
    for (const line of journal.data.journalLines ?? []) {
      if (line.account === "Accounts receivable")
        balance.receivable = integer(
          balance.receivable + line.debit - line.credit,
        );
      if (line.account === "Accounts payable")
        balance.payable = integer(balance.payable + line.credit - line.debit);
    }
    impact.set(source, balance);
  }
  const byId = new Map(records.map((r) => [r.id, r]));
  const invoiceBalances = new Map<string, number>();
  for (const record of records)
    if (record.kind === "invoices" || record.kind === "supplierInvoices") {
      const opening =
        impact.get(record.id)?.[
          record.kind === "invoices" ? "receivable" : "payable"
        ] ?? 0;
      if (opening) invoiceBalances.set(record.id, opening);
    }
  for (const record of records) {
    if (record.kind === "creditNotes" || record.kind === "debitNotes") {
      if (!invoiceBalances.has(record.data.sourceId!)) continue;
      const value =
        impact.get(record.id)?.[
          record.kind === "creditNotes" ? "receivable" : "payable"
        ] ?? 0;
      invoiceBalances.set(
        record.data.sourceId!,
        integer(invoiceBalances.get(record.data.sourceId!)! + value),
      );
    } else if (record.kind === "payments") {
      const customer =
        record.data.flow === "receipt" ||
        record.data.flow === "customer_refund";
      const value =
        impact.get(record.id)?.[customer ? "receivable" : "payable"] ?? 0;
      if (!value) continue;
      if (record.data.flow?.endsWith("_refund")) {
        const note = byId.get(record.data.sourceId!);
        if (note && invoiceBalances.has(note.data.sourceId!))
          invoiceBalances.set(
            note.data.sourceId!,
            integer(invoiceBalances.get(note.data.sourceId!)! + value),
          );
      } else {
        const factor = value / record.data.amount!;
        if (!Number.isInteger(factor) || Math.abs(factor) > 1)
          fail("Payment allocation journals require reconciliation", 409);
        for (const allocation of record.data.allocations ?? [])
          if (invoiceBalances.has(allocation.invoiceId))
            invoiceBalances.set(
              allocation.invoiceId,
              integer(
                invoiceBalances.get(allocation.invoiceId)! +
                  factor * allocation.amount,
              ),
            );
      }
    }
  }
  const data = [];
  const totals = {
    receivable: 0,
    payable: 0,
    customerCredit: 0,
    supplierCredit: 0,
  };
  for (const [id, amount] of invoiceBalances) {
    if (!amount) continue;
    const invoice = byId.get(id)! as Entry;
    const type = invoice.kind === "invoices" ? "receivable" : "payable";
    const dueDate = invoice.data.dueDate ?? invoice.data.date!;
    const days = Math.max(
      0,
      Math.floor(
        (Date.parse(asOf + "T00:00:00Z") - Date.parse(dueDate + "T00:00:00Z")) /
          86400000,
      ),
    );
    const bucket =
      amount < 0
        ? "credit"
        : dueDate >= asOf
          ? "current"
          : days <= 30
            ? "1–30"
            : days <= 60
              ? "31–60"
              : days <= 90
                ? "61–90"
                : "90+";
    const party = byId.get(invoice.data.partyId!);
    data.push({
      invoiceId: id,
      number: invoice.data.number,
      partyId: invoice.data.partyId,
      party:
        party?.data.name ?? invoice.data.partySnapshot?.name ?? "Unknown party",
      type,
      date: invoice.data.date,
      dueDate,
      daysOverdue: days,
      bucket,
      amount,
    });
    if (amount > 0) totals[type] = integer(totals[type] + amount);
    else if (type === "receivable")
      totals.customerCredit = integer(totals.customerCredit - amount);
    else totals.supplierCredit = integer(totals.supplierCredit - amount);
  }
  data.sort(
    (a, b) =>
      a.dueDate.localeCompare(b.dueDate) ||
      (a.number ?? "").localeCompare(b.number ?? ""),
  );
  return {
    asOf,
    data,
    totals,
    scope:
      "Invoice allocations only; unallocated party payments and manual opening balances are shown in the party ledger.",
  };
}
