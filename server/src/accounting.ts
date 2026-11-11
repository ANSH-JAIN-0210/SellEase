import { RecordModel } from "./models.js";
import type { Actor, Data } from "./types.js";
export type AccountType = NonNullable<Data["accountType"]>;
export const builtInAccounts: Record<string, AccountType> = {
  Cash: "asset",
  Bank: "asset",
  Inventory: "asset",
  "Work in progress": "asset",
  "Accounts receivable": "asset",
  "Input tax pending validation": "asset",
  "Accounts payable": "liability",
  "Goods received not invoiced": "liability",
  "Accrued production costs": "liability",
  "CGST payable": "liability",
  "SGST payable": "liability",
  "IGST payable": "liability",
  Capital: "equity",
  Sales: "revenue",
  "Sales returns": "revenue",
  "Cost of goods sold": "expense",
  "Purchase adjustments": "expense",
  "Purchase return variance": "expense",
  "Supplier returns clearing": "asset",
};
export async function financialReport(
  actor: Actor,
  from?: string,
  to?: string,
) {
  const accounts = await RecordModel.find({
    org: actor.org,
    kind: "accounts",
  }).lean();
  const chart = { ...builtInAccounts };
  for (const account of accounts)
    chart[account.data.name!] = account.data.accountType!;
  const base = { org: actor.org, kind: "journals", "data.status": "posted" };
  const pipeline = (date: Record<string, string>) => [
    {
      $match: {
        ...base,
        ...(Object.keys(date).length ? { "data.date": date } : {}),
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
    { $sort: { _id: 1 as const } },
  ];
  const [period, closing] = await Promise.all([
    RecordModel.aggregate<{ _id: string; debit: number; credit: number }>(
      pipeline({
        ...(from ? { $gte: from } : {}),
        ...(to ? { $lte: to } : {}),
      }),
    ),
    RecordModel.aggregate<{ _id: string; debit: number; credit: number }>(
      pipeline(to ? { $lte: to } : {}),
    ),
  ]);
  const classify = (name: string) =>
    chart[name] ?? (name.startsWith("Expense: ") ? "expense" : undefined);
  const rows = (records: typeof period) =>
    records.map((row) => ({
      ...row,
      type: classify(row._id),
      balance: row.debit - row.credit,
    }));
  const periodRows = rows(period),
    closingRows = rows(closing);
  const sum = (data: typeof periodRows, type: AccountType, credit = false) =>
    data
      .filter((r) => r.type === type)
      .reduce((s, r) => s + (credit ? -r.balance : r.balance), 0);
  const revenue = sum(periodRows, "revenue", true),
    expenses = sum(periodRows, "expense"),
    profit = revenue - expenses;
  const cumulativeProfit =
    sum(closingRows, "revenue", true) - sum(closingRows, "expense");
  const assets = sum(closingRows, "asset"),
    liabilities = sum(closingRows, "liability", true),
    equity = sum(closingRows, "equity", true);
  const unclassified = [
    ...new Set(closingRows.filter((r) => !r.type).map((r) => r._id)),
  ];
  return {
    period: periodRows,
    closing: closingRows,
    profitAndLoss: { revenue, expenses, profit },
    balanceSheet: {
      assets,
      liabilities,
      equity,
      currentResult: cumulativeProfit,
      totalEquity: equity + cumulativeProfit,
      difference: assets - liabilities - equity - cumulativeProfit,
    },
    unclassified,
    classified: unclassified.length === 0,
    chart: Object.entries(chart).map(([name, type]) => ({ name, type })),
  };
}
