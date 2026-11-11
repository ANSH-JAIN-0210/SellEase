import { test } from "node:test";
import assert from "node:assert/strict";
import { totals, journalBalance, fiscalYear } from "../src/calculations.js";
test("money calculations use integer minor units and exact half-up tax rounding", () => {
  assert.deepEqual(
    totals([
      {
        itemId: "x",
        quantity: 3,
        rate: 1001,
        discount: 3,
        taxBps: 500,
        taxMode: "split",
      },
    ]),
    { subtotal: 3003, discount: 3, tax: 150, total: 3150 },
  );
  assert.equal(
    totals([
      {
        itemId: "x",
        quantity: 1,
        rate: 1,
        discount: 0,
        taxBps: 5000,
        taxMode: "integrated",
      },
    ]).tax,
    1,
  );
  assert.throws(() =>
    totals([
      {
        itemId: "x",
        quantity: 1,
        rate: 100,
        discount: 101,
        taxBps: 0,
        taxMode: "none",
      },
    ]),
  );
});
test("journals reject imbalance, negative values and unsafe amounts", () => {
  assert.equal(
    journalBalance([
      { account: "Cash", debit: 120, credit: 0 },
      { account: "Capital", debit: 0, credit: 120 },
    ]),
    120,
  );
  assert.throws(() =>
    journalBalance([
      { account: "Cash", debit: 121, credit: 0 },
      { account: "Capital", debit: 0, credit: 120 },
    ]),
  );
  assert.throws(() =>
    journalBalance([
      { account: "Cash", debit: 1.1, credit: 0 },
      { account: "Capital", debit: 0, credit: 1.1 },
    ]),
  );
});
test("financial year follows configured start month", () => {
  assert.equal(fiscalYear("2026-03-31", 4), "2025-26");
  assert.equal(fiscalYear("2026-04-01", 4), "2026-27");
  assert.equal(fiscalYear("2026-12-31", 1), "2026-27");
});
