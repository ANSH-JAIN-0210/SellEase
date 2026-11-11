import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import mongoose from "mongoose";
import request from "supertest";
import { MongoMemoryReplSet } from "mongodb-memory-server";
import { createApp } from "../src/app.js";
import { initModels, RecordModel, User } from "../src/models.js";
import { hash } from "../src/auth.js";
import type { Entry } from "../src/types.js";
let mongo: MongoMemoryReplSet;
const app = createApp();
const owner = request.agent(app),
  other = request.agent(app),
  sales = request.agent(app);
const date = "2026-11-03";
const post = (
  agent: typeof owner,
  path: string,
  data: unknown,
  key = randomUUID(),
) =>
  agent
    .post("/api" + path)
    .set("X-SellEase", "1")
    .set("Idempotency-Key", key)
    .set("Content-Type", "application/json")
    .send(JSON.stringify(data));
async function create(kind: string, data: unknown) {
  const r = await post(owner, "/records/" + kind, data);
  assert.equal(r.status, 201, JSON.stringify(r.body));
  return r.body;
}
async function act(
  kind: string,
  id: string,
  data: unknown,
  key = randomUUID(),
) {
  const r = await post(owner, `/records/${kind}/${id}/actions`, data, key);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return r.body;
}
before(async () => {
  mongo = await MongoMemoryReplSet.create({
    replSet: { count: 1, storageEngine: "wiredTiger" },
    instanceOpts: [{ launchTimeout: 60000 }],
  });
  await mongoose.connect(mongo.getUri());
  await initModels();
  for (const [agent, name] of [
    [owner, "Owner"],
    [other, "Other"],
  ] as const) {
    const r = await post(agent, "/auth/register", {
      name,
      businessName: name + " business",
      email: name.toLowerCase() + "@example.com",
      password: "a-long-test-password",
    });
    assert.equal(r.status, 201, JSON.stringify(r.body));
  }
});
after(async () => {
  await mongoose.disconnect();
  await mongo?.stop();
});
test("complete persistent purchase → manufacture → dispatch → invoice → allocation workflow", async () => {
  const supplier = await create("parties", {
    name: "Fabric supplier",
    kind: "supplier",
  });
  const customer = await create("parties", {
    name: "Wholesale customer",
    kind: "customer",
  });
  const fabric = await create("materials", {
    name: "Cotton · navy lot A",
    sku: "FAB-A",
    unit: "metre",
    cost: 10000,
    reorder: 5,
  });
  const product = await create("products", {
    name: "Cargo · Navy · L",
    sku: "CARGO-N-L",
    unit: "piece",
    price: 65000,
    cost: 30000,
    reorder: 5,
  });
  const purchase = await create("purchases", {
    partyId: supplier.id,
    date,
    lines: [{ itemId: fabric.id, quantity: 100, rate: 10000 }],
  });
  let stock = (await owner.get("/api/stock")).body.data;
  assert.equal(stock.length, 0, "draft must not alter stock");
  await act("purchases", purchase.id, { action: "confirm" });
  const receiptKey = randomUUID();
  await act(
    "purchases",
    purchase.id,
    { action: "receive", quantities: [{ itemId: fabric.id, quantity: 60 }] },
    receiptKey,
  );
  await act(
    "purchases",
    purchase.id,
    { action: "receive", quantities: [{ itemId: fabric.id, quantity: 60 }] },
    receiptKey,
  );
  stock = (await owner.get("/api/stock")).body.data;
  assert.equal(
    stock[0].quantity,
    60,
    "duplicate receipt must not duplicate stock",
  );
  const excess = await post(
    owner,
    `/records/purchases/${purchase.id}/actions`,
    { action: "receive", quantities: [{ itemId: fabric.id, quantity: 41 }] },
  );
  assert.equal(excess.status, 400);
  await act("purchases", purchase.id, {
    action: "receive",
    quantities: [{ itemId: fabric.id, quantity: 40 }],
  });
  const job = await create("production", {
    name: "Cargo batch A",
    outputItemId: product.id,
    quantity: 20,
    date,
    materialLines: [{ itemId: fabric.id, quantity: 40 }],
    costLines: [{ name: "Stitching", amount: 100000 }],
  });
  await act("production", job.id, { action: "issue" });
  assert.equal(
    (
      await post(owner, `/records/production/${job.id}/actions`, {
        action: "issue",
      })
    ).status,
    400,
  );
  const cutting = await create("cutting", {
    name: "Cutting A",
    sourceId: job.id,
    itemId: fabric.id,
    quantity: 40,
    date,
    sizes: [{ size: "L", color: "Navy", planned: 20, actual: 20, rejected: 1 }],
  });
  await act("cutting", cutting.id, { action: "confirm" });
  const expense = await create("expenses", {
    name: "Job pressing",
    category: "Pressing",
    amount: 10000,
    date,
    method: "cash",
    sourceId: job.id,
  });
  await act("expenses", expense.id, { action: "finalize" });
  const completed = await act("production", job.id, {
    action: "complete",
    finished: 19,
    rejected: 1,
  });
  assert.equal(completed.data.actualCost, 510000);
  const order = await create("sales", {
    partyId: customer.id,
    date,
    lines: [
      {
        itemId: product.id,
        quantity: 10,
        rate: 65000,
        taxBps: 500,
        taxMode: "split",
      },
    ],
  });
  await act("sales", order.id, { action: "confirm" });
  const dispatchKey = randomUUID();
  await act(
    "sales",
    order.id,
    { action: "dispatch", quantities: [{ itemId: product.id, quantity: 5 }] },
    dispatchKey,
  );
  await act(
    "sales",
    order.id,
    { action: "dispatch", quantities: [{ itemId: product.id, quantity: 5 }] },
    dispatchKey,
  );
  assert.equal((await owner.get("/api/records/challans")).body.total, 1);
  const invoice = await create("invoices", { sourceId: order.id, date });
  const finalized = await act("invoices", invoice.id, { action: "finalize" });
  assert.equal(finalized.data.total, 682500);
  assert.match(finalized.data.number, /INV\/2026-27\/00001/);
  const duplicateInvoice = await create("invoices", {
    sourceId: order.id,
    date,
  });
  assert.equal(
    (
      await post(owner, `/records/invoices/${duplicateInvoice.id}/actions`, {
        action: "finalize",
      })
    ).status,
    400,
  );
  const payment = await create("payments", {
    partyId: customer.id,
    date,
    amount: 200000,
    flow: "receipt",
    method: "bank",
    reference: "BANK-001",
    allocations: [{ invoiceId: invoice.id, amount: 200000 }],
  });
  const paymentKey = randomUUID();
  await act("payments", payment.id, { action: "finalize" }, paymentKey);
  await act("payments", payment.id, { action: "finalize" }, paymentKey);
  const stored = (await owner.get("/api/records/invoices/" + invoice.id)).body;
  assert.equal(stored.data.paid, 200000);
  assert.equal(
    (
      await post(owner, `/records/invoices/${invoice.id}/actions`, {
        action: "reverse",
        reason: "Correct invoice",
      })
    ).status,
    400,
    "allocated invoice cannot be reversed",
  );
  const overpayment = await create("payments", {
    partyId: customer.id,
    date,
    amount: 600000,
    flow: "receipt",
    method: "cash",
    reference: "TOO-MUCH",
    allocations: [{ invoiceId: invoice.id, amount: 600000 }],
  });
  assert.equal(
    (
      await post(owner, `/records/payments/${overpayment.id}/actions`, {
        action: "finalize",
      })
    ).status,
    400,
  );
  await act("payments", payment.id, {
    action: "reverse",
    reason: "Bank receipt entered against wrong invoice",
  });
  assert.equal(
    (await owner.get("/api/records/invoices/" + invoice.id)).body.data.paid,
    0,
  );
  const balances = (await owner.get("/api/stock")).body.data;
  assert.equal(
    balances.find(
      (x: { _id: { itemId: string } }) => x._id.itemId === fabric.id,
    ).quantity,
    60,
  );
  assert.equal(
    balances.find(
      (x: { _id: { itemId: string } }) => x._id.itemId === product.id,
    ).quantity,
    14,
  );
  const trial = (await owner.get("/api/reports/trial-balance")).body.data as {
    debit: number;
    credit: number;
  }[];
  assert.equal(
    trial.reduce((s, l) => s + l.debit, 0),
    trial.reduce((s, l) => s + l.credit, 0),
  );
  assert.equal(
    (await other.get("/api/records/products/" + product.id)).status,
    404,
  );
  assert.equal((await other.get("/api/records/products")).body.total, 0);
  const journalCount = await RecordModel.countDocuments({ kind: "journals" });
  assert.ok(journalCount >= 8);
});
test("CSV export honors filters, tenant and cost permissions across pages", async () => {
  for (let index = 0; index < 23; index++) {
    await create("products", {
      name: index === 0 ? " =CSV verification" : "CSV verification " + index,
      sku: "VERIFY-CSV-" + index,
      cost: 812345,
    });
  }
  const foreign = await post(other, "/records/products", {
    name: "Foreign item",
    sku: "VERIFY-CSV-FOREIGN",
  });
  assert.equal(foreign.status, 201);
  const path = "/api/records/products";
  const filter =
    "?search=VERIFY-CSV&status=active&sort=data.name&direction=asc";
  const page = await owner.get(path + filter);
  assert.equal(page.body.data.length, 20);
  const exported = await owner.get(
    path + "/export.csv" + filter + "&page=2&limit=1",
  );
  assert.equal(exported.status, 200);
  assert.match(
    exported.headers["content-disposition"],
    /attachment.*sellease-products.csv/,
  );
  assert.equal(exported.text.trimEnd().split("\r\n").length, 24);
  assert.match(exported.text, /"'=CSV verification"/);
  assert.match(exported.text, /812345/);
  assert.doesNotMatch(exported.text, /VERIFY-CSV-FOREIGN/);
  assert.equal((await request(app).get(path + "/export.csv")).status, 401);
  assert.equal(
    (await owner.get(path + "/export.csv?from=2026-11-05&to=2026-11-01"))
      .status,
    400,
  );
});
test("authentication, CSRF header and backend roles are enforced", async () => {
  assert.equal((await request(app).get("/api/records/products")).status, 401);
  assert.equal(
    (await owner.post("/api/records/products").send({})).status,
    403,
  );
  assert.equal(
    (
      await post(owner, "/records/products", {
        name: "Invalid",
        sku: "INVALID",
        cost: 1.23,
      })
    ).status,
    400,
  );
  const user = await post(owner, "/users", {
    name: "Sales person",
    email: "sales@example.com",
    password: "another-long-password",
    role: "sales",
  });
  assert.equal(user.status, 201);
  assert.equal(
    (
      await post(sales, "/auth/login", {
        email: "sales@example.com",
        password: "another-long-password",
      })
    ).status,
    200,
  );
  assert.equal(
    (await post(sales, "/records/expenses", { name: "No access" })).status,
    403,
  );
  assert.equal((await sales.get("/api/reports/trial-balance")).status, 403);
  assert.equal((await sales.get("/api/records/audit")).status, 403);
  const exportPath = "/api/records/products/export.csv?search=VERIFY-CSV";
  const safeExport = await sales.get(exportPath);
  assert.equal(safeExport.status, 200);
  assert.match(safeExport.text, /VERIFY-CSV-0/);
  assert.doesNotMatch(safeExport.text, /812345/);
  assert.equal((await sales.get("/api/records/audit/export.csv")).status, 403);
  const me = await owner.get("/api/me");
  assert.equal(
    (
      await owner
        .put("/api/settings")
        .set("X-SellEase", "1")
        .set("Idempotency-Key", randomUUID())
        .send({ ...me.body.settings, name: "Changed", onboarding: undefined })
    ).status,
    200,
  );
});
test("transaction rollback, concurrency and conflicting idempotency keys", async () => {
  const customer = await create("parties", {
    name: "Concurrency customer",
    kind: "customer",
  });
  const product = await create("products", {
    name: "Concurrent SKU",
    sku: "CONCURRENT",
    price: 1000,
  });
  await post(owner, "/stock/adjust", {
    itemId: product.id,
    quantity: 5,
    reason: "Opening count",
    date,
  });
  const make = () =>
    create("sales", {
      partyId: customer.id,
      date,
      lines: [{ itemId: product.id, quantity: 5, rate: 1000 }],
    });
  const a = await make(),
    b = await make();
  await act("sales", a.id, { action: "confirm" });
  await act("sales", b.id, { action: "confirm" });
  const attempts = await Promise.all(
    [a, b].map((o) =>
      post(owner, `/records/sales/${o.id}/actions`, {
        action: "dispatch",
        quantities: [{ itemId: product.id, quantity: 5 }],
      }),
    ),
  );
  assert.deepEqual(attempts.map((r) => r.status).sort(), [200, 409]);
  const key = randomUUID();
  const one = await post(owner, "/records/categories", { name: "One" }, key);
  assert.equal(one.status, 201);
  const two = await post(owner, "/records/categories", { name: "Two" }, key);
  assert.equal(two.status, 409);
  const invs = await Promise.all(
    [a, b].map((o) => create("invoices", { sourceId: o.id, date })),
  );
  const results = await Promise.all(
    invs.map((i) =>
      post(owner, `/records/invoices/${i.id}/actions`, { action: "finalize" }),
    ),
  );
  assert.ok(
    results.every((r) => r.status === 200),
    JSON.stringify(results.map((r) => r.body)),
  );
  assert.notEqual(results[0].body.data.number, results[1].body.data.number);
});
test("partial supplier billing, proportional discounts, payment allocation and reversal", async () => {
  const supplier = await create("parties", {
    name: "Billing supplier",
    kind: "supplier",
  });
  const material = await create("materials", {
    name: "Supplier billed material",
    sku: "BILL-MAT",
    unit: "metre",
    cost: 1000,
  });
  const po = await create("purchases", {
    partyId: supplier.id,
    date,
    lines: [
      {
        itemId: material.id,
        quantity: 3,
        rate: 1000,
        discount: 100,
        taxBps: 500,
        taxMode: "split",
      },
    ],
  });
  await act("purchases", po.id, { action: "confirm" });
  await act("purchases", po.id, {
    action: "receive",
    quantities: [{ itemId: material.id, quantity: 1 }],
  });
  const bill = await create("supplierInvoices", {
    sourceId: po.id,
    date,
    reference: "SUP-001",
  });
  assert.equal(bill.data.total, 1015);
  await act("supplierInvoices", bill.id, { action: "finalize" });
  const payment = await create("payments", {
    partyId: supplier.id,
    amount: 500,
    date,
    method: "bank",
    flow: "payment",
    reference: "SUP-BANK-001",
    allocations: [{ invoiceId: bill.id, amount: 500 }],
  });
  await act("payments", payment.id, { action: "finalize" });
  assert.equal(
    (await owner.get("/api/records/supplierInvoices/" + bill.id)).body.data
      .paid,
    500,
  );
  assert.equal(
    (
      await post(owner, `/records/supplierInvoices/${bill.id}/actions`, {
        action: "reverse",
        reason: "Correction",
      })
    ).status,
    400,
  );
  await act("payments", payment.id, {
    action: "reverse",
    reason: "Payment correction",
  });
  await act("supplierInvoices", bill.id, {
    action: "reverse",
    reason: "Supplier bill correction",
  });
  assert.equal(
    (await owner.get("/api/records/purchases/" + po.id)).body.data.lines[0]
      .invoiced,
    0,
  );
  await act("purchases", po.id, {
    action: "receive",
    quantities: [{ itemId: material.id, quantity: 2 }],
  });
  const newBill = await create("supplierInvoices", {
    sourceId: po.id,
    date,
    reference: "SUP-002",
  });
  assert.equal(newBill.data.total, 3045);
  await act("supplierInvoices", newBill.id, { action: "finalize" });
  const stock = (await owner.get("/api/stock")).body.data.find(
    (s: { _id: { itemId: string } }) => s._id.itemId === material.id,
  );
  assert.equal(stock.value, 2900);
  const grni = (
    await owner.get(
      "/api/reports/ledger?account=Goods%20received%20not%20invoiced&partyId=" +
        supplier.id,
    )
  ).body;
  assert.equal(grni.closing, 0);
});
test("warehouse transfers preserve total quantity/value and contractor returns do not duplicate stock", async () => {
  const material = await create("materials", {
    name: "Transfer material",
    sku: "TRANSFER-MAT",
    cost: 100,
  });
  const product = await create("products", {
    name: "Jobwork output",
    sku: "JOBWORK-OUT",
    cost: 300,
  });
  const warehouse = await create("warehouses", { name: "Annex" });
  const contractor = await create("parties", {
    name: "Stitching contractor",
    kind: "contractor",
  });
  await post(owner, "/stock/adjust", {
    itemId: material.id,
    quantity: 20,
    reason: "Opening stock count",
    date,
  });
  const transfer = await post(owner, "/stock/transfer", {
    itemId: material.id,
    quantity: 5,
    sourceWarehouseId: "default",
    destinationWarehouseId: warehouse.id,
    reason: "Move to annex",
    date,
  });
  assert.equal(transfer.status, 200);
  const stock = (await owner.get("/api/stock")).body.data.filter(
    (s: { _id: { itemId: string } }) => s._id.itemId === material.id,
  ) as { quantity: number; value: number }[];
  assert.equal(
    stock.reduce((s, r) => s + r.quantity, 0),
    20,
  );
  assert.equal(
    stock.reduce((s, r) => s + r.value, 0),
    2000,
  );
  const job = await create("production", {
    name: "Outsourced batch",
    outputItemId: product.id,
    quantity: 5,
    date,
    materialLines: [{ itemId: material.id, quantity: 10 }],
  });
  await act("production", job.id, { action: "issue" });
  const work = await create("jobwork", {
    name: "Stitching",
    sourceId: job.id,
    partyId: contractor.id,
    quantity: 5,
    rate: 50,
    date,
  });
  await act("jobwork", work.id, { action: "issue" });
  assert.equal(
    (
      await post(owner, `/records/production/${job.id}/actions`, {
        action: "complete",
        finished: 5,
        rejected: 0,
      })
    ).status,
    400,
  );
  await act("jobwork", work.id, {
    action: "receive",
    finished: 3,
    rejected: 0,
  });
  await act("jobwork", work.id, {
    action: "receive",
    finished: 1,
    rejected: 1,
  });
  const finished = await act("production", job.id, {
    action: "complete",
    finished: 4,
    rejected: 1,
  });
  assert.equal(finished.data.actualCost, 1200);
  const ledger = (
    await owner.get(
      "/api/reports/ledger?account=Accounts%20payable&partyId=" + contractor.id,
    )
  ).body;
  assert.equal(ledger.closing, -200);
});
test("draft manual journals are excluded from financial reports", async () => {
  const draft = await create("journals", {
    description: "Opening capital worksheet",
    date,
    journalLines: [
      { account: "Test cash", debit: 999, credit: 0 },
      { account: "Test capital", debit: 0, credit: 999 },
    ],
  });
  let trial = (await owner.get("/api/reports/trial-balance")).body.data;
  assert.ok(!trial.some((r: { _id: string }) => r._id === "Test cash"));
  await act("journals", draft.id, { action: "finalize" });
  trial = (await owner.get("/api/reports/trial-balance")).body.data;
  assert.equal(
    trial.find((r: { _id: string }) => r._id === "Test cash").debit,
    999,
  );
});
test("failed multi-material issue rolls back all movements; tenant mutations and stale edits are rejected", async () => {
  const first = await create("materials", {
    name: "Rollback material A",
    sku: "ROLLBACK-A",
    cost: 10,
  });
  const missing = await create("materials", {
    name: "Rollback material B",
    sku: "ROLLBACK-B",
    cost: 10,
  });
  const output = await create("products", {
    name: "Rollback output",
    sku: "ROLLBACK-OUT",
  });
  await post(owner, "/stock/adjust", {
    itemId: first.id,
    quantity: 10,
    reason: "Test opening stock",
    date,
  });
  const job = await create("production", {
    name: "Rollback job",
    outputItemId: output.id,
    quantity: 2,
    date,
    materialLines: [
      { itemId: first.id, quantity: 2 },
      { itemId: missing.id, quantity: 2 },
    ],
  });
  const before = await RecordModel.countDocuments({ kind: "movements" });
  const r = await post(owner, `/records/production/${job.id}/actions`, {
    action: "issue",
  });
  assert.equal(r.status, 409);
  assert.equal(await RecordModel.countDocuments({ kind: "movements" }), before);
  assert.equal(
    (await owner.get("/api/records/production/" + job.id)).body.data.status,
    "draft",
  );
  const category = await create("categories", { name: "Original category" });
  const update = (agent: typeof owner, version: number, name: string) =>
    agent
      .put("/api/records/categories/" + category.id)
      .set("X-SellEase", "1")
      .set("Idempotency-Key", randomUUID())
      .send({ version, data: { name, status: "active", description: "" } });
  assert.equal((await update(other, 1, "Attack")).status, 404);
  assert.equal((await update(owner, 1, "Updated")).status, 200);
  assert.equal((await update(owner, 1, "Stale")).status, 409);
});
test("public catalog uses an explicit allowlist and finalized documents retain snapshots", async () => {
  const product = await create("products", {
    name: "Public catalog item",
    sku: "PUBLIC-SKU",
    cost: 12345,
    price: 20000,
    published: true,
  });
  const me = (await owner.get("/api/me")).body;
  const settings = { ...me.settings, catalogEnabled: true };
  delete settings.onboarding;
  assert.equal(
    (
      await owner
        .put("/api/settings")
        .set("X-SellEase", "1")
        .set("Idempotency-Key", randomUUID())
        .send(settings)
    ).status,
    200,
  );
  const catalog = await request(app).get("/api/catalog/" + me.user.org);
  assert.equal(catalog.status, 200);
  assert.equal(
    catalog.body.items.find((p: { id: string }) => p.id === product.id).cost,
    undefined,
  );
  assert.equal(
    catalog.body.items.find((p: { id: string }) => p.id === product.id).org,
    undefined,
  );
  const customer = await create("parties", {
    name: "Original customer",
    kind: "customer",
    address: "Original address",
  });
  const order = await create("sales", {
    partyId: customer.id,
    date,
    lines: [{ itemId: product.id, quantity: 1, rate: 20000 }],
  });
  await act("sales", order.id, { action: "confirm" });
  const invoice = await create("invoices", { sourceId: order.id, date });
  await act("invoices", invoice.id, { action: "finalize" });
  const p = { ...product.data, name: "Renamed later" };
  await owner
    .put("/api/records/products/" + product.id)
    .set("X-SellEase", "1")
    .set("Idempotency-Key", randomUUID())
    .send({ version: product.version, data: p });
  const final = (await owner.get("/api/records/invoices/" + invoice.id)).body;
  assert.equal(final.data.lines[0].name, "Public catalog item");
  assert.equal(final.data.partySnapshot.name, "Original customer");
  assert.equal(
    (
      await owner
        .put("/api/records/invoices/" + invoice.id)
        .set("X-SellEase", "1")
        .set("Idempotency-Key", randomUUID())
        .send({ version: final.version, data: { total: 1 } })
    ).status,
    400,
  );
});
test("password reset requires an expiring single-use token and revokes existing sessions", async () => {
  const agent = request.agent(app);
  const email = "reset@example.com";
  assert.equal(
    (
      await post(agent, "/auth/register", {
        name: "Reset QA",
        businessName: "Reset QA",
        email,
        password: "first-long-password",
      })
    ).status,
    201,
  );
  const token = "a".repeat(64);
  await User.updateOne(
    { email },
    {
      $set: {
        resetHash: hash(token),
        resetExpires: new Date(Date.now() + 60000),
      },
    },
  );
  assert.equal(
    (
      await post(agent, "/auth/reset", {
        token: "b".repeat(64),
        password: "second-long-password",
      })
    ).status,
    400,
  );
  assert.equal(
    (
      await post(agent, "/auth/reset", {
        token,
        password: "second-long-password",
      })
    ).status,
    200,
  );
  assert.equal((await agent.get("/api/me")).status, 401);
  assert.equal(
    (
      await post(agent, "/auth/reset", {
        token,
        password: "third-long-password",
      })
    ).status,
    400,
  );
  assert.equal(
    (
      await post(agent, "/auth/login", {
        email,
        password: "second-long-password",
      })
    ).status,
    200,
  );
});
test("fractional fabric quantities reconcile exactly through partial receipts and material issues", async () => {
  const supplier = await create("parties", {
    name: "Fractional fabric supplier",
    kind: "supplier",
  });
  const fabric = await create("materials", {
    name: "Measured fabric",
    sku: "FRACTION-M",
    unit: "metre",
    cost: 10000,
  });
  const output = await create("products", {
    name: "Measured output",
    sku: "FRACTION-OUT",
  });
  const po = await create("purchases", {
    partyId: supplier.id,
    date,
    lines: [{ itemId: fabric.id, quantity: 0.3, rate: 10000 }],
  });
  await act("purchases", po.id, { action: "confirm" });
  await act("purchases", po.id, {
    action: "receive",
    quantities: [{ itemId: fabric.id, quantity: 0.1 }],
  });
  await act("purchases", po.id, {
    action: "receive",
    quantities: [{ itemId: fabric.id, quantity: 0.2 }],
  });
  const job = await create("production", {
    name: "Measured batch",
    outputItemId: output.id,
    quantity: 1,
    date,
    materialLines: [{ itemId: fabric.id, quantity: 0.3 }],
  });
  await act("production", job.id, { action: "issue" });
  const stock = (await owner.get("/api/stock")).body.data.find(
    (s: { _id: { itemId: string } }) => s._id.itemId === fabric.id,
  );
  assert.equal(stock.quantity, 0);
  assert.equal(stock.value, 0);
  await act("production", job.id, {
    action: "return",
    quantities: [{ itemId: fabric.id, quantity: 0.1 }],
  });
  const cut = await create("cutting", {
    name: "Fractional cutting",
    sourceId: job.id,
    itemId: fabric.id,
    quantity: 0.1,
    date,
    sizes: [{ size: "L", color: "Navy", planned: 1, actual: 1, rejected: 0 }],
  });
  await act("cutting", cut.id, { action: "confirm" });
  assert.equal(
    (
      await post(owner, `/records/production/${job.id}/actions`, {
        action: "return",
        quantities: [{ itemId: fabric.id, quantity: 0.2 }],
      })
    ).status,
    400,
  );
  const finished = await act("production", job.id, {
    action: "complete",
    finished: 1,
    rejected: 0,
  });
  assert.equal(finished.data.actualCost, 2000);
  assert.equal(
    (
      await post(owner, "/stock/adjust", {
        itemId: fabric.id,
        quantity: 0.0001,
        date,
        reason: "Too precise",
      })
    ).status,
    400,
  );
  assert.equal(
    (
      await post(owner, "/stock/adjust", {
        itemId: output.id,
        quantity: 0.5,
        date,
        reason: "Fractional piece",
      })
    ).status,
    400,
  );
});
test("customer return → credit note → refund is source-linked, bounded, reversible and retry-safe", async () => {
  const customer = await create("parties", {
    name: "Return customer",
    kind: "customer",
  });
  const item = await create("products", {
    name: "Return SKU",
    sku: "RETURN-SKU",
    price: 1000,
    cost: 500,
  });
  await post(owner, "/stock/adjust", {
    itemId: item.id,
    quantity: 10,
    reason: "Opening count",
    date,
  });
  const order = await create("sales", {
    partyId: customer.id,
    date,
    lines: [
      {
        itemId: item.id,
        quantity: 10,
        rate: 1000,
        taxBps: 500,
        taxMode: "split",
      },
    ],
  });
  await act("sales", order.id, { action: "confirm" });
  await act("sales", order.id, {
    action: "dispatch",
    quantities: [{ itemId: item.id, quantity: 10 }],
  });
  const challan = (await owner.get("/api/records/challans")).body.data.find(
    (c: Entry) => c.data.sourceId === order.id,
  );
  const invoice = await create("invoices", { sourceId: order.id, date });
  await act("invoices", invoice.id, { action: "finalize" });
  const receipt = await create("payments", {
    partyId: customer.id,
    amount: 10500,
    date,
    method: "bank",
    flow: "receipt",
    reference: "RETURN-PAID",
    allocations: [{ invoiceId: invoice.id, amount: 10500 }],
  });
  await act("payments", receipt.id, { action: "finalize" });
  const physical = await create("customerReturns", {
    sourceId: challan.id,
    date,
    reason: "Customer returned two pieces",
    quantities: [{ itemId: item.id, quantity: 2 }],
  });
  const returnKey = randomUUID();
  await act("customerReturns", physical.id, { action: "finalize" }, returnKey);
  await act("customerReturns", physical.id, { action: "finalize" }, returnKey);
  assert.equal(
    (await owner.get("/api/stock")).body.data.find(
      (s: { _id: { itemId: string } }) => s._id.itemId === item.id,
    ).quantity,
    2,
  );
  const note = await create("creditNotes", {
    sourceId: invoice.id,
    returnId: physical.id,
    date,
    reason: "Credit for accepted return",
    quantities: [{ itemId: item.id, quantity: 2 }],
  });
  const posted = await act("creditNotes", note.id, { action: "finalize" });
  assert.equal(posted.data.total, 2100);
  assert.equal(
    (await owner.get("/api/records/invoices/" + invoice.id)).body.data.credited,
    2100,
  );
  const excessive = await create("payments", {
    partyId: customer.id,
    amount: 2101,
    date,
    method: "bank",
    flow: "customer_refund",
    sourceId: note.id,
    reference: "REFUND-TOO-MUCH",
    allocations: [],
  });
  assert.equal(
    (
      await post(owner, `/records/payments/${excessive.id}/actions`, {
        action: "finalize",
      })
    ).status,
    400,
  );
  const refund = await create("payments", {
    partyId: customer.id,
    amount: 2100,
    date,
    method: "bank",
    flow: "customer_refund",
    sourceId: note.id,
    reference: "REFUND-OK",
    allocations: [],
  });
  const refundKey = randomUUID();
  await act("payments", refund.id, { action: "finalize" }, refundKey);
  await act("payments", refund.id, { action: "finalize" }, refundKey);
  assert.equal(
    (await owner.get("/api/records/invoices/" + invoice.id)).body.data.refunded,
    2100,
  );
  assert.equal(
    (
      await post(owner, `/records/creditNotes/${note.id}/actions`, {
        action: "reverse",
        reason: "Correction",
      })
    ).status,
    400,
  );
  await act("payments", refund.id, {
    action: "reverse",
    reason: "Refund correction",
  });
  await act("creditNotes", note.id, {
    action: "reverse",
    reason: "Credit note correction",
  });
  assert.equal(
    (await owner.get("/api/records/invoices/" + invoice.id)).body.data.credited,
    0,
  );
  assert.equal(
    (await owner.get("/api/records/customerReturns/" + physical.id)).body.data
      .noted,
    false,
  );
  assert.equal(
    (await other.get("/api/records/customerReturns/" + physical.id)).status,
    404,
  );
  const salesReturn = await post(sales, "/records/customerReturns", {
    sourceId: challan.id,
    date,
    reason: "Sales return with protected cost snapshot",
    quantities: [{ itemId: item.id, quantity: 1 }],
  });
  assert.equal(salesReturn.status, 201);
  assert.equal(salesReturn.body.data.lines[0].costValue, undefined);
  const salesPosted = await post(
    sales,
    `/records/customerReturns/${salesReturn.body.id}/actions`,
    { action: "finalize" },
  );
  assert.equal(salesPosted.status, 200);
  assert.equal(salesPosted.body.data.value, undefined);
  assert.equal(salesPosted.body.data.lines[0].costValue, undefined);
});
test("billed supplier returns and matched debit notes clear inventory and supplier liability exactly once", async () => {
  const supplier = await create("parties", {
    name: "Return supplier",
    kind: "supplier",
  });
  const item = await create("materials", {
    name: "Supplier return lot",
    sku: "SUP-RETURN",
    cost: 1000,
  });
  const po = await create("purchases", {
    partyId: supplier.id,
    date,
    lines: [
      {
        itemId: item.id,
        quantity: 5,
        rate: 1000,
        taxBps: 500,
        taxMode: "split",
      },
    ],
  });
  await act("purchases", po.id, { action: "confirm" });
  await act("purchases", po.id, {
    action: "receive",
    quantities: [{ itemId: item.id, quantity: 5 }],
  });
  const bill = await create("supplierInvoices", {
    sourceId: po.id,
    date,
    reference: "BILL-RETURN",
  });
  await act("supplierInvoices", bill.id, { action: "finalize" });
  const physical = await create("supplierReturns", {
    sourceId: po.id,
    date,
    reason: "Supplier accepted defective goods",
    quantities: [{ itemId: item.id, quantity: 2 }],
  });
  await act("supplierReturns", physical.id, { action: "finalize" });
  const note = await create("debitNotes", {
    sourceId: bill.id,
    returnId: physical.id,
    date,
    reason: "Recover price for returned goods",
    quantities: [{ itemId: item.id, quantity: 2 }],
  });
  await act("debitNotes", note.id, { action: "finalize" });
  const ledger = (
    await owner.get("/api/reports/ledger?account=Supplier%20returns%20clearing")
  ).body;
  assert.equal(ledger.closing, 0);
  assert.equal(
    (await owner.get("/api/stock")).body.data.find(
      (s: { _id: { itemId: string } }) => s._id.itemId === item.id,
    ).quantity,
    3,
  );
  assert.equal(
    (await owner.get("/api/records/supplierInvoices/" + bill.id)).body.data
      .credited,
    2100,
  );
  const tooMany = await post(owner, "/records/debitNotes", {
    sourceId: bill.id,
    date,
    reason: "Excess credit",
    quantities: [{ itemId: item.id, quantity: 4 }],
  });
  assert.equal(tooMany.status, 400);
  assert.equal(
    (
      await post(owner, "/records/debitNotes", {
        sourceId: bill.id,
        returnId: physical.id,
        date,
        reason: "Duplicate return match",
        quantities: [{ itemId: item.id, quantity: 2 }],
      })
    ).status,
    400,
  );
});
test("classified financial statements balance and period locks reject backdated posting without losing setup changes", async () => {
  const agent = request.agent(app);
  assert.equal(
    (
      await post(agent, "/auth/register", {
        name: "Accounting owner",
        businessName: "Accounting test",
        email: "accounting@example.test",
        password: "accounting-long-password",
      })
    ).status,
    201,
  );
  const journal = await post(agent, "/records/journals", {
    description: "Capital and service income",
    date,
    journalLines: [
      { account: "Cash", debit: 11000, credit: 0 },
      { account: "Owner contributions", debit: 0, credit: 10000 },
      { account: "Service revenue", debit: 0, credit: 1000 },
    ],
  });
  assert.equal(journal.status, 201);
  assert.equal(
    (
      await post(agent, `/records/journals/${journal.body.id}/actions`, {
        action: "finalize",
      })
    ).status,
    200,
  );
  let report = (await agent.get("/api/reports/financial")).body;
  assert.equal(report.classified, false);
  assert.ok(report.unclassified.includes("Service revenue"));
  assert.equal(
    (
      await post(agent, "/records/accounts", {
        name: "Owner contributions",
        accountType: "equity",
      })
    ).status,
    201,
  );
  assert.equal(
    (
      await post(agent, "/records/accounts", {
        name: "Service revenue",
        accountType: "revenue",
      })
    ).status,
    201,
  );
  assert.equal(
    (
      await post(agent, "/records/accounts", {
        name: "Cash",
        accountType: "expense",
      })
    ).status,
    400,
  );
  report = (await agent.get("/api/reports/financial")).body;
  assert.equal(report.classified, true);
  assert.equal(report.profitAndLoss.profit, 1000);
  assert.equal(report.balanceSheet.assets, 11000);
  assert.equal(report.balanceSheet.totalEquity, 11000);
  assert.equal(report.balanceSheet.difference, 0);
  const draft = await post(agent, "/records/expenses", {
    name: "Pending expense",
    category: "Rent",
    amount: 100,
    date,
    method: "cash",
  });
  assert.equal(draft.status, 201);
  assert.equal(
    (await post(agent, "/accounting/close", { through: date })).status,
    409,
  );
  assert.equal(
    (
      await post(agent, `/records/expenses/${draft.body.id}/actions`, {
        action: "void",
      })
    ).status,
    200,
  );
  assert.equal(
    (await post(agent, "/accounting/close", { through: date })).status,
    200,
  );
  const late = await post(agent, "/records/journals", {
    description: "Late period adjustment",
    date,
    journalLines: [
      { account: "Cash", debit: 100, credit: 0 },
      { account: "Capital", debit: 0, credit: 100 },
    ],
  });
  assert.equal(
    (
      await post(agent, `/records/journals/${late.body.id}/actions`, {
        action: "finalize",
      })
    ).status,
    409,
  );
  assert.equal(
    (
      await post(agent, `/records/journals/${late.body.id}/actions`, {
        action: "finalize",
        postingDate: "2026-11-04",
      })
    ).status,
    200,
  );
  const me = (await agent.get("/api/me")).body;
  const settings = { ...me.settings, name: "Updated accounting business" };
  delete settings.onboarding;
  delete settings.closedThrough;
  assert.equal(
    (
      await agent
        .put("/api/settings")
        .set("X-SellEase", "1")
        .set("Idempotency-Key", randomUUID())
        .send(settings)
    ).status,
    200,
  );
  assert.equal((await agent.get("/api/me")).body.settings.closedThrough, date);
  assert.equal(
    (await post(agent, "/accounting/close", { through: "2026-11-02" })).status,
    400,
  );
  assert.equal((await sales.get("/api/reports/financial")).status, 403);
});
test("partial credit-note reversal preserves every remaining tax component and minor unit", async () => {
  const customer = await create("parties", {
    name: "Rounding customer",
    kind: "customer",
  });
  const item = await create("products", {
    name: "Minor-unit source",
    sku: "CREDIT-ROUND",
  });
  const order = await create("sales", {
    partyId: customer.id,
    date,
    lines: [
      {
        itemId: item.id,
        quantity: 2,
        rate: 10,
        taxBps: 1000,
        taxMode: "split",
      },
    ],
  });
  await act("sales", order.id, { action: "confirm" });
  const invoice = await create("invoices", { sourceId: order.id, date });
  await act("invoices", invoice.id, { action: "finalize" });
  const make = () =>
    create("creditNotes", {
      sourceId: invoice.id,
      date,
      reason: "Partial price credit",
      quantities: [{ itemId: item.id, quantity: 1 }],
    });
  const first = await make();
  await act("creditNotes", first.id, { action: "finalize" });
  const second = await make();
  await act("creditNotes", second.id, { action: "finalize" });
  await act("creditNotes", first.id, {
    action: "reverse",
    reason: "Reissue earlier partial note",
  });
  const replacement = await make();
  await act("creditNotes", replacement.id, { action: "finalize" });
  const saved = (await owner.get("/api/records/invoices/" + invoice.id)).body;
  assert.equal(saved.data.credited, saved.data.total);
  assert.equal(saved.data.lines[0].creditedCgst, 1);
  assert.equal(saved.data.lines[0].creditedSgst, 1);
  assert.equal(saved.data.lines[0].creditedGross, 20);
});
test("invoice ageing uses historical journal effects rather than current payment counters", async () => {
  const customer = await create("parties", {
    name: "Ageing customer",
    kind: "customer",
  });
  const item = await create("materials", {
    name: "Ageing material",
    sku: "AGE-METRE",
    unit: "metre",
  });
  const order = await create("sales", {
    partyId: customer.id,
    date: "2026-09-01",
    lines: [{ itemId: item.id, quantity: 1, rate: 10000 }],
  });
  await act("sales", order.id, { action: "confirm" });
  const invoice = await create("invoices", {
    sourceId: order.id,
    date: "2026-09-01",
    dueDate: "2026-09-15",
  });
  await act("invoices", invoice.id, { action: "finalize" });
  const payment = await create("payments", {
    partyId: customer.id,
    date: "2026-10-01",
    amount: 2500,
    method: "bank",
    flow: "receipt",
    reference: "AGE-PARTIAL",
    allocations: [{ invoiceId: invoice.id, amount: 2500 }],
  });
  await act("payments", payment.id, { action: "finalize" });
  const credit = await create("creditNotes", {
    sourceId: invoice.id,
    date: "2026-10-15",
    reason: "Approved partial credit",
    quantities: [{ itemId: item.id, quantity: 0.1 }],
  });
  await act("creditNotes", credit.id, { action: "finalize" });
  await act("payments", payment.id, {
    action: "reverse",
    postingDate: "2026-11-05",
    reason: "Later payment reversal",
  });
  const before = (
    await owner.get("/api/reports/ageing?asOf=2026-11-04")
  ).body.data.find(
    (row: { invoiceId: string }) => row.invoiceId === invoice.id,
  );
  assert.equal(before.amount, 6500);
  assert.equal(before.daysOverdue, 50);
  assert.equal(before.bucket, "31–60");
  const after = (
    await owner.get("/api/reports/ageing?asOf=2026-11-06")
  ).body.data.find(
    (row: { invoiceId: string }) => row.invoiceId === invoice.id,
  );
  assert.equal(after.amount, 9000);
  assert.equal((await sales.get("/api/reports/ageing")).status, 403);
  assert.ok(
    !(await other.get("/api/reports/ageing")).body.data.some(
      (row: { invoiceId: string }) => row.invoiceId === invoice.id,
    ),
  );
});
test("currency and financial-year changes cannot relabel existing money or numbered documents", async () => {
  const me = (await owner.get("/api/me")).body;
  const settings = { ...me.settings };
  delete settings.onboarding;
  delete settings.closedThrough;
  const update = (body: unknown) =>
    owner
      .put("/api/settings")
      .set("X-SellEase", "1")
      .set("Idempotency-Key", randomUUID())
      .send(body as object);
  assert.equal((await update({ ...settings, currency: "USD" })).status, 409);
  assert.equal(
    (await update({ ...settings, financialYearStart: 1 })).status,
    409,
  );
  assert.equal((await owner.get("/api/me")).body.settings.currency, "INR");
});
test("fractional purchase receipts and reversed partial bills preserve order value down to the minor unit", async () => {
  const supplier = await create("parties", {
    name: "Minor-unit supplier",
    kind: "supplier",
  });
  const material = await create("materials", {
    name: "Fractional valued lot",
    sku: "ROUND-RECEIPT",
    unit: "metre",
  });
  const order = await create("purchases", {
    partyId: supplier.id,
    date,
    lines: [{ itemId: material.id, quantity: 1.5, rate: 1 }],
  });
  await act("purchases", order.id, { action: "confirm" });
  const billTotals: number[] = [];
  for (let i = 0; i < 3; i++) {
    await act("purchases", order.id, {
      action: "receive",
      quantities: [{ itemId: material.id, quantity: 0.5 }],
    });
    const bill = await create("supplierInvoices", {
      sourceId: order.id,
      date,
      reference: "ROUND-FRACTION-" + i,
    });
    billTotals.push(bill.data.total);
    await act("supplierInvoices", bill.id, { action: "finalize" });
  }
  assert.deepEqual(billTotals, [1, 0, 1]);
  const balance = (await owner.get("/api/stock")).body.data.find(
    (s: { _id: { itemId: string } }) => s._id.itemId === material.id,
  );
  assert.equal(balance.quantity, 1.5);
  assert.equal(balance.value, 2);
  const otherMaterial = await create("materials", {
    name: "Discount remainder lot",
    sku: "ROUND-DISCOUNT",
    unit: "metre",
  });
  const discounted = await create("purchases", {
    partyId: supplier.id,
    date,
    lines: [{ itemId: otherMaterial.id, quantity: 3, rate: 10, discount: 1 }],
  });
  await act("purchases", discounted.id, { action: "confirm" });
  const bills = [];
  for (let i = 0; i < 3; i++) {
    await act("purchases", discounted.id, {
      action: "receive",
      quantities: [{ itemId: otherMaterial.id, quantity: 1 }],
    });
    const bill = await create("supplierInvoices", {
      sourceId: discounted.id,
      date,
      reference: "ROUND-DISCOUNT-" + i,
    });
    await act("supplierInvoices", bill.id, { action: "finalize" });
    bills.push(bill);
  }
  assert.deepEqual(
    bills.map((b) => b.data.total),
    [10, 9, 10],
  );
  await act("supplierInvoices", bills[1].id, {
    action: "reverse",
    reason: "Reissue middle partial bill",
  });
  const replacement = await create("supplierInvoices", {
    sourceId: discounted.id,
    date,
    reference: "ROUND-REPLACEMENT",
  });
  assert.equal(replacement.data.total, 9);
  await act("supplierInvoices", replacement.id, { action: "finalize" });
  const ledger = (
    await owner.get(
      "/api/reports/ledger?account=Goods%20received%20not%20invoiced&partyId=" +
        supplier.id,
    )
  ).body;
  assert.equal(ledger.closing, 0);
});
