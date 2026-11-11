# Domain and posting model

## Storage

Identity, Organization, Session, Idempotency and Sequence are separate Mongoose models. BusinessRecord stores typed, server-validated document data by organization and kind. Each record has a UUID, organization, kind, version and timestamps. Zod validates each supported command before persistence. The generic collection is a deliberate early-stage module implementation; it is not a license to accept arbitrary client JSON.

Indexes cover organization/kind/ID uniqueness, organization/kind/SKU uniqueness for item masters, creation-date lists, global identity email, session hash/expiry, organization/idempotency key and organization/sequence scope. Additional workload-specific indexes and query profiling are required before large-data release.

## Entities and relationships

- Organization owns settings and serializes critical writes through its revision document.
- Identity belongs to one organization and has an owner/admin/accountant/sales/purchasing/production/inventory/staff role. Staff directory records are distinct from login identities.
- Product is a finished SKU with style/color/size; Material is a separately tracked material or fabric lot. Their stock comes from movements, not a mutable quantity field.
- Party has customer/supplier/both/contractor relationship and business details. Warehouse identifies a location; `default` is the initial location.
- Purchase order references a supplier and item lines with received and invoiced counters. Goods receipt creates source-linked movements and a receipt document. Supplier invoice matches received, unbilled quantities and records the supplier reference.
- Production job references an output SKU, material requirements, configured stages and explicit additional cost lines. Cutting plan references a job/material and an editable size matrix. Contractor job work references an open job and contractor with issued/returned/accepted/rejected quantities and rate.
- Sales order references a customer and item lines with dispatched/invoiced counters. Each dispatch creates a delivery challan and source-linked negative stock movements.
- Customer invoice and supplier invoice reference their orders. Finalization snapshots business, party and item descriptions; later master-data changes do not rewrite historical document identity.
- Payment references a party and zero or more invoice allocations, with direction determining receivable/payable treatment.
- Expense references a category, optional party/job and cash/bank settlement.
- Journal contains balanced debit/credit lines, optional party dimensions and source document. All statements derive from posted journals, including reversal entries.
- Support tickets and audit records are organization scoped. Catalog returns an allowlist of published product fields only.

## State transitions

| Document                  | Allowed transitions and effects                                                                                                     |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Purchase/sales order      | draft → confirmed; drafts can be voided. Receipt/dispatch adds cumulative counters within confirmed state.                          |
| Purchase receipt          | Created on receiving specified quantities, bounded by remaining ordered quantity.                                                   |
| Customer/supplier invoice | draft → posted → reversed; paid allocations must first be reversed. Financial values cannot be updated through master-data editing. |
| Production                | draft → in_progress on material issue → completed on reconciled accepted/rejected output. Stages advance while in progress.         |
| Cutting                   | draft → confirmed, bounded by previously issued job material and prior confirmed cutting consumption. No second stock issue.        |
| Contractor work           | draft → in_progress on assignment → completed when all assigned quantities are returned. No independent finished-stock posting.     |
| Expense/payment           | draft → posted → reversed. Reversal preserves original journal and posts opposite lines.                                            |
| Manual journal            | draft → posted. Draft journals are excluded from financial reports. Manual journal reversal is not yet exposed.                     |
| Challan                   | dispatched → delivered on acknowledgement. Acknowledgement does not touch stock.                                                    |
| Ticket                    | open → closed.                                                                                                                      |
| Master data               | active → archived through validated, version-checked updates.                                                                       |

## Transaction boundaries

Every business mutation starts a MongoDB session/transaction, updates the organization's revision document, checks the idempotency record, executes validated business operations, appends audit metadata and stores its result under the idempotency key. MongoDB retries transient conflicts. The revision write serializes operations within an organization, preventing two dispatches from both observing the same available stock or two invoices consuming the same uninvoiced quantity.

This favors correctness over high write throughput. Before horizontal high-volume release, replace coarse organization serialization with tested, conditional per-balance/document updates and preserve transactional invariants. Transactions require a replica set. There is no unsafe standalone-MongoDB fallback.

## Monetary and valuation rules

Money is integer minor units with two decimal places. Supported currency configuration is INR/USD/EUR/GBP/AUD/CAD/SGD/AED. Quantities support three decimal places, with stock movements storing an authoritative integer quantityMilli. Multiplication and addition reject unsafe integer results. Tax ratios use BigInt half-up rounding per line. Split tax assigns any odd minor unit to SGST after flooring CGST; professional confirmation is needed for jurisdictional acceptability.

Purchase receipts allocate line discounts cumulatively and proportionally, so partial receipts do not repeatedly lose rounding remainders. Receipt value is net of discount, excluding tax. Supplier invoices debit GRNI and pending input-tax validation and credit supplier payable. Tax recovery is not claimed automatically.

Inventory uses movement-value moving-average costing per item/location. Issues consume a proportional share of remaining ledger value, including all residual value when stock is exhausted. Production capitalizes actual issued material value plus confirmed job costs, posted job expenses and accepted contractor charges. Zero accepted production is blocked pending a defined write-off workflow. Dispatch debits cost of goods sold and credits inventory using stock ledger cost. Positive physical adjustments use configured standard cost and an Inventory adjustments counteraccount; opening capital reclassification requires an approved journal.

## Posting examples

| Operation                  | Debit                               | Credit                                   |
| -------------------------- | ----------------------------------- | ---------------------------------------- |
| Purchase receipt           | Inventory                           | Goods received not invoiced              |
| Supplier bill              | GRNI + input tax pending validation | Accounts payable (supplier)              |
| Material issue             | Work in progress                    | Inventory                                |
| Accepted contractor return | Work in progress                    | Accounts payable (contractor)            |
| Paid job expense           | Work in progress                    | Cash/Bank                                |
| Confirmed extra job cost   | Work in progress                    | Accrued production costs                 |
| Finished receipt           | Inventory                           | Work in progress                         |
| Dispatch                   | Cost of goods sold                  | Inventory                                |
| Customer invoice           | Accounts receivable (customer)      | Sales + configured output tax components |
| Customer receipt           | Cash/Bank                           | Accounts receivable (customer)           |
| Supplier payment           | Accounts payable (supplier)         | Cash/Bank                                |
| Paid operating expense     | Expense category                    | Cash/Bank                                |

Posting actions accept an operational postingDate independently of the original document date. New stock movements and generated journals use that posting date. A monotonic closedThrough setting rejects postings at or before the lock. Closing requires balanced journals, no dated unresolved financial/return drafts, and classified posted accounts. The lock is preserved by ordinary business-setting updates; no automatic reopening is exposed.

## Retention and migration

Posted records and movements are never deleted through the API. Idempotency records do not expire automatically because replay must not re-post a historical financial operation. Expired sessions are TTL-cleaned. No automatic legacy migration exists: legacy users lack organizations, suppliers/staff have numeric contact/bank fields and existing stock/accounting history is unknown. Migration requires a reviewed mapping, a backup, dry-run validation and explicit business approval.

## Returns, notes, refunds and reporting

Customer returns reference a dispatched challan and restore its saved dispatch cost exactly once. Billed supplier returns reference a purchase, deduct available stock at ledger cost and debit Supplier returns clearing. Unbilled supplier returns and reversal of posted physical returns are not implemented. A missing historical dispatch cost snapshot is rejected pending a reviewed migration.

Credit/debit notes reference posted customer/supplier invoices and optionally match one full physical return from the same source order/party. Quantities and remaining gross/discount/tax amounts are bounded. Source invoice counters are updated transactionally. Credit notes debit Sales returns and the configured output-tax components and credit receivables. Matched supplier debit notes debit payables, credit the physical return clearing value and input-tax adjustment, and post any cost/price difference to Purchase return variance. Allowance notes without physical returns use Purchase adjustments.

Refund records reference posted notes. Available refunds are bounded both by the note and by the source invoice's net credit balance, including prior refunds. Refunds post cash/bank against the appropriate receivable/payable account. Linked refunds must be reversed before a note can be reversed. Financial-note reversal restores the exact monetary and quantity remainders, including individual tax components.

Partial supplier bills retain net/discount/tax allocation counters on their purchase lines. Receipts allocate the full order's net amount cumulatively in integer minor units. Bills allocate only the remaining received value. Reversing a middle bill restores its actual values, rather than estimating from the remaining quantity alone. Draft supplier bills retain a source version and require recreation if the purchase changed. Historical source records missing required allocation metadata are rejected rather than silently migrated.

Financial statements classify fixed built-in posting accounts and custom account definitions. Used custom classifications and account names cannot be silently changed. Unclassified accounts are reported explicitly; Inventory adjustments is intentionally unclassified until reviewed. The balance-sheet worksheet includes cumulative earnings/loss and shows its reconciliation difference. These are accounting worksheets, not statutory assurance.

Invoice ageing uses dated receivable/payable journal effects, note/refund links and invoice allocations. It includes reversals only on their posting date, so a later reversal does not rewrite an earlier as-of report. Unallocated party payments, contractor accruals and manual opening balances remain visible in party ledgers rather than being invented as dated invoices.
