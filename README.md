# SellEase

Angular 20 + SCSS business workspace with a strict TypeScript, Express 5 and MongoDB/Mongoose API. Implements connected purchase, stock, production, dispatch, invoice, payment and journal workflows. This is a tested local implementation, **not a production-ready completion of every item in the supplied master specification**. See IMPLEMENTATION_STATUS.md for scope and release blockers.

## Source provenance

The originally supplied `sellease-server` and `sellease-client` URLs returned 404 even through the connected account. Following the user's confirmation, `ANSH-JAIN-0210/SellEase` was cloned at `51c5c4ef898935925582114185efcd8ae107b36a` (master). That repository contains only a small JavaScript backend, no Angular client. A sanitized copy of its application source is retained in `legacy/backend/`. Committed dependencies and `.env` were excluded. The legacy routes are not mounted; they have unauthenticated data operations and an unsafe password-reset flow. Hardcoded mail credentials were removed from the retained reference. Rotate the original exposed credentials separately.

## Run with a persistent local database

Requirements: Node.js 22.12+ (verified with 24.22.2), npm, Docker Compose or a MongoDB replica set.

```sh
npm ci
docker compose up -d
```

Copy `server/.env.example` to `server/.env`. The example URI points to the Compose replica set. For the development client, keep `CLIENT_ORIGIN=http://localhost:4200`.

```sh
npm run dev
```

Open `http://localhost:4200`, create a workspace and complete business settings. No business or demo records are seeded automatically. Data is stored in the configured MongoDB database. The Compose database is bound only to loopback and is for local development; production requires authenticated, encrypted database access and backups.

## Isolated preview without Docker

```sh
npm run build
npm run preview -w server
```

Open `http://localhost:5000`. This command starts an isolated local MongoDB replica set using `mongodb-memory-server`. It downloads an official MongoDB binary on first use (the Windows archive is approximately 600 MB). It never connects to `MONGODB_URI`. **All preview records disappear when it stops. Do not use it for business records.**

## Verify

```sh
npm test
npm run lint
npm run check
npm run build
```

Tests use their own replica set and HTTP requests through Supertest, rather than mocked database responses. The suite covers business posting, rollback, concurrency, authorization, tenant boundaries, snapshots, catalog exposure and password-reset token security. See docs/VERIFICATION.md for actual results and browser checks.

## Built client served by the API

Set `CLIENT_ORIGIN` to the actual site origin and configure `MONGODB_URI`, then:

```sh
npm run build
npm start
```

The API serves the built Angular client and SPA fallback on port 5000. It binds to `127.0.0.1`; deploy behind a TLS reverse proxy on the same host, or explicitly adapt the host binding for the chosen hosting environment. Set `NODE_ENV=production` for secure cookies. Production hosting is not deployed or provisioned by this package.

## First business workflow

1. Configure name, address, currency, financial-year start and production stages in Business settings.
2. Create customer/supplier/contractor parties, material lots and product variants. Each color/size SKU is a separate inventory item.
3. Draft and confirm a purchase. Receive partial quantities. Receipts add stock and post inventory against Goods received not invoiced.
4. Create a supplier invoice from received, unbilled quantities. Finalize it and allocate a supplier payment.
5. Create a production job. Issue its materials once, confirm cutting matrices, optionally assign contractor work, receive accepted/rejected contractor quantities, and complete the job with accepted/rejected output.
6. Confirm a sales order. Dispatch quantities to create a challan and deduct stock once. Acknowledge delivery separately.
7. Create and finalize a customer invoice. Record and finalize a customer receipt, optionally allocating it to the invoice.
8. Trace source-linked journal entries in the party/account ledger and trial balance. Reverse posted payments before reversing paid invoices.
9. Record a customer return against a challan, create a matched credit note, then record a refund only if the source invoice has an available credit balance. Billed supplier returns and debit notes use the corresponding supplier workflow.
10. Classify additional journal labels in Chart of accounts, review profit/loss, balance-sheet worksheets and historical invoice ageing, then close an accounting period only after drafts and account classifications are resolved.

Stock adjustments require a reason and create accounting entries at configured standard cost for additions and ledger cost for reductions. Transfers preserve quantity and value. Quantities support three decimal places in the configured base unit. Movement balances aggregate integer thousandths. Formal opening-stock valuation and unit-conversion rules require business confirmation before real deployment.

## Security and integrations

- Identity uses salted scrypt password hashes and hashed, server-side 12-hour session tokens in HttpOnly, SameSite=Strict cookies. Password reset tokens expire after 20 minutes, are single-use and revoke existing sessions.
- All browser writes require an application header and a matching Origin when supplied. CORS permits the configured client origin only.
- Every business record belongs to an organization. Backend permissions apply independently of the Angular navigation.
- All retryable business mutations require `Idempotency-Key`. Reuse a key for the same request after a network failure; use a new key after changing the request.
- SMTP recovery is enabled only with SMTP_HOST and MAIL_FROM. Configure SMTP_PORT, SMTP_USER and SMTP_PASS as required. No emails have been sent during this implementation.
- Gateway, SMS, e-invoice/e-way integrations, cloud uploads, monitoring and deployment require selected providers and configuration. There are no fake live integration buttons.

The included factory photos are private reference documentation, not imported accounting data. Review sharing before publishing this repository or distributing its source archive.
