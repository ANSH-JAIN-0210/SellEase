# Verification record

Verified locally on Windows using official Node.js 24.22.2, Angular 20, TypeScript 5.9, Express 5, Mongoose 8 and an isolated official MongoDB 7.0.24 replica-set binary.

## Automated checks

- Strict server TypeScript and Angular production builds pass. The final checked client is approximately 405 kB raw / 101 kB estimated transfer.
- Twenty unit/integration test groups pass with no failures or skips. See server/test/ for assertions and actual workflows.
- ESLint passes for server, tests and client TypeScript with zero reported errors or warnings.
- Integration tests use real HTTP requests and MongoDB transactions; they verify rollback and concurrency rather than substituting in-memory JavaScript repositories.

The initial database startup exceeded the test library's 10-second default on this machine. The local test/preview launch allowance was raised to 60 seconds; subsequent runs started normally and passed. The initial browser check also caught missing Angular zoneless setup and an optimized stylesheet load handler blocked by CSP. Both were corrected, rebuilt and verified in the browser.

## Browser verification

In the isolated local QA preview:

- Registration opened a workspace and dashboard.
- Product form saved a SKU with monetary amounts, color and size.
- The saved product appeared in the server-backed list and its detail view with the expected values.
- Desktop and responsive/light/dark screenshots are retained under screenshots/ as those checks finish.

API integration tests cover the complete business posting chain. Browser verification is not a comprehensive automated end-to-end suite: the purchasing/manufacturing/invoicing/payment forms still need full repeatable browser coverage before release.

## Limits

No production data, real email/SMS delivery, live payment gateway, official e-invoice/e-way integration, external deployment, restore rehearsal or formal statutory validation was tested. No claim of production readiness or full master-specification completion is made.

The Jenkinsfile is a checked-in example, not a pipeline run; its Node-24 tool installation must be configured in Jenkins. Docker Compose configuration has not been run on this Windows machine; the executed database tests used the isolated replica-set runner.

## Continuation verification — 4 November 2026

The expanded suite passes 20 test groups with zero failures/skips. Lint, strict source/test type checking and server/client production builds pass. New assertions cover physical returns, matched financial notes, linked refund limits/reversals, partial tax-component rounding, historical ageing across a later payment reversal, account classifications and balanced worksheets, period locks, currency/year immutability, protected mutation responses, and fractional receipt/bill remainders after reversing a middle bill.

Browser QA created and posted a customer return against an observed challan, matched and posted a credit note, and created/posted a synthetic refund through the forms. The posted note is captured in screenshots/credit-note-posted.png. Financial report screens were visually reviewed using the same isolated records. The QA setup script lives only under the working directory; production startup does not seed those records.
