# Deployment, backup and rollback

No external deployment has been made. Select hosting, domain, email, object storage and database providers before release.

## Production configuration

Use Node 22.12+ and a MongoDB replica set with TLS, authentication and least-privileged application credentials. Provide MONGODB_URI as a secret. Supply CLIENT_ORIGIN as the exact HTTPS browser origin and NODE_ENV=production. The current HTTP listener is loopback-only and expects a TLS reverse proxy. Configure the proxy with body-size limits and timeouts and keep the API/SPA on the same origin. Review trust-proxy settings and use a distributed rate limiter before running multiple API instances; the bundled limiter is process-local.

Install dependencies using npm ci, run npm test and npm run build. The server requires a replica-set hello response before accepting requests and exposes /api/health. The client uses a conservative CSP-compatible CSS build without inline load handlers. Credentials, cookies and request bodies are not written to operational logs.

Optional SMTP configuration enables password recovery. Validate email delivery and domain authentication in a nonproduction environment. SMS/mobile verification, email account verification, payment gateways, e-invoicing/e-way generation, storage providers, Sentry, n8n and scheduled jobs are not provisioned. No need to add Redis until a confirmed deployment requires distributed rate limits/queues/cache.

## Backups

Use the database provider's point-in-time backups or a consistent replica-set backup. Encrypt backups, limit access and test restoration into a separate environment. For self-managed development, mongodump --oplog and mongorestore --oplogReplay are starting points; production runbooks must be checked against the chosen MongoDB version and topology. Do not run restore commands against live business data without explicit authorization.

Verify restore by reconciling movement sums to stock balances, journal debit totals to credit totals, invoice outstanding totals to allocations, sequence uniqueness and per-organization record counts. Include source-document and private-reference-image retention in the business backup policy.

## Release/rollback

Build and test an immutable release artifact. Back up the database before any future schema/data migration. This implementation introduces new collection names and does not mutate legacy collections. Deploy application changes only after configuration and business-accounting sign-off. To roll back application code, restore the previous artifact and verify that it understands all records already posted by the newer release. Never undo business postings by deleting documents or resetting current balances.

The Jenkinsfile runs checks/tests/builds only; it does not deploy or obtain credentials. Pin and review runtime and dependency updates through the lockfile and a controlled release process.

# Render deployment with MongoDB Atlas

Deploy the `sellease-implementation` branch as one Node web service from the repository root. The Express process serves the built Angular client and API together.

- Build: `MONGOMS_DISABLE_POSTINSTALL=1 npm ci --include=dev && npm run build`
- Start: `npm start`
- Health check: `/api/health`
- Environment: `NODE_VERSION=24.22.2`, `NODE_ENV=production`, and `MONGODB_URI` as a Render secret. Use a database-scoped Atlas user and a URI whose path names the SellEase database.
- Allow the Render service's outbound ranges in the Atlas project's network access settings. Render supplies the port and public HTTPS origin. Set `CLIENT_ORIGIN` explicitly if using a different public origin.

After the first healthy deploy, create a separate hosted workspace and verify sign-in and an authenticated read. The local preview and its sample workspace are separate.
