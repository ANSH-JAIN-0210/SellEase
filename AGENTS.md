# SellEase implementation guidance

Read README.md, IMPLEMENTATION_STATUS.md and docs/BUSINESS_DECISIONS.md before modifying the application.

- Preserve Angular, SCSS, Express, TypeScript and MongoDB/Mongoose.
- The legacy/ directory is a sanitized reference snapshot. Its insecure routes are never mounted by the new application. Do not run the legacy server or automatically migrate its data.
- All business mutations go through transact() and Business. Keep organization scoping, serialization, audit and idempotency in the same transaction.
- Drafts do not post stock or money. Never implement direct balance edits or silently modify posted financial documents.
- Currency amounts are integer minor units. Quantities support three decimal places and are stored authoritatively in integer thousandths on movements.
- Never enable demo/test records in a production database. Integration tests use an isolated local replica set.
- Update status and business-decision documents when behavior or scope changes. Record actual test results, not intended results.
- Run npm test and npm run build after business logic changes. Check browser workflows after UI changes.
- No credentials in source or logs. No production deployment, real historical-data import, or destructive migration without explicit authorization.
