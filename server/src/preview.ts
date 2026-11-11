/** Isolated local QA server. Never connects to the configured business database. */
import { MongoMemoryReplSet } from "mongodb-memory-server";
import mongoose from "mongoose";
import express from "express";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createApp } from "./app.js";
import { initModels } from "./models.js";
if (process.env.NODE_ENV === "production")
  throw new Error("Isolated preview is disabled in production");
const mongo = await MongoMemoryReplSet.create({
  replSet: { count: 1, storageEngine: "wiredTiger" },
  instanceOpts: [{ launchTimeout: 60000 }],
});
await mongoose.connect(mongo.getUri());
await initModels();
process.env.CLIENT_ORIGIN = "http://localhost:5000";
const app = createApp();
const client = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../client/dist/client/browser",
);
app.use(express.static(client));
app.get("/{*path}", (_req, res) =>
  res.sendFile(path.join(client, "index.html")),
);
const server = app.listen(5000, "127.0.0.1", () =>
  console.log(
    "Isolated QA preview: http://localhost:5000 — data is discarded when stopped.",
  ),
);
for (const signal of ["SIGTERM", "SIGINT"])
  process.on(signal, () =>
    server.close(() => {
      void mongoose
        .disconnect()
        .then(() => mongo.stop())
        .then(() => process.exit(0));
    }),
  );
