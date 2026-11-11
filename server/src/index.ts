import "dotenv/config";
import mongoose from "mongoose";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { existsSync } from "node:fs";
import { createApp } from "./app.js";
import { initModels } from "./models.js";
const uri = process.env.MONGODB_URI;
if (!uri) throw new Error("MONGODB_URI is required. See server/.env.example.");
await mongoose.connect(uri, { serverSelectionTimeoutMS: 10000 });
const hello = await mongoose.connection.db!.admin().command({ hello: 1 });
if (!hello.setName)
  throw new Error("MongoDB replica set required for transactional posting.");
await initModels();
const app = createApp();
const client = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../client/dist/client/browser",
);
if (existsSync(client)) {
  const express = await import("express");
  app.use(express.default.static(client));
  app.get("/{*path}", (_req, res) =>
    res.sendFile(path.join(client, "index.html")),
  );
}
const server = app.listen(Number(process.env.PORT ?? 5000), "127.0.0.1", () =>
  console.log(`SellEase listening on port ${process.env.PORT ?? 5000}`),
);
for (const signal of ["SIGTERM", "SIGINT"])
  process.on(signal, () =>
    server.close(() => {
      void mongoose.disconnect().then(() => process.exit(0));
    }),
  );
