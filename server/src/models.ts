import mongoose, { Schema } from "mongoose";
import type { Data, Kind, Settings } from "./types.js";
const recordSchema = new Schema(
  {
    id: { type: String, required: true },
    org: { type: String, required: true },
    kind: { type: String, required: true },
    data: { type: Schema.Types.Mixed, required: true },
    version: { type: Number, default: 1 },
    createdAt: { type: String, required: true },
    updatedAt: { type: String, required: true },
  },
  { versionKey: false, strict: "throw" },
);
recordSchema.index({ org: 1, kind: 1, id: 1 }, { unique: true });
recordSchema.index({ org: 1, kind: 1, createdAt: -1 });
recordSchema.index(
  { org: 1, kind: 1, "data.name": 1 },
  { unique: true, partialFilterExpression: { kind: "accounts" } },
);
recordSchema.index(
  { org: 1, kind: 1, "data.sku": 1 },
  {
    unique: true,
    partialFilterExpression: { "data.sku": { $type: "string" } },
  },
);
export const RecordModel = mongoose.model<{
  id: string;
  org: string;
  kind: Kind;
  data: Data;
  version: number;
  createdAt: string;
  updatedAt: string;
}>("BusinessRecord", recordSchema);
const orgSchema = new Schema(
  {
    id: { type: String, required: true, unique: true },
    settings: { type: Schema.Types.Mixed, required: true },
    revision: { type: Number, default: 0 },
  },
  { strict: "throw" },
);
export const Org = mongoose.model<{
  id: string;
  settings: Settings;
  revision: number;
}>("Organization", orgSchema);
export const User = mongoose.model(
  "Identity",
  new Schema(
    {
      id: { type: String, unique: true, required: true },
      org: { type: String, required: true },
      email: { type: String, unique: true, required: true },
      name: { type: String, required: true },
      password: { type: String, required: true, select: false },
      role: { type: String, required: true },
      active: { type: Boolean, default: true },
      resetHash: { type: String, select: false },
      resetExpires: { type: Date, select: false },
    },
    { timestamps: true, strict: "throw" },
  ),
);
export const Session = mongoose.model(
  "Session",
  new Schema(
    {
      hash: { type: String, unique: true, required: true },
      userId: { type: String, required: true },
      expires: { type: Date, required: true },
    },
    { strict: "throw" },
  ),
);
Session.schema.index({ expires: 1 }, { expireAfterSeconds: 0 });
export const Idempotency = mongoose.model(
  "Idempotency",
  new Schema(
    { org: String, key: String, hash: String, result: Schema.Types.Mixed },
    { timestamps: true, strict: "throw" },
  ),
);
Idempotency.schema.index({ org: 1, key: 1 }, { unique: true });
export const Sequence = mongoose.model(
  "Sequence",
  new Schema(
    { org: String, scope: String, value: Number },
    { strict: "throw" },
  ),
);
Sequence.schema.index({ org: 1, scope: 1 }, { unique: true });
export async function initModels() {
  await Promise.all([
    RecordModel.init(),
    Org.init(),
    User.init(),
    Session.init(),
    Idempotency.init(),
    Sequence.init(),
  ]);
}
