import {
  createHash,
  randomBytes,
  randomUUID,
  scrypt as scryptCallback,
  timingSafeEqual,
} from "node:crypto";
import { promisify } from "node:util";
import type { Request, Response, NextFunction } from "express";
import { z } from "zod";
import mongoose from "mongoose";
import nodemailer from "nodemailer";
import { User, Org, Session } from "./models.js";
import { fail, type Actor, type Settings } from "./types.js";
const scrypt = promisify(scryptCallback);
export const hash = (value: string) =>
  createHash("sha256").update(value).digest("hex");
export async function passwordHash(password: string) {
  const salt = randomBytes(16).toString("hex");
  return `${salt}:${((await scrypt(password, salt, 64)) as Buffer).toString("hex")}`;
}
async function passwordMatches(password: string, stored: string) {
  const [salt, value] = stored.split(":");
  const check = (await scrypt(password, salt, 64)) as Buffer;
  const expected = Buffer.from(value ?? "", "hex");
  return expected.length === check.length && timingSafeEqual(expected, check);
}
export interface AuthRequest extends Request {
  actor?: Actor;
}
const credentials = z
  .object({
    email: z
      .string()
      .email()
      .max(254)
      .transform((v) => v.toLowerCase()),
    password: z.string().min(12).max(128),
  })
  .strict();
export async function issueSession(res: Response, userId: string) {
  const token = randomBytes(32).toString("hex");
  await Session.create({
    hash: hash(token),
    userId,
    expires: new Date(Date.now() + 12 * 60 * 60 * 1000),
  });
  res.cookie("sellease_session", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: 12 * 60 * 60 * 1000,
  });
}
export async function register(req: Request, res: Response) {
  const p = credentials
    .extend({
      name: z.string().trim().min(1).max(120),
      businessName: z.string().trim().min(1).max(160),
    })
    .parse(req.body);
  const session = await mongoose.startSession();
  const id = randomUUID(),
    org = randomUUID();
  const password = await passwordHash(p.password);
  try {
    await session.withTransaction(async () => {
      const settings: Settings = {
        name: p.businessName,
        address: "",
        gstin: "",
        currency: "INR",
        timezone: "Asia/Kolkata",
        financialYearStart: 4,
        businessType: "garment",
        stages: [
          "Cutting",
          "Stitching",
          "Finishing",
          "Pressing",
          "Packing",
          "Quality check",
        ],
        onboarding: {
          isMobileVerified: false,
          isPersonalInfoSaved: true,
          isBusinessInfoSaved: true,
          isAddressDetailSaved: false,
          isTransactionInfoSaved: false,
        },
        catalogEnabled: false,
      };
      await Org.create([{ id: org, settings, revision: 0 }], { session });
      await User.create(
        [
          {
            id,
            org,
            email: p.email,
            name: p.name,
            password,
            role: "owner",
            active: true,
          },
        ],
        { session },
      );
    });
  } finally {
    await session.endSession();
  }
  await issueSession(res, id);
  res
    .status(201)
    .json({ user: { id, org, name: p.name, email: p.email, role: "owner" } });
}
export async function login(req: Request, res: Response) {
  const p = credentials.parse(req.body);
  const user = await User.findOne({ email: p.email, active: true }).select(
    "+password",
  );
  const dummy = "00000000000000000000000000000000:" + "0".repeat(128);
  const valid = await passwordMatches(p.password, user?.password ?? dummy);
  if (!user || !valid) fail("Email or password is incorrect", 401);
  if (req.cookies?.sellease_session)
    await Session.deleteOne({
      hash: hash(String(req.cookies.sellease_session)),
    });
  await issueSession(res, user!.id);
  res.json({
    user: {
      id: user!.id,
      org: user!.org,
      name: user!.name,
      email: user!.email,
      role: user!.role,
    },
  });
}
export async function authenticate(
  req: AuthRequest,
  _res: Response,
  next: NextFunction,
) {
  try {
    const token = req.cookies?.sellease_session;
    if (typeof token !== "string") fail("Sign in required", 401);
    const session = await Session.findOne({
      hash: hash(token),
      expires: { $gt: new Date() },
    }).lean();
    if (!session) fail("Session expired. Sign in again.", 401);
    const user = await User.findOne({
      id: session!.userId,
      active: true,
    }).lean();
    if (!user) fail("Account unavailable", 401);
    req.actor = {
      id: user!.id!,
      org: user!.org!,
      name: user!.name!,
      role: user!.role!,
    };
    next();
  } catch (error) {
    next(error);
  }
}
export async function logout(req: Request, res: Response) {
  if (req.cookies?.sellease_session)
    await Session.deleteOne({
      hash: hash(String(req.cookies.sellease_session)),
    });
  res.clearCookie("sellease_session", { path: "/" }).json({ success: true });
}
export async function recover(req: Request, res: Response) {
  const { email } = z
    .object({
      email: z
        .string()
        .email()
        .transform((v) => v.toLowerCase()),
    })
    .strict()
    .parse(req.body);
  if (!process.env.SMTP_HOST || !process.env.MAIL_FROM)
    fail(
      "Password recovery email is not configured. Contact the business owner.",
      503,
    );
  const user = await User.findOne({ email, active: true });
  if (user) {
    const token = randomBytes(32).toString("hex");
    user.resetHash = hash(token);
    user.resetExpires = new Date(Date.now() + 20 * 60 * 1000);
    await user.save();
    const transport = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT ?? 587),
      secure: process.env.SMTP_PORT === "465",
      auth: process.env.SMTP_USER
        ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        : undefined,
    });
    try {
      await transport.sendMail({
        from: process.env.MAIL_FROM,
        to: email,
        subject: "Reset your SellEase password",
        text: `Reset your password within 20 minutes: ${process.env.CLIENT_ORIGIN ?? "http://localhost:4200"}/?reset=${token}`,
      });
    } catch {
      // Do not disclose whether an account exists through provider errors.
      console.error(
        "Password recovery delivery failed; check SMTP configuration",
      );
    }
  }
  res.json({
    message:
      "If this address has an active account, password recovery has been requested. Contact support if no email arrives.",
  });
}
export async function reset(req: Request, res: Response) {
  const p = z
    .object({
      token: z.string().regex(/^[a-f0-9]{64}$/),
      password: z.string().min(12).max(128),
    })
    .strict()
    .parse(req.body);
  const password = await passwordHash(p.password);
  const session = await mongoose.startSession();
  try {
    await session.withTransaction(async () => {
      const user = await User.findOneAndUpdate(
        { resetHash: hash(p.token), resetExpires: { $gt: new Date() } },
        { $set: { password }, $unset: { resetHash: 1, resetExpires: 1 } },
        { new: true, session },
      );
      if (!user) fail("Reset link is invalid or expired");
      await Session.deleteMany({ userId: user!.id }, { session });
    });
  } finally {
    await session.endSession();
  }
  res.json({ message: "Password changed. Sign in with your new password." });
}
