import { inject, Injectable, signal } from "@angular/core";
import { HttpClient, HttpErrorResponse } from "@angular/common/http";
import { firstValueFrom } from "rxjs";
export type {
  Entry,
  Data,
  Line,
  Settings,
  Kind,
  SizeRow,
} from "../../server/src/types";
import type { Entry, Settings } from "../../server/src/types";
export interface Identity {
  id: string;
  org: string;
  name: string;
  role: string;
  email?: string;
}
export interface Page {
  data: Entry[];
  total: number;
  page: number;
  limit: number;
}
@Injectable({ providedIn: "root" })
export class Api {
  private http = inject(HttpClient);
  user = signal<Identity | null>(null);
  settings = signal<Settings | null>(null);
  permissions = signal<string[]>([]);
  readable = signal<string[]>([]);
  get<T>(path: string) {
    return firstValueFrom(this.http.get<T>("/api" + path));
  }
  post<T>(path: string, data: unknown, key: string = crypto.randomUUID()) {
    return firstValueFrom(
      this.http.post<T>("/api" + path, data, {
        headers: { "Idempotency-Key": key },
      }),
    );
  }
  put<T>(path: string, data: unknown, key: string = crypto.randomUUID()) {
    return firstValueFrom(
      this.http.put<T>("/api" + path, data, {
        headers: { "Idempotency-Key": key },
      }),
    );
  }
  async me() {
    const r = await this.get<{
      user: Identity;
      settings: Settings;
      permissions: string[];
      readable: string[];
    }>("/me");
    this.user.set(r.user);
    this.settings.set(r.settings);
    this.permissions.set(r.permissions);
    this.readable.set(r.readable ?? []);
  }
  can(p: string) {
    return this.permissions().includes("*") || this.permissions().includes(p);
  }
  error(e: unknown) {
    return e instanceof HttpErrorResponse
      ? typeof e.error?.message === "string"
        ? e.error.message
        : e.status === 0
          ? "Cannot reach the server. Check that the API is running."
          : "The request could not be completed."
      : e instanceof Error
        ? e.message
        : "The request could not be completed.";
  }
}
