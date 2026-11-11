import {
  Component,
  HostListener,
  inject,
  signal,
  computed,
  ElementRef,
  viewChild,
} from "@angular/core";
import { CommonModule } from "@angular/common";
import {
  FormsModule,
  ReactiveFormsModule,
  FormRecord,
  FormControl,
  Validators,
} from "@angular/forms";
import {
  Api,
  type Entry,
  type Data,
  type Kind,
  type Line,
  type SizeRow,
} from "./api";
interface Field {
  key: string;
  label: string;
  type?: string;
  required?: boolean;
  options?: { value: string; label: string }[];
  hint?: string;
}
interface Nav {
  key: string;
  label: string;
  icon: string;
  group: string;
  description: string;
}
interface Dash {
  summary: {
    _id: { kind: string; status: string };
    count: number;
    total: number;
    paid: number;
    credited?: number;
    refunded?: number;
  }[];
  lowStock: { id: string; data: Data; quantity: number }[];
  recent: { createdAt: string; data: Data }[];
}
interface Stock {
  _id: { itemId: string; warehouseId: string };
  quantity: number;
  value: number;
}
interface LedgerRow {
  id: string;
  date: string;
  description: string;
  sourceId?: string;
  sourceKind?: Kind;
  partyId?: string;
  account: string;
  debit: number;
  credit: number;
  balance: number;
}
const nav: Nav[] = [
  {
    key: "overview",
    label: "Overview",
    icon: "◫",
    group: "WORKSPACE",
    description: "Your business, at a glance.",
  },
  {
    key: "sales",
    label: "Sales orders",
    icon: "↗",
    group: "COMMERCE",
    description: "From customer order to fulfilment.",
  },
  {
    key: "invoices",
    label: "Invoices",
    icon: "▤",
    group: "COMMERCE",
    description: "Create, finalize and track customer invoices.",
  },
  {
    key: "challans",
    label: "Delivery challans",
    icon: "⇢",
    group: "COMMERCE",
    description: "Trace every dispatch and acknowledgement.",
  },
  {
    key: "purchases",
    label: "Purchases",
    icon: "↙",
    group: "COMMERCE",
    description: "Purchase orders and partial goods receipts.",
  },
  {
    key: "supplierInvoices",
    label: "Supplier invoices",
    icon: "▤",
    group: "COMMERCE",
    description:
      "Match supplier bills to received goods and allocate payments.",
  },
  {
    key: "products",
    label: "Products",
    icon: "◇",
    group: "INVENTORY",
    description: "Your styles, colors and sizes in one place.",
  },
  {
    key: "materials",
    label: "Fabric & materials",
    icon: "▱",
    group: "INVENTORY",
    description: "Keep fabric lots and raw materials traceable.",
  },
  {
    key: "stock",
    label: "Stock explorer",
    icon: "▦",
    group: "INVENTORY",
    description: "Availability derived from your movement ledger.",
  },
  {
    key: "movements",
    label: "Stock movements",
    icon: "⇄",
    group: "INVENTORY",
    description: "A traceable history of every stock change.",
  },
  {
    key: "warehouses",
    label: "Locations",
    icon: "⌂",
    group: "INVENTORY",
    description: "Organize your storage locations.",
  },
  {
    key: "production",
    label: "Production jobs",
    icon: "⚒",
    group: "MANUFACTURING",
    description: "Turn issued materials into accepted finished goods.",
  },
  {
    key: "cutting",
    label: "Cutting plans",
    icon: "✂",
    group: "MANUFACTURING",
    description: "Plan and confirm your color and size matrix.",
  },
  {
    key: "jobwork",
    label: "Contractor job work",
    icon: "⇄",
    group: "MANUFACTURING",
    description: "Assign, receive and cost outsourced production quantities.",
  },
  {
    key: "expenses",
    label: "Expense daybook",
    icon: "≡",
    group: "FINANCE",
    description: "Record and post everyday business expenses.",
  },
  {
    key: "payments",
    label: "Payments",
    icon: "⇌",
    group: "FINANCE",
    description: "Receipts, supplier payments and invoice allocations.",
  },
  {
    key: "journals",
    label: "Journal entries",
    icon: "▤",
    group: "FINANCE",
    description: "Opening balances and controlled accounting adjustments.",
  },
  {
    key: "ledger",
    label: "Account ledger",
    icon: "▥",
    group: "FINANCE",
    description: "Source-linked entries and running balances.",
  },
  {
    key: "reports",
    label: "Financial reports",
    icon: "▧",
    group: "FINANCE",
    description: "Trial balance from posted journals.",
  },
  {
    key: "parties",
    label: "Customers & suppliers",
    icon: "♧",
    group: "PEOPLE",
    description: "The people and businesses you work with.",
  },
  {
    key: "staff",
    label: "Staff directory",
    icon: "♙",
    group: "PEOPLE",
    description: "Contact records for your team.",
  },
  {
    key: "users",
    label: "Access & permissions",
    icon: "⊞",
    group: "ADMINISTRATION",
    description: "Manage login access and business roles.",
  },
  {
    key: "categories",
    label: "Categories",
    icon: "⌘",
    group: "ADMINISTRATION",
    description: "Organize products and expenses.",
  },
  {
    key: "tickets",
    label: "Support tickets",
    icon: "?",
    group: "ADMINISTRATION",
    description: "Keep internal requests and issues organized.",
  },
  {
    key: "audit",
    label: "Audit trail",
    icon: "◷",
    group: "ADMINISTRATION",
    description: "Who changed what, and when.",
  },
  {
    key: "settings",
    label: "Business settings",
    icon: "⚙",
    group: "ADMINISTRATION",
    description: "Configure your business and production workflow.",
  },
  {
    key: "help",
    label: "Workflow guide",
    icon: "ⓘ",
    group: "ADMINISTRATION",
    description:
      "Learn the posting boundaries that keep your records reliable.",
  },
];
const returnModules = [
  "customerReturns",
  "supplierReturns",
  "creditNotes",
  "debitNotes",
];
nav.push(
  {
    key: "accounts",
    label: "Chart of accounts",
    icon: "▥",
    group: "FINANCE",
    description: "Classify ledger accounts for financial statements.",
  },
  {
    key: "customerReturns",
    label: "Customer returns",
    icon: "↩",
    group: "COMMERCE",
    description: "Receive physical returns against dispatched challans.",
  },
  {
    key: "supplierReturns",
    label: "Supplier returns",
    icon: "↪",
    group: "COMMERCE",
    description:
      "Return billed goods to a supplier with traceable stock effects.",
  },
  {
    key: "creditNotes",
    label: "Credit notes",
    icon: "−",
    group: "FINANCE",
    description: "Credit customer invoices without duplicating stock receipts.",
  },
  {
    key: "debitNotes",
    label: "Debit notes",
    icon: "−",
    group: "FINANCE",
    description: "Adjust supplier invoices and reconcile supplier returns.",
  },
);
@Component({
  selector: "app-root",
  standalone: true,
  imports: [CommonModule, FormsModule, ReactiveFormsModule],
  templateUrl: "./app.html",
})
export class AppComponent {
  returnQuantities: Record<string, number> = {};
  postingDate = "";
  closeThrough = "";
  financial = signal<{
    profitAndLoss: { revenue: number; expenses: number; profit: number };
    balanceSheet: {
      assets: number;
      liabilities: number;
      equity: number;
      currentResult: number;
      totalEquity: number;
      difference: number;
    };
    unclassified: string[];
    classified: boolean;
  } | null>(null);
  journalLines: {
    account: string;
    debit: number;
    credit: number;
    partyId?: string;
  }[] = [];
  ageing = signal<{
    asOf: string;
    scope: string;
    totals: {
      receivable: number;
      payable: number;
      customerCredit: number;
      supplierCredit: number;
    };
    data: {
      invoiceId: string;
      number: string;
      party: string;
      type: string;
      dueDate: string;
      daysOverdue: number;
      bucket: string;
      amount: number;
    }[];
  } | null>(null);
  api = inject(Api);
  nav = nav;
  view = signal("overview");
  ready = signal(false);
  loading = signal(false);
  busy = signal(false);
  error = signal("");
  toast = signal("");
  rows = signal<Entry[]>([]);
  total = signal(0);
  page = signal(1);
  search = "";
  status = "";
  sort = "createdAt";
  direction = "desc";
  from = "";
  to = "";
  readonly salesStages = [
    { key: "draft", label: "Draft", icon: "edit" },
    { key: "awaiting", label: "Awaiting dispatch", icon: "package" },
    { key: "partial", label: "Partially dispatched", icon: "truck" },
    { key: "dispatched", label: "Fully dispatched", icon: "check" },
    { key: "void", label: "Voided", icon: "close" },
  ] as const;
  salesStage = signal<(typeof this.salesStages)[number]["key"] | "">("");
  salesSummary = signal<{ _id: string; count: number; value: number }[]>([]);
  linkedOrder = signal<{ id: string; number: string } | null>(null);
  dispatchTransport = "";
  dispatchVehicle = "";
  dispatchEway = "";
  dispatchGatePass = "";
  partyFilter = "";
  accountFilter = "";
  drawer = signal(false);
  detail = signal<Entry | null>(null);
  command = signal(false);
  commandSearch = "";
  mobile = signal(false);
  dark = signal(localStorage.getItem("sellease_theme") === "dark");
  collapsed = signal(false);
  form = new FormRecord<FormControl<string>>({});
  fields: Field[] = [];
  lines: Line[] = [];
  sizes: SizeRow[] = [];
  costLines: { name: string; amount: number }[] = [];
  materials: { itemId: string; quantity: number }[] = [];
  lookups = signal<Entry[]>([]);
  dash = signal<Dash | null>(null);
  stock = signal<Stock[]>([]);
  ledger = signal<LedgerRow[]>([]);
  trial = signal<{ _id: string; debit: number; credit: number }[]>([]);
  opening = 0;
  closing = 0;
  editId = "";
  editVersion = 0;
  formKey = "";
  actionKey = "";
  authMode: "login" | "register" | "recover" | "reset" = "login";
  auth = {
    name: "",
    businessName: "",
    email: "",
    password: "",
    token: new URLSearchParams(location.search).get("reset") ?? "",
  };
  authMessage = "";
  authForm = viewChild<ElementRef<HTMLFormElement>>("authForm");
  previousFocus: HTMLElement | null = null;
  printMode = false;
  get today() {
    return new Date().toLocaleDateString("en-CA", {
      timeZone: this.api.settings()?.timezone ?? "Asia/Kolkata",
    });
  }
  actionQuantities: Record<string, number> = {};
  accepted = 0;
  rejected = 0;
  reversalReason = "";
  private searchTimer?: ReturnType<typeof setTimeout>;
  private toastTimer?: ReturnType<typeof setTimeout>;
  catalog = signal<{
    name: string;
    currency: string;
    items: {
      id: string;
      name: string;
      sku: string;
      color: string;
      size: string;
      price: number;
      description: string;
    }[];
  } | null>(null);
  catalogPage = 1;
  title = computed(
    () => nav.find((n) => n.key === this.view())?.label ?? "Overview",
  );
  description = computed(
    () => nav.find((n) => n.key === this.view())?.description ?? "",
  );
  visibleNav = computed(() =>
    nav
      .filter(
        (n) =>
          [
            "overview",
            "stock",
            "ledger",
            "reports",
            "users",
            "settings",
            "help",
          ].includes(n.key) || this.api.readable().includes(n.key),
      )
      .filter(
        (n) =>
          ![
            "expenses",
            "payments",
            "journals",
            "ledger",
            "reports",
            "audit",
          ].includes(n.key) || this.finance(),
      )
      .filter(
        (n) =>
          !["users", "settings", "staff"].includes(n.key) ||
          this.api.can("users"),
      ),
  );
  groups = computed(() => [...new Set(this.visibleNav().map((n) => n.group))]);
  canCreate = computed(
    () =>
      ![
        "overview",
        "stock",
        "movements",
        "ledger",
        "reports",
        "audit",
        "challans",
        "settings",
        "help",
        "notifications",
      ].includes(this.view()) && this.api.can(this.view()),
  );
  finance() {
    return ["owner", "admin", "accountant"].includes(
      this.api.user()?.role ?? "",
    );
  }
  constructor() {
    document.documentElement.dataset["theme"] = this.dark() ? "dark" : "light";
    if (this.auth.token) this.authMode = "reset";
    void this.init();
  }
  async init() {
    const cat = new URLSearchParams(location.search).get("catalog");
    if (cat) {
      try {
        this.catalog.set(
          await this.api.get(`/catalog/${encodeURIComponent(cat)}?page=1`),
        );
      } catch (e) {
        this.error.set(this.api.error(e));
      }
      this.ready.set(true);
      return;
    }
    try {
      await this.api.me();
      await this.navigate(location.hash.slice(1) || "overview");
    } catch {
      /* Sign-in is the entry point for an expired session. */
    } finally {
      this.ready.set(true);
    }
  }
  @HostListener("window:keydown", ["$event"]) keyboard(e: KeyboardEvent) {
    if ((e.ctrlKey || e.metaKey) && e.key === "k") {
      e.preventDefault();
      this.command.set(!this.command());
    }
    if (e.key === "Escape") {
      this.drawer.set(false);
      this.detail.set(null);
      this.command.set(false);
      this.mobile.set(false);
      this.previousFocus?.focus();
    }
    if (e.key === "Tab" && (this.drawer() || this.detail() || this.command())) {
      const elements = [
        ...document.querySelectorAll<HTMLElement>(
          '[role="dialog"] button,[role="dialog"] input,[role="dialog"] select,[role="dialog"] textarea',
        ),
      ].filter((el) => !el.hasAttribute("disabled"));
      if (
        elements.length &&
        e.shiftKey &&
        document.activeElement === elements[0]
      ) {
        e.preventDefault();
        elements.at(-1)?.focus();
      } else if (
        elements.length &&
        !e.shiftKey &&
        document.activeElement === elements.at(-1)
      ) {
        e.preventDefault();
        elements[0].focus();
      }
    }
  }
  @HostListener("window:hashchange") hashChanged() {
    const next = location.hash.slice(1);
    if (next && next !== this.view()) void this.navigate(next);
  }
  notify(message: string) {
    this.toast.set(message);
    clearTimeout(this.toastTimer);
    this.toastTimer = setTimeout(() => this.toast.set(""), 4500);
  }
  toggleTheme() {
    this.dark.set(!this.dark());
    localStorage.setItem("sellease_theme", this.dark() ? "dark" : "light");
    document.documentElement.dataset["theme"] = this.dark() ? "dark" : "light";
  }
  async authSubmit() {
    this.error.set("");
    this.busy.set(true);
    try {
      if (this.authMode === "recover") {
        const r = await this.api.post<{ message: string }>("/auth/recover", {
          email: this.auth.email,
        });
        this.authMessage = r.message;
      } else if (this.authMode === "reset") {
        await this.api.post("/auth/reset", {
          token: this.auth.token,
          password: this.auth.password,
        });
        history.replaceState({}, "", "/");
        this.authMode = "login";
        this.auth.password = "";
        this.authMessage = "Password changed. Sign in to continue.";
      } else {
        await this.api.post(
          "/auth/" + this.authMode,
          this.authMode === "register"
            ? {
                name: this.auth.name,
                businessName: this.auth.businessName,
                email: this.auth.email,
                password: this.auth.password,
              }
            : { email: this.auth.email, password: this.auth.password },
        );
        this.auth.password = "";
        await this.api.me();
        await this.navigate("overview");
      }
    } catch (e) {
      this.error.set(this.api.error(e));
    } finally {
      this.busy.set(false);
    }
  }
  async logout() {
    try {
      await this.api.post("/auth/logout", {});
      this.api.user.set(null);
      this.rows.set([]);
      this.dash.set(null);
      this.lookups.set([]);
    } catch (e) {
      this.error.set(this.api.error(e));
    }
  }
  async navigate(key: string, order?: Entry) {
    if (!this.visibleNav().some((n) => n.key === key)) key = "overview";
    clearTimeout(this.searchTimer);
    this.rows.set([]);
    this.total.set(0);
    this.view.set(key);
    history.replaceState({}, "", location.pathname + "#" + key);
    this.page.set(1);
    this.search = "";
    this.status = "";
    this.from = "";
    this.to = "";
    this.salesStage.set("");
    this.linkedOrder.set(
      order
        ? { id: order.id, number: order.data.number ?? order.id.slice(0, 8) }
        : null,
    );
    this.mobile.set(false);
    this.command.set(false);
    this.error.set("");
    await this.reload();
  }
  async reload() {
    this.loading.set(true);
    this.error.set("");
    try {
      const view = this.view();
      if (view === "overview")
        this.dash.set(await this.api.get<Dash>("/dashboard"));
      else if (view === "stock") {
        await this.loadLookups();
        this.stock.set((await this.api.get<{ data: Stock[] }>("/stock")).data);
      } else if (view === "ledger") {
        const q = new URLSearchParams();
        if (this.partyFilter) q.set("partyId", this.partyFilter);
        if (this.accountFilter) q.set("account", this.accountFilter);
        if (this.from) q.set("from", this.from);
        if (this.to) q.set("to", this.to);
        const r = await this.api.get<{
          data: LedgerRow[];
          opening: number;
          closing: number;
        }>("/reports/ledger?" + q);
        this.ledger.set(r.data);
        this.opening = r.opening;
        this.closing = r.closing;
        await this.loadLookups();
      } else if (view === "reports") {
        const q = new URLSearchParams();
        if (this.from) q.set("from", this.from);
        if (this.to) q.set("to", this.to);
        this.financial.set(await this.api.get("/reports/financial?" + q));
        this.ageing.set(
          await this.api.get(
            "/reports/ageing?asOf=" + encodeURIComponent(this.to || this.today),
          ),
        );
        this.trial.set(
          (
            await this.api.get<{
              data: { _id: string; debit: number; credit: number }[];
            }>("/reports/trial-balance?" + q)
          ).data,
        );
      } else if (view === "users") {
        const r = await this.api.get<{
          data: {
            id: string;
            name: string;
            email: string;
            role: string;
            active: boolean;
          }[];
        }>("/users");
        this.rows.set(
          r.data.map((u) => ({
            id: u.id,
            kind: "staff",
            org: this.api.user()!.org,
            version: 1,
            createdAt: "",
            updatedAt: "",
            data: u,
          })),
        );
        this.total.set(r.data.length);
      } else if (view === "settings" || view === "help") {
        /* These pages use settings and static workflow guidance. */
      } else {
        const q = this.recordQuery();
        q.set("page", String(this.page()));
        q.set("limit", "20");
        const [r, summary] = await Promise.all([
          this.api.get<{ data: Entry[]; total: number }>(
            "/records/" + view + "?" + q,
          ),
          view === "sales"
            ? this.api.get<{
                data: { _id: string; count: number; value: number }[];
              }>("/sales/summary")
            : Promise.resolve(null),
        ]);
        const currentQuery = this.recordQuery();
        currentQuery.set("page", String(this.page()));
        currentQuery.set("limit", "20");
        if (this.view() !== view || currentQuery.toString() !== q.toString())
          return;
        if (summary) this.salesSummary.set(summary.data);
        this.rows.set(r.data);
        this.total.set(r.total);
        await this.loadLookups();
      }
    } catch (e) {
      this.error.set(this.api.error(e));
    } finally {
      this.loading.set(false);
    }
  }
  private recordQuery() {
    const q = new URLSearchParams({
      search: this.search,
      sort: this.sort,
      direction: this.direction,
    });
    if (this.status) q.set("status", this.status);
    if (this.from) q.set("from", this.from);
    if (this.to) q.set("to", this.to);
    const source = this.linkedOrder();
    if (source) q.set("sourceId", source.id);
    if (this.view() === "sales" && this.salesStage())
      q.set("fulfillment", this.salesStage());
    return q;
  }
  salesCount(stage: string) {
    return this.salesSummary().find((row) => row._id === stage)?.count ?? 0;
  }
  hasNav(key: string) {
    return this.visibleNav().some((item) => item.key === key);
  }
  openOrderDocuments(key: "challans" | "invoices", order: Entry) {
    this.detail.set(null);
    void this.navigate(key, order);
  }
  clearLinkedOrder() {
    this.linkedOrder.set(null);
    this.page.set(1);
    void this.reload();
  }
  cashBook() {
    return this.accountFilter === "Cash" || this.accountFilter === "Bank";
  }
  selectLedger(account: string) {
    this.accountFilter = account;
    this.partyFilter = "";
    void this.reload();
  }
  ledgerTotal(field: "debit" | "credit") {
    return this.ledger().reduce((total, row) => total + row[field], 0);
  }
  async openLedgerSource(row: LedgerRow) {
    if (!row.sourceKind || !row.sourceId || !this.hasNav(row.sourceKind))
      return;
    try {
      await this.openDetail(
        await this.api.get<Entry>(`/records/${row.sourceKind}/${row.sourceId}`),
      );
    } catch (error) {
      this.error.set(this.api.error(error));
    }
  }
  salesOrderValue() {
    return this.salesSummary()
      .filter((row) => row._id !== "void" && row._id !== "draft")
      .reduce((total, row) => total + row.value, 0);
  }
  salesProgress(row: Entry) {
    const lines = row.data.lines ?? [];
    const ordered = lines.reduce(
      (sum, line) => sum + Math.round(line.quantity * 1000),
      0,
    );
    const sent = lines.reduce(
      (sum, line) => sum + Math.round((line.dispatched ?? 0) * 1000),
      0,
    );
    const key =
      row.data.status === "draft"
        ? "draft"
        : row.data.status === "void"
          ? "void"
          : sent === 0
            ? "awaiting"
            : sent < ordered
              ? "partial"
              : "dispatched";
    return {
      key,
      label: this.salesStages.find((stage) => stage.key === key)!.label,
      ordered: ordered / 1000,
      sent: sent / 1000,
      percent: ordered ? Math.min(100, Math.round((sent * 100) / ordered)) : 0,
    };
  }
  pendingQuantity(row: Entry, line: Line) {
    const posted = row.kind === "purchases" ? line.received : line.dispatched;
    return Math.max(
      0,
      (Math.round(line.quantity * 1000) - Math.round((posted ?? 0) * 1000)) /
        1000,
    );
  }
  canPostOrder(row: Entry) {
    return (
      row.data.status === "confirmed" &&
      this.api.can(row.kind) &&
      (row.data.lines ?? []).some((line) => this.pendingQuantity(row, line) > 0)
    );
  }
  fillRemaining(row: Entry) {
    this.actionQuantities = Object.fromEntries(
      (row.data.lines ?? []).map((line) => [
        line.itemId,
        this.pendingQuantity(row, line),
      ]),
    );
  }
  filterSales(stage: (typeof this.salesStages)[number]["key"] | "") {
    this.salesStage.set(stage);
    this.page.set(1);
    void this.reload();
  }
  clearSalesFilters() {
    clearTimeout(this.searchTimer);
    this.search = "";
    this.from = "";
    this.to = "";
    this.filterSales("");
  }
  recordExportUrl() {
    return "/api/records/" + this.view() + "/export.csv?" + this.recordQuery();
  }
  datedRecords() {
    return [
      "purchases",
      "sales",
      "production",
      "cutting",
      "jobwork",
      "invoices",
      "supplierInvoices",
      "customerReturns",
      "supplierReturns",
      "creditNotes",
      "debitNotes",
      "challans",
      "expenses",
      "payments",
      "movements",
      "journals",
    ].includes(this.view());
  }
  async loadLookups() {
    const out: Entry[] = [];
    for (const kind of [
      "products",
      "materials",
      "parties",
      "production",
      "sales",
      "purchases",
      "invoices",
      "supplierInvoices",
      "challans",
      "customerReturns",
      "supplierReturns",
      "creditNotes",
      "debitNotes",
      "warehouses",
    ]) {
      if (!this.api.readable().includes(kind)) continue;
      let page = 1;
      let total: number;
      do {
        const r = await this.api.get<{ data: Entry[]; total: number }>(
          "/records/" + kind + "?limit=100&page=" + page,
        );
        out.push(...r.data);
        total = r.total;
        page++;
      } while ((page - 1) * 100 < total && page <= 20);
    }
    this.lookups.set(out);
  }
  lookup(id: string | undefined) {
    const r = this.lookups().find((e) => e.id === id);
    return r?.data.name ?? r?.data.number ?? id?.slice(0, 8) ?? "—";
  }
  sku(id: string) {
    return this.lookups().find((e) => e.id === id)?.data.sku ?? "—";
  }
  options(kind: string) {
    return this.lookups().filter(
      (e) => e.kind === kind && e.data.status !== "archived",
    );
  }
  items() {
    return this.lookups().filter(
      (e) =>
        ["products", "materials"].includes(e.kind) &&
        e.data.status !== "archived",
    );
  }
  currency() {
    return this.api.settings()?.currency ?? this.catalog()?.currency ?? "INR";
  }
  money(value: number | undefined) {
    return new Intl.NumberFormat("en-IN", {
      style: "currency",
      currency: this.currency(),
      maximumFractionDigits: 2,
    }).format((value ?? 0) / 100);
  }
  minor(value: string) {
    if (!/^\d+(\.\d{0,2})?$/.test(value))
      throw new Error("Enter an amount with up to two decimal places");
    const [whole, fraction = ""] = value.split(".");
    const minor = Number(whole) * 100 + Number(fraction.padEnd(2, "0"));
    if (!Number.isSafeInteger(minor)) throw new Error("Amount is too large");
    return minor;
  }
  amountInput(value: number) {
    return (value / 100).toFixed(2);
  }
  date(value: string | undefined) {
    return value
      ? new Date(
          value.length === 10 ? value + "T00:00:00Z" : value,
        ).toLocaleDateString("en-IN", {
          day: "numeric",
          month: "short",
          year: "numeric",
          timeZone:
            value.length === 10
              ? "UTC"
              : (this.api.settings()?.timezone ?? "Asia/Kolkata"),
        })
      : "—";
  }
  debounce() {
    clearTimeout(this.searchTimer);
    this.searchTimer = setTimeout(() => {
      this.page.set(1);
      void this.reload();
    }, 300);
  }
  async changePage(delta: number) {
    this.page.update((v) => v + delta);
    await this.reload();
  }
  setSort(sort: string) {
    this.direction =
      this.sort === sort && this.direction === "asc" ? "desc" : "asc";
    this.sort = sort;
    void this.reload();
  }
  metric(kind: string, status: string) {
    return this.dash()?.summary.find(
      (x) => x._id.kind === kind && x._id.status === status,
    );
  }
  commandItems() {
    const term = this.commandSearch.toLowerCase();
    return this.visibleNav().filter((n) =>
      n.label.toLowerCase().includes(term),
    );
  }
  fieldValue(key: string) {
    return this.form.controls[key]?.value ?? "";
  }
  selectField(
    key: string,
    label: string,
    kind: string,
    required = true,
  ): Field {
    return {
      key,
      label,
      type: "select",
      required,
      options: this.options(kind).map((e) => ({
        value: e.id,
        label: e.data.name ?? e.data.number ?? e.id,
      })),
    };
  }
  async openCreate(existing?: Entry) {
    this.previousFocus = document.activeElement as HTMLElement;
    this.error.set("");
    this.editId = existing?.id ?? "";
    this.editVersion = existing?.version ?? 0;
    this.formKey = crypto.randomUUID();
    const k = this.view();
    const text = (
      key: string,
      label: string,
      required = false,
      type = "text",
    ): Field => ({ key, label, required, type });
    this.fields = [];
    if (["products", "materials"].includes(k))
      this.fields = [
        text("name", "Name", true),
        text("sku", "Unique SKU / lot code", true),
        text("description", "Description"),
        text("category", "Category"),
        {
          key: "unit",
          label: "Base unit",
          type: "select",
          options: ["piece", "metre", "kg", "roll"].map((value) => ({
            value,
            label: value,
          })),
          required: true,
        },
        text("price", "Selling price", false, "money"),
        text("cost", "Standard unit cost", false, "money"),
        text("reorder", "Reorder threshold", false, "number"),
        text("hsn", "HSN / SAC"),
        text("style", "Style number"),
        text("color", "Color"),
        text("size", "Size"),
        text("lot", "Fabric lot"),
        text("tags", "Tags (comma separated)"),
        {
          key: "published",
          label: "Publish in catalog",
          type: "select",
          options: [
            { value: "false", label: "Private" },
            { value: "true", label: "Public" },
          ],
        },
      ];
    else if (k === "parties")
      this.fields = [
        text("name", "Party name", true),
        {
          key: "kind",
          label: "Relationship",
          type: "select",
          options: ["customer", "supplier", "both", "contractor"].map(
            (value) => ({ value, label: value }),
          ),
          required: true,
        },
        text("email", "Email", false, "email"),
        text("phone", "Phone"),
        text("address", "Address"),
        text("gstin", "GSTIN"),
        text("notes", "Notes"),
      ];
    else if (["warehouses", "categories"].includes(k))
      this.fields = [
        text("name", "Name", true),
        text("description", "Description"),
      ];
    else if (k === "staff")
      this.fields = [
        text("name", "Full name", true),
        text("email", "Email", true, "email"),
        text("phone", "Phone", true),
        text("role", "Job title", true),
      ];
    else if (k === "users")
      this.fields = [
        text("name", "Full name", true),
        text("email", "Email", true, "email"),
        text("password", "Initial password (12+ characters)", true, "password"),
        {
          key: "role",
          label: "Access role",
          type: "select",
          required: true,
          options: [
            "admin",
            "accountant",
            "sales",
            "purchasing",
            "production",
            "inventory",
            "staff",
          ].map((value) => ({ value, label: value })),
        },
      ];
    else if (k === "sales" || k === "purchases")
      this.fields = [
        this.selectField(
          "partyId",
          k === "sales" ? "Customer" : "Supplier",
          "parties",
        ),
        text("date", "Order date", true, "date"),
        text("dueDate", "Due date", false, "date"),
        ...(k === "sales"
          ? [text("reference", "Customer PO or paper reference")]
          : []),
        text("notes", "Notes"),
      ];
    else if (k === "invoices" || k === "supplierInvoices") {
      this.fields = [
        this.selectField(
          "sourceId",
          k === "invoices"
            ? "Confirmed sales order"
            : "Received purchase order",
          k === "invoices" ? "sales" : "purchases",
        ),
        text("date", "Invoice date", true, "date"),
        text("dueDate", "Due date", false, "date"),
      ];
      if (k === "supplierInvoices")
        this.fields.push(text("reference", "Supplier invoice reference", true));
    } else if (k === "production")
      this.fields = [
        text("name", "Job name / style", true),
        text("reference", "Paper job or cost sheet number"),
        this.selectField(
          "outputItemId",
          "Finished product variant",
          "products",
        ),
        text("quantity", "Planned output quantity", true, "number"),
        text("date", "Start date", true, "date"),
        text("notes", "Notes"),
      ];
    else if (returnModules.includes(k)) {
      const sourceKinds: Record<string, string> = {
        customerReturns: "challans",
        supplierReturns: "purchases",
        creditNotes: "invoices",
        debitNotes: "supplierInvoices",
      };
      this.fields = [
        this.selectField("sourceId", "Source document", sourceKinds[k]),
        text("date", "Return / note date", true, "date"),
        text("reason", "Reason", true),
      ];
      if (k === "creditNotes" || k === "debitNotes")
        this.fields.push(
          this.selectField(
            "returnId",
            "Match physical return (optional)",
            k === "creditNotes" ? "customerReturns" : "supplierReturns",
            false,
          ),
        );
      this.returnQuantities = {};
    } else if (k === "jobwork")
      this.fields = [
        text("name", "Assignment name", true),
        this.selectField("sourceId", "Production job", "production"),
        this.selectField("partyId", "Contractor", "parties"),
        text("quantity", "Quantity assigned", true, "number"),
        text("rate", "Rate per accepted unit", true, "money"),
        text("date", "Assignment date", true, "date"),
        text("notes", "Notes"),
      ];
    else if (k === "accounts") {
      this.fields = [
        text("name", "Account name (exact journal label)", true),
        {
          key: "accountType",
          label: "Classification",
          type: "select",
          required: true,
          options: ["asset", "liability", "equity", "revenue", "expense"].map(
            (value) => ({ value, label: value }),
          ),
        },
        text("description", "Description"),
      ];
    } else if (k === "journals") {
      this.fields = [
        text("description", "Journal description", true),
        text("date", "Posting date", true, "date"),
      ];
      this.journalLines = [
        { account: "Cash", debit: 0, credit: 0 },
        { account: "Capital", debit: 0, credit: 0 },
      ];
    } else if (k === "cutting")
      this.fields = [
        text("name", "Cutting plan name", true),
        text("reference", "Paper cutting sheet number"),
        this.selectField("sourceId", "Production job", "production"),
        this.selectField("itemId", "Fabric / material lot", "materials"),
        text("quantity", "Quantity consumed from job issue", true, "number"),
        text("date", "Cutting date", true, "date"),
        text("notes", "Notes"),
      ];
    else if (k === "expenses")
      this.fields = [
        text("name", "Description", true),
        text("category", "Expense category", true),
        text("amount", "Amount", true, "money"),
        text("date", "Expense date", true, "date"),
        {
          key: "method",
          label: "Paid from",
          type: "select",
          options: [
            { value: "cash", label: "Cash" },
            { value: "bank", label: "Bank" },
          ],
          required: true,
        },
        this.selectField(
          "sourceId",
          "Production job (optional)",
          "production",
          false,
        ),
        this.selectField("partyId", "Paid to (optional)", "parties", false),
        text("notes", "Notes"),
      ];
    else if (k === "payments")
      this.fields = [
        this.selectField("partyId", "Party", "parties"),
        {
          key: "flow",
          label: "Direction",
          type: "select",
          required: true,
          options: [
            { value: "receipt", label: "Customer receipt" },
            { value: "payment", label: "Supplier payment" },
            { value: "customer_refund", label: "Refund to customer" },
            { value: "supplier_refund", label: "Refund from supplier" },
          ],
        },
        text("amount", "Amount", true, "money"),
        text("date", "Payment date", true, "date"),
        {
          key: "method",
          label: "Method",
          type: "select",
          options: ["cash", "bank", "upi"].map((value) => ({
            value,
            label: value,
          })),
          required: true,
        },
        text("reference", "Payment reference", true),
        {
          key: "invoiceId",
          label: "Allocate to invoice (optional)",
          type: "select",
          options: this.lookups()
            .filter(
              (e) =>
                ["invoices", "supplierInvoices"].includes(e.kind) &&
                e.data.status === "posted",
            )
            .map((e) => ({
              value: e.id,
              label:
                (e.kind === "supplierInvoices" ? "Supplier: " : "Customer: ") +
                (e.data.number ?? e.id),
            })),
        },
        text("allocationAmount", "Allocation amount", false, "money"),
        {
          key: "sourceId",
          label: "Credit / debit note (refunds only)",
          type: "select",
          options: this.lookups()
            .filter(
              (e) =>
                ["creditNotes", "debitNotes"].includes(e.kind) &&
                e.data.status === "posted",
            )
            .map((e) => ({ value: e.id, label: e.data.number ?? e.id })),
        },
        text("notes", "Notes"),
      ];
    else if (k === "tickets")
      this.fields = [
        text("subject", "Subject", true),
        text("message", "Describe the request", true),
        {
          key: "priority",
          label: "Priority",
          type: "select",
          options: ["normal", "high"].map((value) => ({ value, label: value })),
        },
      ];
    if (k === "materials")
      this.fields.push(
        text("width", "Fabric width (recorded unit)", false, "number"),
        text("gsm", "GSM", false, "number"),
      );
    const record = new FormRecord<FormControl<string>>({});
    for (const f of this.fields) {
      let value = "";
      const d = existing?.data as unknown as
        Record<string, unknown> | undefined;
      const initial = d?.[f.key];
      if (initial !== undefined)
        value =
          f.type === "money"
            ? this.amountInput(Number(initial))
            : Array.isArray(initial)
              ? initial.join(", ")
              : String(initial);
      else if (f.type === "date") value = this.today;
      else if (f.type === "money" || f.type === "number") value = "0";
      else if (f.options?.length && f.required) value = f.options[0].value;
      else if (f.key === "published") value = "false";
      record.addControl(
        f.key,
        new FormControl(value, {
          nonNullable: true,
          validators: f.required ? [Validators.required] : [],
        }),
      );
    }
    this.form = record;
    this.lines = [];
    this.sizes = [];
    this.materials = [];
    this.costLines = [];
    if (k === "sales" || k === "purchases") this.addLine();
    if (k === "cutting") this.addSize();
    if (k === "production") this.materials.push({ itemId: "", quantity: 1 });
    this.drawer.set(true);
    setTimeout(() =>
      document.querySelector<HTMLElement>('[role="dialog"] input')?.focus(),
    );
  }
  addLine() {
    this.lines.push({
      itemId: "",
      quantity: 1,
      rate: 0,
      discount: 0,
      taxBps: 0,
      taxMode: "none",
    });
  }
  addSize() {
    this.sizes.push({
      size: "",
      color: "",
      planned: 0,
      actual: 0,
      rejected: 0,
    });
  }
  itemSelected(l: Line) {
    const d = this.lookups().find((e) => e.id === l.itemId)?.data;
    l.rate = this.view() === "sales" ? (d?.price ?? 0) : (d?.cost ?? 0);
  }
  setLineMoney(l: Line, field: "rate" | "discount", event: Event) {
    try {
      l[field] = this.minor((event.target as HTMLInputElement).value);
      this.error.set("");
    } catch (e) {
      this.error.set(this.api.error(e));
    }
  }
  lineTotal(l: Line) {
    const net = (l.gross ?? Math.round(l.quantity * l.rate)) - l.discount;
    return (
      net +
      (l.taxAmount ??
        (l.taxMode === "none" ? 0 : Math.round((net * l.taxBps) / 10000)))
    );
  }
  isReturnModule() {
    return returnModules.includes(this.view());
  }
  sourceChanged(key: string) {
    if (key === "sourceId" && this.isReturnModule()) this.returnQuantities = {};
  }
  returnSource() {
    return this.lookups().find((e) => e.id === this.fieldValue("sourceId"));
  }
  returnRemaining(line: Line) {
    if (["creditNotes", "debitNotes"].includes(this.view()))
      return Math.max(0, line.quantity - (line.creditedQuantity ?? 0));
    return Math.max(
      0,
      (this.view() === "supplierReturns"
        ? Math.min(line.received ?? 0, line.invoiced ?? 0)
        : line.quantity) - (line.returned ?? 0),
    );
  }
  lineGrandTotal() {
    return this.lines.reduce((s, l) => s + this.lineTotal(l), 0);
  }
  async save() {
    this.form.markAllAsTouched();
    if (this.form.invalid) return;
    this.busy.set(true);
    this.error.set("");
    try {
      const raw = this.form.getRawValue();
      const payload: Record<string, unknown> = {};
      for (const field of this.fields) {
        const value = raw[field.key];
        if (
          value === "" &&
          !field.required &&
          [
            "sourceId",
            "partyId",
            "dueDate",
            "invoiceId",
            "allocationAmount",
            "returnId",
          ].includes(field.key)
        )
          continue;
        payload[field.key] =
          field.type === "money"
            ? this.minor(value || "0")
            : field.type === "number"
              ? Number(value)
              : value;
      }
      const k = this.view();
      if (["products", "materials"].includes(k)) {
        payload["tags"] = String(payload["tags"] ?? "")
          .split(",")
          .map((v) => v.trim())
          .filter(Boolean);
        payload["published"] = payload["published"] === "true";
        payload["status"] = "active";
      }
      if (["accounts", "parties", "categories", "warehouses"].includes(k))
        payload["status"] = "active";
      if (k === "staff") payload["active"] = true;
      if (k === "sales" || k === "purchases") payload["lines"] = this.lines;
      if (k === "journals") payload["journalLines"] = this.journalLines;
      if (returnModules.includes(k))
        payload["quantities"] = Object.entries(this.returnQuantities)
          .filter(([, quantity]) => quantity > 0)
          .map(([itemId, quantity]) => ({ itemId, quantity }));
      if (k === "production") {
        payload["materialLines"] = this.materials;
        payload["costLines"] = this.costLines;
      }
      if (k === "cutting") payload["sizes"] = this.sizes;
      if (k === "payments") {
        const invoiceId = payload["invoiceId"];
        payload["allocations"] = invoiceId
          ? [{ invoiceId, amount: payload["allocationAmount"] }]
          : [];
        delete payload["invoiceId"];
        delete payload["allocationAmount"];
      }
      const path = k === "users" ? "/users" : "/records/" + k;
      if (this.editId)
        await this.api.put(
          path + "/" + this.editId,
          { version: this.editVersion, data: payload },
          this.formKey,
        );
      else await this.api.post(path, payload, this.formKey);
      this.drawer.set(false);
      this.notify(this.editId ? "Changes saved" : "Record created");
      await this.reload();
    } catch (e) {
      this.error.set(this.api.error(e));
    } finally {
      this.busy.set(false);
    }
  }
  async openDetail(row: Entry) {
    this.previousFocus = document.activeElement as HTMLElement;
    this.detail.set(row);
    this.actionKey = crypto.randomUUID();
    this.actionQuantities = {};
    this.dispatchTransport = "";
    this.dispatchVehicle = "";
    this.dispatchEway = "";
    this.dispatchGatePass = "";
    this.postingDate = this.today;
    this.accepted = row.data.quantity ?? 0;
    this.rejected = 0;
    this.reversalReason = "";
    this.error.set("");
    setTimeout(() =>
      document.querySelector<HTMLElement>('[role="dialog"] button')?.focus(),
    );
  }
  async action(action: string) {
    const e = this.detail();
    if (!e) return;
    if (
      ["reverse", "void"].includes(action) &&
      !window.confirm(
        action === "reverse"
          ? "Post a permanent reversal with the entered reason?"
          : "Void this draft?",
      )
    )
      return;
    this.busy.set(true);
    this.error.set("");
    try {
      const payload: Record<string, unknown> = {
        action,
        postingDate: this.postingDate,
      };
      if (["receive", "dispatch", "return"].includes(action))
        payload["quantities"] = Object.entries(this.actionQuantities)
          .filter(([, quantity]) => quantity > 0)
          .map(([itemId, quantity]) => ({ itemId, quantity }));
      if (
        action === "complete" ||
        (e.kind === "jobwork" && action === "receive")
      ) {
        delete payload["quantities"];
        payload["finished"] = this.accepted;
        payload["rejected"] = this.rejected;
      }
      if (action === "reverse") payload["reason"] = this.reversalReason;
      if (action === "dispatch") {
        payload["transport"] = this.dispatchTransport.trim();
        payload["vehicle"] = this.dispatchVehicle.trim();
        payload["eway"] = this.dispatchEway.trim();
        payload["gatePass"] = this.dispatchGatePass.trim();
      }
      const updated = await this.api.post<Entry>(
        `/records/${e.kind}/${e.id}/actions`,
        payload,
        this.actionKey,
      );
      this.detail.set(updated);
      this.actionKey = crypto.randomUUID();
      this.notify("Operation posted successfully");
      await this.reload();
    } catch (err) {
      this.error.set(this.api.error(err));
    } finally {
      this.busy.set(false);
    }
  }
  editable(row: Entry) {
    return (
      [
        "accounts",
        "products",
        "materials",
        "parties",
        "categories",
        "warehouses",
        "staff",
      ].includes(row.kind) && this.api.can(row.kind)
    );
  }
  async archive(row: Entry) {
    if (
      !window.confirm(
        "Archive this master record? Existing history will remain available.",
      )
    )
      return;
    try {
      await this.api.put(`/records/${row.kind}/${row.id}`, {
        version: row.version,
        data: { ...row.data, status: "archived" },
      });
      this.detail.set(null);
      await this.reload();
    } catch (e) {
      this.error.set(this.api.error(e));
    }
  }
  async createInvoice(row: Entry) {
    this.detail.set(null);
    await this.navigate("invoices");
    await this.openCreate();
    this.form.controls["sourceId"].setValue(row.id);
  }
  async toggleUser(row: Entry) {
    try {
      await this.api.put("/users/" + row.id, {
        role: row.data.role,
        active: !row.data.active,
      });
      await this.reload();
    } catch (e) {
      this.error.set(this.api.error(e));
    }
  }
  async adjustStock() {
    await this.loadLookups();
    this.fields = [
      {
        key: "itemId",
        label: "Item",
        type: "select",
        required: true,
        options: this.items().map((e) => ({
          value: e.id,
          label: e.data.name ?? e.id,
        })),
      },
      {
        key: "quantity",
        label: "Signed adjustment quantity",
        type: "number",
        required: true,
      },
      { key: "reason", label: "Reason", required: true },
      { key: "date", label: "Date", type: "date", required: true },
    ];
    this.form = new FormRecord<FormControl<string>>({});
    for (const f of this.fields)
      this.form.addControl(
        f.key,
        new FormControl(f.type === "date" ? this.today : "", {
          nonNullable: true,
          validators: Validators.required,
        }),
      );
    this.formKey = crypto.randomUUID();
    this.drawer.set(true);
    this.editId = "__adjust";
  }
  async saveAdjustment() {
    this.form.markAllAsTouched();
    if (this.form.invalid) return;
    this.busy.set(true);
    try {
      const p = this.form.getRawValue();
      await this.api.post(
        "/stock/adjust",
        { ...p, quantity: Number(p["quantity"]) },
        this.formKey,
      );
      this.drawer.set(false);
      this.notify("Stock adjustment posted");
      await this.reload();
    } catch (e) {
      this.error.set(this.api.error(e));
    } finally {
      this.busy.set(false);
    }
  }
  async transferStock() {
    await this.adjustStock();
    this.editId = "__transfer";
    const options = [
      { value: "default", label: "Default" },
      ...this.options("warehouses").map((e) => ({
        value: e.id,
        label: e.data.name ?? e.id,
      })),
    ];
    this.fields.push(
      {
        key: "sourceWarehouseId",
        label: "From location",
        type: "select",
        required: true,
        options,
      },
      {
        key: "destinationWarehouseId",
        label: "To location",
        type: "select",
        required: true,
        options,
      },
    );
    this.form.addControl(
      "sourceWarehouseId",
      new FormControl("default", {
        nonNullable: true,
        validators: Validators.required,
      }),
    );
    this.form.addControl(
      "destinationWarehouseId",
      new FormControl("", {
        nonNullable: true,
        validators: Validators.required,
      }),
    );
  }
  async saveTransfer() {
    this.form.markAllAsTouched();
    if (this.form.invalid) return;
    this.busy.set(true);
    try {
      const p = this.form.getRawValue();
      await this.api.post(
        "/stock/transfer",
        { ...p, quantity: Number(p["quantity"]) },
        this.formKey,
      );
      this.drawer.set(false);
      this.notify("Warehouse transfer posted");
      await this.reload();
    } catch (e) {
      this.error.set(this.api.error(e));
    } finally {
      this.busy.set(false);
    }
  }
  setJournalMoney(
    line: { debit: number; credit: number },
    field: "debit" | "credit",
    event: Event,
  ) {
    try {
      line[field] = this.minor((event.target as HTMLInputElement).value);
      this.error.set("");
    } catch (e) {
      this.error.set(this.api.error(e));
    }
  }
  async saveSettings(form: HTMLFormElement) {
    if (!form.reportValidity()) return;
    const data = new FormData(form);
    this.busy.set(true);
    try {
      await this.api.put("/settings", {
        name: String(data.get("name")),
        address: String(data.get("address")),
        gstin: String(data.get("gstin")),
        currency: String(data.get("currency")),
        timezone: String(data.get("timezone")),
        financialYearStart: Number(data.get("financialYearStart")),
        businessType: String(data.get("businessType")),
        stages: String(data.get("stages"))
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        catalogEnabled: data.get("catalogEnabled") === "on",
      });
      await this.api.me();
      this.notify("Business settings saved");
    } catch (e) {
      this.error.set(this.api.error(e));
    } finally {
      this.busy.set(false);
    }
  }
  async catalogNext(delta: number) {
    const id = new URLSearchParams(location.search).get("catalog");
    this.catalogPage += delta;
    try {
      this.catalog.set(
        await this.api.get(`/catalog/${id}?page=${this.catalogPage}`),
      );
    } catch (e) {
      this.catalogPage -= delta;
      this.error.set(this.api.error(e));
    }
  }
  async closePeriod() {
    if (!this.closeThrough) return;
    if (
      !window.confirm(
        "Close accounting through " +
          this.closeThrough +
          "? Backdated postings on or before this date will be rejected. The lock cannot be moved backwards.",
      )
    )
      return;
    this.busy.set(true);
    try {
      await this.api.post("/accounting/close", { through: this.closeThrough });
      await this.api.me();
      this.notify("Accounting period closed");
    } catch (e) {
      this.error.set(this.api.error(e));
    } finally {
      this.busy.set(false);
    }
  }
  totalTrial(field: "debit" | "credit") {
    return this.trial().reduce((s, r) => s + r[field], 0);
  }
  exportCsv() {
    let records: Record<string, unknown>[];
    if (this.view() === "ledger")
      records = this.ledger().map((x) => ({ ...x }));
    else if (this.view() === "reports")
      records = [
        ...this.trial().map((x) => ({ report: "Trial balance", ...x })),
        ...Object.entries(this.financial()?.profitAndLoss ?? {}).map(
          ([account, amountMinor]) => ({
            report: "Profit/loss",
            account,
            amountMinor,
            currency: this.currency(),
          }),
        ),
        ...Object.entries(this.financial()?.balanceSheet ?? {}).map(
          ([account, amountMinor]) => ({
            report: "Balance sheet",
            account,
            amountMinor,
            currency: this.currency(),
          }),
        ),
        ...(this.ageing()?.data ?? []).map((x) => ({
          report: "Invoice ageing",
          ...x,
          amountMinor: x.amount,
          currency: this.currency(),
        })),
      ];
    else if (this.view() === "stock")
      records = this.stock().map((x) => ({
        item: this.lookup(x._id.itemId),
        warehouse: this.lookup(x._id.warehouseId),
        quantity: x.quantity,
      }));
    else records = this.rows().map((x) => ({ id: x.id, ...x.data }));
    if (!records.length) return;
    const keys = [...new Set(records.flatMap(Object.keys))];
    const escape = (v: unknown) =>
      '"' +
      String(typeof v === "object" ? JSON.stringify(v) : (v ?? ""))
        .replace(/^[=+@-]/, "'$&")
        .replace(/"/g, '""') +
      '"';
    const blob = new Blob(
      [
        "\ufeff" +
          [
            keys.map(escape).join(","),
            ...records.map((r) => keys.map((k) => escape(r[k])).join(",")),
          ].join("\r\n"),
      ],
      { type: "text/csv;charset=utf-8;" },
    );
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `sellease-${this.view()}-${this.today}.csv`;
    link.click();
    URL.revokeObjectURL(link.href);
    this.notify("Visible results exported");
  }
  print() {
    window.print();
  }
  readonlyKeys(data: Data) {
    return Object.entries(data).filter(
      ([key, value]) =>
        ![
          "lines",
          "sizes",
          "materialLines",
          "costLines",
          "journalLines",
          "allocations",
          "stages",
          "businessSnapshot",
          "partySnapshot",
          "actor",
          "quantityMilli",
          "sourceKind",
          "sourceId",
          "sourceVersion",
          "completed",
          "issued",
        ].includes(key) &&
        value !== undefined &&
        value !== "",
    );
  }
  pretty(key: string) {
    return key
      .replace(/Id$/, "")
      .replace(/([A-Z])/g, " $1")
      .replace(/^./, (s) => s.toUpperCase());
  }
  valueText(key: string, value: unknown) {
    if (
      [
        "amount",
        "total",
        "subtotal",
        "tax",
        "discount",
        "paid",
        "credited",
        "refunded",
        "cost",
        "price",
        "actualCost",
        "value",
      ].includes(key)
    )
      return this.money(Number(value));
    if (key.endsWith("Id")) return this.lookup(String(value));
    if (key === "flow")
      return String(value)
        .replace(/_/g, " ")
        .replace(/^./, (s) => s.toUpperCase());
    if (Array.isArray(value)) return value.join(", ");
    return String(value);
  }
}
