export type Kind =
  | "products"
  | "materials"
  | "parties"
  | "warehouses"
  | "categories"
  | "staff"
  | "purchases"
  | "sales"
  | "production"
  | "cutting"
  | "jobwork"
  | "invoices"
  | "supplierInvoices"
  | "customerReturns"
  | "supplierReturns"
  | "creditNotes"
  | "debitNotes"
  | "accounts"
  | "challans"
  | "expenses"
  | "payments"
  | "movements"
  | "journals"
  | "tickets"
  | "notifications"
  | "audit";
export interface Line {
  itemId: string;
  quantity: number;
  rate: number;
  discount: number;
  taxBps: number;
  taxMode: "split" | "integrated" | "none";
  received?: number;
  dispatched?: number;
  invoiced?: number;
  returned?: number;
  creditedQuantity?: number;
  creditedGross?: number;
  creditedDiscount?: number;
  creditedCgst?: number;
  creditedSgst?: number;
  creditedIgst?: number;
  billedNet?: number;
  billedDiscount?: number;
  billedTax?: number;
  gross?: number;
  taxAmount?: number;
  costValue?: number;
  cgstAmount?: number;
  sgstAmount?: number;
  igstAmount?: number;
  name?: string;
  sku?: string;
  hsn?: string;
  unit?: string;
}
export interface SizeRow {
  size: string;
  color: string;
  planned: number;
  actual: number;
  rejected: number;
}
export interface JournalLine {
  account: string;
  debit: number;
  credit: number;
  partyId?: string;
}
export interface Data {
  accountType?: "asset" | "liability" | "equity" | "revenue" | "expense";
  postingDate?: string;
  businessSnapshot?: { name: string; address: string; gstin: string };
  partySnapshot?: { name: string; address: string; gstin: string };
  name?: string;
  sku?: string;
  description?: string;
  category?: string;
  unit?: string;
  price?: number;
  cost?: number;
  reorder?: number;
  status?: string;
  kind?: string;
  email?: string;
  phone?: string;
  address?: string;
  gstin?: string;
  hsn?: string;
  color?: string;
  size?: string;
  style?: string;
  width?: number;
  gsm?: number;
  lot?: string;
  supplierId?: string;
  warehouseId?: string;
  tags?: string[];
  published?: boolean;
  partyId?: string;
  date?: string;
  dueDate?: string;
  lines?: Line[];
  number?: string;
  notes?: string;
  total?: number;
  subtotal?: number;
  tax?: number;
  discount?: number;
  paid?: number;
  credited?: number;
  refunded?: number;
  returnId?: string;
  noted?: boolean;
  sourceId?: string;
  sourceVersion?: number;
  sourceKind?: string;
  reference?: string;
  itemId?: string;
  quantity?: number;
  quantityMilli?: number;
  balance?: number;
  reason?: string;
  direction?: string;
  value?: number;
  actor?: string;
  sizes?: SizeRow[];
  materialLines?: { itemId: string; quantity: number }[];
  stages?: string[];
  stage?: number;
  finished?: number;
  rejected?: number;
  outputItemId?: string;
  issued?: boolean;
  completed?: boolean;
  costLines?: { name: string; amount: number }[];
  actualCost?: number;
  amount?: number;
  method?: string;
  allocations?: { invoiceId: string; amount: number }[];
  flow?: string;
  journalLines?: JournalLine[];
  reversed?: boolean;
  role?: string;
  active?: boolean;
  vehicle?: string;
  eway?: string;
  transport?: string;
  acknowledged?: boolean;
  subject?: string;
  priority?: string;
  message?: string;
  rate?: number;
  returned?: number;
  accepted?: number;
  sourceWarehouseId?: string;
  destinationWarehouseId?: string;
}
export interface Entry {
  id: string;
  org: string;
  kind: Kind;
  data: Data;
  version: number;
  createdAt: string;
  updatedAt: string;
}
export interface Settings {
  closedThrough?: string;
  name: string;
  address: string;
  gstin: string;
  currency: string;
  timezone: string;
  financialYearStart: number;
  businessType: string;
  stages: string[];
  onboarding: {
    isMobileVerified: boolean;
    isPersonalInfoSaved: boolean;
    isBusinessInfoSaved: boolean;
    isAddressDetailSaved: boolean;
    isTransactionInfoSaved: boolean;
  };
  catalogEnabled: boolean;
}
export interface Actor {
  id: string;
  org: string;
  role: string;
  name: string;
}
export class DomainError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
export function fail(message: string, status = 400): never {
  throw new DomainError(status, message);
}
