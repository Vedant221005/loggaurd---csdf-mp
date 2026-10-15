import type { Severity } from "../../lib/types";
export function Badge({ value }: { value: Severity | string }) { return <span className={`badge badge-${value}`}>{value}</span>; }
