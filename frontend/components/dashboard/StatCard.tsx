import { Card } from "../ui/Card";
export function StatCard({ label, value, tone="blue" }: { label:string; value:number|string; tone?:string }) { return <Card className="p-5"><div className="mb-5 flex items-center justify-between"><span className="eyebrow">{label}</span><span className={`h-2 w-2 rounded-full bg-${tone}-500`}/></div><div className="text-3xl font-bold">{value}</div></Card>; }
