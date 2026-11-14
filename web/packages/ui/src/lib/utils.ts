export { cn } from "cn";

export type Defined<T> = { [K in keyof T]: Exclude<T[K], undefined> };

/** OP-159 m.31: drops the props that are `undefined`, for primitives typed with exact optional properties. */
export function defined<T extends object>(props: T): Defined<T> {
  return Object.fromEntries(
    Object.entries(props).filter(([, value]) => value !== undefined),
  ) as Defined<T>;
}
