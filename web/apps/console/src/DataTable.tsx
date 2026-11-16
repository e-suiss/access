// OP-159 m.46 (g), TN-131: a long list as a table on suiss/ui's Table markup. TanStack Table
// keeps the row model and TanStack Virtual renders only the rows in view once a list is long;
// short lists render every row. Every value renders as a text node.

import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@access/ui/components/table";
import { cn } from "@access/ui/lib/utils";
import { createColumnHelper, type RowData, tableFeatures, useTable } from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { type ReactElement, type ReactNode, useRef } from "react";

import { t } from "./i18n/index.js";
import { MONO } from "./ui.js";

/** One column: its header and what each row shows in it. */
export interface Column<T extends RowData> {
  readonly id: string;
  readonly header: ReactNode;
  readonly cell: (row: T) => ReactNode;
  readonly className?: string;
  /** The column that names the row (`<th scope="row">`). */
  readonly rowHeader?: boolean;
}

/** From how many rows on a list renders only the rows in view. */
const VIRTUAL_FROM = 60;

/** The estimated height of one row, in pixels, before it is measured. */
const ROW_PX = 44;

const features = tableFeatures({});

export function DataTable<T extends RowData>({
  rows,
  columns,
  rowKey,
  caption,
  label,
  className,
  rowProps,
  ...props
}: {
  readonly rows: readonly T[];
  readonly columns: readonly Column<T>[];
  readonly rowKey: (row: T, index: number) => string;
  /** A caption for screen readers. */
  readonly caption?: string;
  /** The accessible name of the scrolling region a long list renders in. */
  readonly label: string;
  readonly className?: string;
  readonly rowProps?: (row: T) => Readonly<Record<`data-${string}`, string>>;
  readonly "data-testid"?: string;
}): ReactElement {
  const helper = createColumnHelper<typeof features, T>();
  const table = useTable({
    features,
    columns: columns.map((c) =>
      helper.display({
        id: c.id,
        header: () => c.header,
        cell: (info) => c.cell(info.row.original),
      }),
    ),
    data: rows as T[],
    getRowId: (row: T, index: number) => rowKey(row, index),
  });
  const model = table.getRowModel().rows;
  const scroll = useRef<HTMLElement>(null);
  const virtual = model.length >= VIRTUAL_FROM;
  const virtualizer = useVirtualizer({
    count: virtual ? model.length : 0,
    getScrollElement: () => scroll.current,
    estimateSize: () => ROW_PX,
    overscan: 8,
  });
  const items = virtualizer.getVirtualItems();
  const shown = virtual
    ? items.map((i) => ({ row: model[i.index], index: i.index }))
    : model.map((row, index) => ({ row, index }));
  const before = virtual ? (items[0]?.start ?? 0) : 0;
  const after = virtual ? virtualizer.getTotalSize() - (items.at(-1)?.end ?? 0) : 0;

  const body = (
    <Table className={cn(caption === undefined ? undefined : "caption-top", className)} {...props}>
      {caption !== undefined && <TableCaption className="sr-only">{caption}</TableCaption>}
      <TableHeader>
        {table.getHeaderGroups().map((g) => (
          <TableRow key={g.id} className="hover:bg-transparent">
            {g.headers.map((h, i) => (
              <TableHead key={h.id} scope="col" className={columns[i]?.className}>
                <table.FlexRender header={h} />
              </TableHead>
            ))}
          </TableRow>
        ))}
      </TableHeader>
      <TableBody>
        {before > 0 && (
          <tr>
            <td
              colSpan={columns.length}
              aria-hidden="true"
              className="p-0"
              style={{ height: before }}
            />
          </tr>
        )}
        {shown.map(({ row, index }) =>
          row === undefined ? null : (
            <TableRow
              key={row.id}
              data-index={index}
              ref={virtual ? virtualizer.measureElement : undefined}
              {...rowProps?.(row.original)}
            >
              {row.getAllCells().map((cell, i) => {
                const c = columns[i];
                return c?.rowHeader === true ? (
                  <TableHead
                    key={cell.id}
                    scope="row"
                    className={cn("text-sm font-medium text-foreground", c.className)}
                  >
                    <table.FlexRender cell={cell} />
                  </TableHead>
                ) : (
                  <TableCell key={cell.id} className={c?.className}>
                    <table.FlexRender cell={cell} />
                  </TableCell>
                );
              })}
            </TableRow>
          ),
        )}
        {after > 0 && (
          <tr>
            <td
              colSpan={columns.length}
              aria-hidden="true"
              className="p-0"
              style={{ height: after }}
            />
          </tr>
        )}
      </TableBody>
    </Table>
  );
  if (!virtual) return body;
  return (
    <section
      ref={scroll}
      aria-label={label}
      className="max-h-[36rem] overflow-y-auto rounded-md outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
    >
      {body}
    </section>
  );
}

interface Result {
  readonly text: string;
  readonly at: number;
}

/** A search page's results, each as its JSON text (OP-151 m.8). */
export function ResultTable({
  results,
  ...props
}: {
  readonly results: readonly unknown[];
  readonly "data-testid"?: string;
}): ReactElement {
  const rows: readonly Result[] = results.map((r, at) => ({ text: JSON.stringify(r), at }));
  return (
    <DataTable
      rows={rows}
      rowKey={(r) => String(r.at)}
      label={t("resultsRegion")}
      columns={[{ id: "result", header: t("resultColumn"), className: MONO, cell: (r) => r.text }]}
      {...props}
    />
  );
}
