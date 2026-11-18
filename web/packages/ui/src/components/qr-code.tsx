// TN-155: a QR code drawn from its value in the page, as SVG elements; the value never leaves
// the browser and no markup string is built, so it renders under Trusted Types.
import qrcode from "qrcode-generator";
import { useMemo } from "react";

import { cn } from "@access/ui/lib/utils";

/** The QR code of `value`, error correction M, with a four-module quiet zone. */
function QrCode({
  value,
  label,
  className,
}: {
  readonly value: string;
  readonly label: string;
  readonly className?: string;
}) {
  const { size, path } = useMemo(() => {
    const qr = qrcode(0, "M");
    qr.addData(value, "Byte");
    qr.make();
    const n = qr.getModuleCount();
    const quiet = 4;
    let d = "";
    for (let row = 0; row < n; row += 1) {
      for (let col = 0; col < n; col += 1) {
        if (qr.isDark(row, col)) d += `M${col + quiet} ${row + quiet}h1v1h-1z`;
      }
    }
    return { size: n + quiet * 2, path: d };
  }, [value]);
  return (
    <svg
      data-slot="qr-code"
      role="img"
      aria-label={label}
      viewBox={`0 0 ${size} ${size}`}
      shapeRendering="crispEdges"
      className={cn("size-48 rounded-lg bg-white", className)}
    >
      <path d={path} fill="#000" />
    </svg>
  );
}

export { QrCode };
