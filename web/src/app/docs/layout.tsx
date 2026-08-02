import type { ReactNode } from "react";

import { DocsShell } from "@/components/docs-shell";
import { listDocs } from "@/lib/docs";

export default function DocsLayout({ children }: { children: ReactNode }) {
  const docs = listDocs();

  return <DocsShell docs={docs}>{children}</DocsShell>;
}
