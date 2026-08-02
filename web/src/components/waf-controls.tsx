"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";

import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { listWafTechniques, type WafOptions, type WafTechnique } from "@/lib/api";
import { cn } from "@/lib/utils";

export type WafControlValue = {
  techniques: string[];
  options: WafOptions;
};

const DEFAULT_VALUE: WafControlValue = {
  techniques: [],
  options: {
    comma_count: 5,
    pad_size: 20000,
    pad_key: "f",
    include_type_key: false,
  },
};

type Props = {
  value?: WafControlValue;
  onChange: (value: WafControlValue) => void;
};

export function WafControls({ value, onChange }: Props) {
  const current = value ?? DEFAULT_VALUE;
  const [catalog, setCatalog] = useState<WafTechnique[]>([]);

  useEffect(() => {
    void listWafTechniques()
      .then(setCatalog)
      .catch((err) => {
        toast.error(err instanceof Error ? err.message : String(err));
      });
  }, []);

  function toggle(id: string) {
    const techniques = current.techniques.includes(id)
      ? current.techniques.filter((x) => x !== id)
      : [...current.techniques, id];
    onChange({ ...current, techniques });
  }

  function patchOptions(patch: Partial<WafOptions>) {
    onChange({
      ...current,
      options: { ...current.options, ...patch },
    });
  }

  return (
    <div className="space-y-3 rounded-lg border p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-sm font-medium">WAF 绕过（生成时叠加）</div>
          <p className="text-xs text-muted-foreground">
            可选；按点击顺序叠加。不选则输出原始 payload。
          </p>
        </div>
        <div className="flex gap-1">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() =>
              onChange({
                ...current,
                techniques: catalog.map((t) => t.id),
              })
            }
          >
            全选
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => onChange({ ...current, techniques: [] })}
          >
            清空
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        {catalog.map((t) => {
          const on = current.techniques.includes(t.id);
          return (
            <button
              key={t.id}
              type="button"
              title={t.description}
              onClick={() => toggle(t.id)}
              className={cn(
                buttonVariants({
                  variant: on ? "default" : "outline",
                  size: "sm",
                }),
              )}
            >
              {t.title}
            </button>
          );
        })}
      </div>

      {current.techniques.length > 0 ? (
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="space-y-1">
            <Label htmlFor="waf-comma">多逗号数量</Label>
            <Input
              id="waf-comma"
              value={String(current.options.comma_count ?? 5)}
              onChange={(e) =>
                patchOptions({ comma_count: Number(e.target.value) || 5 })
              }
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="waf-pad">填充长度</Label>
            <Input
              id="waf-pad"
              value={String(current.options.pad_size ?? 20000)}
              onChange={(e) =>
                patchOptions({ pad_size: Number(e.target.value) || 20000 })
              }
            />
          </div>
          <div className="space-y-1">
            <Label className="opacity-0">.</Label>
            <Button
              type="button"
              variant={current.options.include_type_key ? "default" : "outline"}
              className="w-full"
              onClick={() =>
                patchOptions({
                  include_type_key: !current.options.include_type_key,
                })
              }
            >
              key 变换含 @type
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

export function emptyWafControlValue(): WafControlValue {
  return {
    techniques: [],
    options: { ...DEFAULT_VALUE.options },
  };
}
