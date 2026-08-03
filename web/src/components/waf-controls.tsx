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

  const showComma = current.techniques.includes("multi_comma");
  const showPad = current.techniques.includes("pad");
  const showTypeKey = current.techniques.some((id) =>
    ["key_underscore", "key_hyphen", "key_mixed"].includes(id),
  );
  const showGhost = current.techniques.some((id) =>
    ["hex_ghost", "unicode_digit", "ghost_bits"].includes(id),
  );
  const showOptions = showComma || showPad || showTypeKey || showGhost;

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

      {showOptions ? (
        <div className="grid gap-3 sm:grid-cols-3">
          {showComma ? (
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
          ) : null}
          {showPad ? (
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
          ) : null}
          {showTypeKey ? (
            <div className="space-y-1">
              <Label className="opacity-0">.</Label>
              <Button
                type="button"
                variant={
                  current.options.include_type_key ? "default" : "outline"
                }
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
          ) : null}
          {showGhost && current.techniques.includes("hex_ghost") ? (
            <div className="space-y-1">
              <Label htmlFor="waf-hex-ghost-filler">hex_ghost 填充符</Label>
              <Input
                id="waf-hex-ghost-filler"
                maxLength={1}
                value={current.options.hex_ghost_filler ?? "_"}
                onChange={(e) =>
                  patchOptions({
                    hex_ghost_filler: (e.target.value || "_").slice(0, 1),
                  })
                }
              />
            </div>
          ) : null}
          {showGhost && current.techniques.includes("unicode_digit") ? (
            <div className="space-y-1">
              <Label htmlFor="waf-unicode-digit">unicode_digit 字形</Label>
              <Input
                id="waf-unicode-digit"
                placeholder="fullwidth|thai|gurmukhi"
                value={current.options.unicode_digit_script ?? "fullwidth"}
                onChange={(e) =>
                  patchOptions({
                    unicode_digit_script: e.target.value || "fullwidth",
                  })
                }
              />
            </div>
          ) : null}
          {showGhost && current.techniques.includes("ghost_bits") ? (
            <div className="space-y-1">
              <Label htmlFor="waf-ghost-k">ghost_bits 高字节 k</Label>
              <Input
                id="waf-ghost-k"
                value={String(current.options.ghost_k ?? 1)}
                onChange={(e) =>
                  patchOptions({ ghost_k: Number(e.target.value) || 1 })
                }
              />
            </div>
          ) : null}
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
