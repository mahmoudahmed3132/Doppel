// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// MITRE ATT&CK Enterprise matrix view (attack_matrix projection) with
// discrete CSS heat classes, secondary-only markers, slide-over technique
// detail drawer, and ATT&CK Navigator JSON layer download.
import { useMemo, useState } from "preact/hooks";
import { qs } from "../../api";
import { systemStatus } from "../../app";
import { fmtNum, fmtTime } from "../../format";
import { Link } from "../../router";
import { useStore } from "../../store";
import { Card, Empty, ErrorBox, KV, Loading, Modal, PageHead, Pill } from "../../ui";
import { DaysSelect, ModuleMissing, useProjection } from "./common";
import type { AttackTactic, TechniqueStat } from "./common";

interface AttackMatrixDTO {
  timeframe: string;
  mappedEvents: number;
  techniquesObserved: number;
  techniquesCovered: number;
  tactics: AttackTactic[];
  techniques: TechniqueStat[];
}

function matrixHeatClass(primary: number, maxPrimary: number): string {
  if (primary <= 0 || maxPrimary <= 0) return "heat-0";
  const ratio = primary / maxPrimary;
  if (ratio >= 0.75) return "heat-4";
  if (ratio >= 0.4) return "heat-3";
  if (ratio >= 0.15) return "heat-2";
  return "heat-1";
}

export function AttackMatrixPage() {
  const st = useStore(systemStatus);
  const [days, setDays] = useState(30);
  const [observedOnly, setObservedOnly] = useState(false);
  const [selected, setSelected] = useState<TechniqueStat | null>(null);

  const matrixInstalled = !!st?.modules.projections.includes("attack_matrix");
  const matrix = useProjection<AttackMatrixDTO>("attack_matrix", { days }, !!st?.modules.attack && matrixInstalled);

  const tacticNames = useMemo(() => {
    const map = new Map<string, string>();
    for (const tc of matrix.data?.tactics ?? []) map.set(tc.id, tc.name);
    return map;
  }, [matrix.data]);

  const { columns, maxPrimary } = useMemo(() => {
    const dto = matrix.data;
    if (!dto) return { columns: [] as { tactic: AttackTactic; items: TechniqueStat[]; observed: number }[], maxPrimary: 0 };
    let maxP = 0;
    for (const t of dto.techniques ?? []) {
      if (t.primaryEvents > maxP) maxP = t.primaryEvents;
    }
    const cols = (dto.tactics ?? []).map((tactic) => {
      const all = (dto.techniques ?? []).filter((t) => (t.tactics ?? []).includes(tactic.id));
      const observed = all.filter((t) => t.primaryEvents + t.secondaryEvents > 0).length;
      const items = observedOnly ? all.filter((t) => t.primaryEvents + t.secondaryEvents > 0) : all;
      items.sort((a, b) => (b.primaryEvents - a.primaryEvents) || (b.secondaryEvents - a.secondaryEvents) || a.id.localeCompare(b.id));
      return { tactic, items, observed };
    }).filter((c) => c.items.length > 0);
    return { columns: cols, maxPrimary: maxP };
  }, [matrix.data, observedOnly]);

  if (!st) return <Loading />;
  if (!st.modules.attack) {
    return (
      <div class="stack-lg">
        <PageHead title="ATT&CK" />
        <ModuleMissing name="ATT&CK mapping" />
      </div>
    );
  }

  const dto = matrix.data;
  const coveragePct = dto && dto.techniquesCovered > 0 ? Math.round((dto.techniquesObserved / dto.techniquesCovered) * 100) : 0;

  return (
    <div class="stack-lg">
      <PageHead
        title="ATT&CK"
        sub="Techniques observed across the fleet, mapped to MITRE ATT&CK Enterprise tactics."
        actions={
          <>
            <DaysSelect days={days} onChange={setDays} />
            <a class="btn btn-sm" href={`/api/v3/analytics/attack/navigator${qs({ days })}`} download>
              Navigator layer
            </a>
          </>
        }
      />
      {!matrixInstalled ? (
        <Card title="Matrix">
          <p class="muted">
            The matrix projection is not installed; download the Navigator layer to view it in ATT&amp;CK Navigator.
          </p>
        </Card>
      ) : matrix.error ? (
        <ErrorBox error={matrix.error} retry={matrix.reload} />
      ) : matrix.loading && !dto ? (
        <Loading />
      ) : dto ? (
        <>
          <div class="counters counters-3">
            <div class="counter">
              <div class="counter-value">{fmtNum(dto.mappedEvents)}</div>
              <div class="counter-label">Mapped events</div>
            </div>
            <div class="counter">
              <div class="counter-value">{dto.techniquesObserved} / {dto.techniquesCovered}</div>
              <div class="counter-label">Techniques observed ({coveragePct}%)</div>
            </div>
            <div class="counter">
              <div class="counter-value">{columns.filter((c) => c.observed > 0).length} / {columns.length}</div>
              <div class="counter-label">Active tactics</div>
            </div>
          </div>

          <Card
            title="Enterprise matrix"
            actions={
              <label class="check matrix-toggle">
                <input
                  type="checkbox"
                  checked={observedOnly}
                  onChange={(e) => setObservedOnly(e.currentTarget.checked)}
                />
                <span>Observed only</span>
              </label>
            }
          >
            {columns.length ? (
              <div class="stack">
                <div class="matrix-scroll" role="region" aria-label="MITRE ATT&CK Matrix" tabIndex={0}>
                  <div class="matrix-grid">
                    {columns.map(({ tactic, items, observed }) => (
                      <div class="matrix-col" key={tactic.id}>
                        <div class="matrix-col-head">
                          <div class="matrix-tactic-name">{tactic.name}</div>
                          <div class="matrix-tactic-meta muted mono">
                            {tactic.id} · {observed}/{items.length}
                          </div>
                        </div>
                        <div class="matrix-cells">
                          {items.map((t) => {
                            const secondaryOnly = t.primaryEvents === 0 && t.secondaryEvents > 0;
                            const heat = matrixHeatClass(t.primaryEvents, maxPrimary);
                            return (
                              <button
                                type="button"
                                key={`${tactic.id}-${t.id}`}
                                class={`matrix-cell matrix-${heat}${secondaryOnly ? " secondary-only" : ""}`}
                                onClick={() => setSelected(t)}
                                aria-label={`${t.id} ${t.name}: ${t.primaryEvents} primary, ${t.secondaryEvents} secondary events`}
                              >
                                <div class="matrix-cell-top">
                                  <span class="mono matrix-cell-id">{t.id}</span>
                                  {t.primaryEvents > 0 ? (
                                    <span class="matrix-cell-count num">{fmtNum(t.primaryEvents)}</span>
                                  ) : secondaryOnly ? (
                                    <span class="matrix-sec-dot" title="Secondary technique hits only">+{fmtNum(t.secondaryEvents)}</span>
                                  ) : null}
                                </div>
                                <div class="matrix-cell-name">{t.name}</div>
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
                <div class="matrix-legend" aria-hidden="true">
                  <span class="muted">Primary intensity:</span>
                  <span class="matrix-swatch matrix-heat-0">0</span>
                  <span class="matrix-swatch matrix-heat-1">low</span>
                  <span class="matrix-swatch matrix-heat-2">med</span>
                  <span class="matrix-swatch matrix-heat-3">high</span>
                  <span class="matrix-swatch matrix-heat-4">peak</span>
                  <span class="matrix-swatch matrix-heat-0 secondary-only">secondary only</span>
                </div>
              </div>
            ) : (
              <Empty>
                {observedOnly
                  ? "No techniques observed in this window. Uncheck \"Observed only\" to see covered techniques."
                  : "No ATT&CK techniques available."}
              </Empty>
            )}
          </Card>

          <Modal
            side
            open={!!selected}
            title={selected ? `${selected.id} — ${selected.name}` : "Technique"}
            onClose={() => setSelected(null)}
          >
            {selected ? (
              <div class="stack-lg">
                <KV
                  rows={[
                    ["Technique ID", <span class="mono">{selected.id}</span>],
                    ["Name", selected.name],
                    [
                      "Tactics",
                      <div class="row">
                        {(selected.tactics ?? []).map((id) => (
                          <Pill key={id} kind="info">{tacticNames.get(id) ?? id}</Pill>
                        ))}
                      </div>,
                    ],
                    ["Primary events", <span class="num strong">{fmtNum(selected.primaryEvents)}</span>],
                    ["Secondary events", <span class="num">{fmtNum(selected.secondaryEvents)}</span>],
                    ["Distinct sources", <span class="num">{fmtNum(selected.sources)}</span>],
                    ["Last seen", fmtTime(selected.lastSeen)],
                  ]}
                />
                <div class="stack">
                  <h3>Observed triggers</h3>
                  {selected.triggers?.length ? (
                    <div class="row">
                      {selected.triggers.map((tr) => (
                        <Link key={tr} href={`/events?trigger=${encodeURIComponent(tr)}`} class="tag mono">
                          {tr}
                        </Link>
                      ))}
                    </div>
                  ) : (
                    <p class="muted">No triggers observed for this technique in the selected window.</p>
                  )}
                </div>
              </div>
            ) : null}
          </Modal>
        </>
      ) : null}
    </div>
  );
}
