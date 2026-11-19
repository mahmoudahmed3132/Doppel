// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// Attack path view (attack_path projection): source picker populated from the
// sources projection plus free-text IP input and ?source= deep linking,
// horizontal kill-chain stepper, tactic progression bar, and chronological
// timeline table.
import { Fragment } from "preact";
import { useEffect, useState } from "preact/hooks";
import { enc, qs } from "../../api";
import { fmtNum, fmtTime } from "../../format";
import { Link, navigate, useLocation } from "../../router";
import type { EventRecord } from "../../types";
import { Alert, Button, Card, Empty, ErrorBox, Loading, PageHead, Pill, SeverityBadge } from "../../ui";
import { criticalityKind, DaysSelect, useProjection } from "./common";
import type { AssetMatch, AttackTactic, SourceProfile } from "./common";

interface PathStep {
  nodeId: string;
  sensorId: string;
  firstSeen: string;
  lastSeen: string;
  events: number;
  maxSeverity: string;
  triggers: string[];
  techniques: string[];
}

interface ProgressStep {
  firstSeen: string;
  technique: string;
  name: string;
  tactics: AttackTactic[];
}

interface PathDTO {
  source: string;
  asset: AssetMatch | null;
  events: number;
  truncated: boolean;
  firstSeen: string;
  lastSeen: string;
  steps: PathStep[];
  progression: ProgressStep[];
  timeline: EventRecord[];
}

export function AttackPathPage() {
  const { query } = useLocation();
  const urlSource = (query.get("source") ?? "").trim();

  const [days, setDays] = useState(30);
  const [inputSource, setInputSource] = useState(urlSource);

  useEffect(() => {
    setInputSource(urlSource);
  }, [urlSource]);

  const sourcesList = useProjection<{ sources: SourceProfile[] }>("sources", { days });
  const pathData = useProjection<PathDTO>("attack_path", { days, source: urlSource || undefined });

  const selectSource = (src: string) => {
    const clean = src.trim();
    setInputSource(clean);
    navigate(`/attack-path${qs({ source: clean || undefined })}`, true);
  };

  const topSources = (sourcesList.data?.sources ?? []).slice(0, 50);
  const dto = pathData.data;

  return (
    <div class="stack-lg">
      <PageHead
        title="Attack path"
        sub="Lateral progression of a single source across decoys, triggers, and MITRE ATT&CK tactics."
        actions={<DaysSelect days={days} onChange={setDays} />}
      />

      <Card>
        <form
          class="path-picker"
          onSubmit={(e) => {
            e.preventDefault();
            selectSource(inputSource);
          }}
        >
          <label class="filter">
            <span>Top sources</span>
            <select
              class="input mono"
              value={topSources.some((s) => s.source === (urlSource || dto?.source)) ? (urlSource || dto?.source || "") : ""}
              onChange={(e) => selectSource(e.currentTarget.value)}
            >
              <option value="">Busiest source (auto)</option>
              {topSources.map((s) => (
                <option key={s.source} value={s.source}>
                  {s.source} ({s.events} events · {s.decoys} {s.decoys === 1 ? "decoy" : "decoys"})
                </option>
              ))}
            </select>
          </label>
          <label class="filter path-picker-input">
            <span>Source IP or identifier</span>
            <input
              class="input mono"
              placeholder="e.g. 203.0.113.10"
              maxLength={256}
              value={inputSource}
              onInput={(e) => setInputSource(e.currentTarget.value)}
            />
          </label>
          <div class="row path-picker-actions">
            <Button type="submit" variant="primary">Trace</Button>
            {urlSource ? (
              <Button variant="ghost" onClick={() => selectSource("")}>Clear</Button>
            ) : null}
          </div>
        </form>
      </Card>

      <ErrorBox error={pathData.error} retry={pathData.reload} />

      {pathData.loading && !dto ? (
        <Loading />
      ) : dto ? (
        dto.events === 0 ? (
          <Card>
            <Empty>
              {dto.source
                ? `No attacker events found for "${dto.source}" in the selected window.`
                : "No attacker events in the selected window."}
            </Empty>
          </Card>
        ) : (
          <>
            {dto.truncated ? (
              <Alert kind="warn">
                <span>This source exceeded 2,000 events in the window. Showing the earliest 2,000 events.</span>
              </Alert>
            ) : null}

            <div class="counters counters-4">
              <div class="counter">
                <div class="counter-value mono path-source-val" title={dto.source}>{dto.source}</div>
                <div class="counter-label">
                  Source{" "}
                  {dto.asset ? (
                    <Pill kind={criticalityKind(dto.asset.criticality)}>
                      {dto.asset.name} ({dto.asset.criticality})
                    </Pill>
                  ) : null}
                </div>
              </div>
              <div class="counter">
                <div class="counter-value">{fmtNum(dto.events)}</div>
                <div class="counter-label">Events</div>
              </div>
              <div class="counter">
                <div class="counter-value">{fmtNum(dto.steps.length)}</div>
                <div class="counter-label">Decoys touched</div>
              </div>
              <div class="counter">
                <div class="counter-value">{fmtNum(dto.progression.length)}</div>
                <div class="counter-label">Tactic milestones</div>
              </div>
            </div>

            <Card
              title="Kill-chain path"
              actions={
                <span class="muted">
                  {fmtTime(dto.firstSeen)} → {fmtTime(dto.lastSeen)}
                </span>
              }
            >
              <div class="killchain-scroll" role="region" aria-label="Attack kill-chain steps" tabIndex={0}>
                <ol class="killchain">
                  {dto.steps.map((step, i) => (
                    <Fragment key={`${step.nodeId}/${step.sensorId}`}>
                      {i > 0 ? (
                        <li class="killchain-arrow" aria-hidden="true">
                          <svg width="28" height="20" viewBox="0 0 28 20">
                            <path class="killchain-arrow-path" d="M2 10h21m-6-6 6 6-6 6" />
                          </svg>
                        </li>
                      ) : null}
                      <li class={`killchain-step killchain-sev-${step.maxSeverity}`}>
                        <div class="row between">
                          <span class="killchain-num">Step {i + 1}</span>
                          <SeverityBadge sev={step.maxSeverity} />
                        </div>
                        <div class="killchain-target">
                          <Link href={`/fleet/${enc(step.nodeId)}`} class="mono strong">{step.nodeId}</Link>
                          <div class="mono muted">{step.sensorId}</div>
                        </div>
                        <div class="killchain-meta muted">
                          <div>{fmtNum(step.events)} {step.events === 1 ? "event" : "events"}</div>
                          <div>First: {fmtTime(step.firstSeen)}</div>
                          <div>Last: {fmtTime(step.lastSeen)}</div>
                        </div>
                        {step.triggers?.length ? (
                          <div class="killchain-tags">
                            {step.triggers.map((tr) => (
                              <span key={tr} class="tag mono">{tr}</span>
                            ))}
                          </div>
                        ) : null}
                        {step.techniques?.length ? (
                          <div class="killchain-tags">
                            {step.techniques.map((tech) => (
                              <Pill key={tech} kind="info">{tech}</Pill>
                            ))}
                          </div>
                        ) : null}
                      </li>
                    </Fragment>
                  ))}
                </ol>
              </div>
            </Card>

            <Card title="Tactic progression">
              {dto.progression?.length ? (
                <ol class="progression">
                  {dto.progression.map((p, i) => (
                    <li class="progression-item" key={`${p.technique}-${i}`}>
                      <div class="progression-tactics">
                        {(p.tactics ?? []).map((t) => (
                          <Pill key={t.id} kind="info">{t.name}</Pill>
                        ))}
                      </div>
                      <div class="progression-tech">
                        <span class="mono strong">{p.technique}</span> {p.name}
                      </div>
                      <div class="muted">{fmtTime(p.firstSeen)}</div>
                    </li>
                  ))}
                </ol>
              ) : (
                <Empty>No mapped MITRE ATT&amp;CK tactics for this source in the selected window.</Empty>
              )}
            </Card>

            <Card title={`Chronological timeline (${fmtNum(dto.timeline.length)})`}>
              <div class="table-wrap">
                <table class="table table-compact">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Severity</th>
                      <th>Node / Sensor</th>
                      <th>Trigger</th>
                      <th>Target</th>
                      <th>ATT&amp;CK</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dto.timeline.map((e) => (
                      <tr
                        key={e.seq || e.event_id}
                        class="row-click"
                        tabIndex={0}
                        onClick={() => navigate(`/events?open=${e.seq}`)}
                        onKeyDown={(ev) => {
                          if (ev.key === "Enter" || ev.key === " ") {
                            ev.preventDefault();
                            navigate(`/events?open=${e.seq}`);
                          }
                        }}
                      >
                        <td class="nowrap">{fmtTime(e.occurred_at)}</td>
                        <td><SeverityBadge sev={e.severity} /></td>
                        <td class="mono">{e.node_alias || e.node_id} / {e.sensor_id}</td>
                        <td class="mono">{e.trigger}</td>
                        <td class="mono">{e.target || "—"}</td>
                        <td>
                          {e.enrichment?.attack?.primary ? (
                            <span class="tag mono" title={e.enrichment.attack.primary.name}>
                              {e.enrichment.attack.primary.id}
                            </span>
                          ) : (
                            <span class="muted">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          </>
        )
      ) : null}
    </div>
  );
}
