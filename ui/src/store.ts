// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
//
// Minimal observable values shared across components.
import { useEffect, useState } from "preact/hooks";

export interface Store<T> { get(): T; set(v: T): void; subscribe(fn: (v: T) => void): () => void }

export function store<T>(initial: T): Store<T> {
  let value = initial;
  const subs = new Set<(v: T) => void>();
  return {
    get: () => value,
    set(v) {
      if (Object.is(v, value)) return;
      value = v;
      subs.forEach((fn) => fn(v));
    },
    subscribe(fn) {
      subs.add(fn);
      return () => subs.delete(fn);
    },
  };
}

export function useStore<T>(s: Store<T>): T {
  const [v, setV] = useState(s.get());
  useEffect(() => {
    setV(s.get());
    return s.subscribe(setV);
  }, [s]);
  return v;
}
