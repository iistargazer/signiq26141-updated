/**
 * useSliderFill — computes the CSS custom property the stylesheet needs to
 * paint a range input's track up to the thumb (the `--fill` percentage).
 * Without it every slider looked half-filled regardless of value.
 *
 * Pass min/max/value as numbers; attach the returned ref+style to the input.
 */
import { useMemo } from 'react'

export function sliderFillStyle(min: number, max: number, value: number): React.CSSProperties {
  const span = max - min
  const pct = span <= 0 ? 0 : Math.min(100, Math.max(0, ((value - min) / span) * 100))
  // cast: CSS custom properties are valid inline style keys at runtime
  return { '--fill': `${pct}%` } as React.CSSProperties
}

/** Convenience hook shape for components that prefer destructuring. */
export function useSliderFill(min: number, max: number, value: number) {
  return useMemo(() => sliderFillStyle(min, max, value), [min, max, value])
}
