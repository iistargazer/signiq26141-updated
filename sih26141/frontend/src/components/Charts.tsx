import {
  Bar,
  BarChart,
  CartesianGrid,
  ComposedChart,
  Legend,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

interface LiveChartPoint {
  processed: number
  [key: string]: number | undefined
}

interface SweepPoint {
  ratio: number
  qber: number
  threshold: number
  theory: number
}

interface ForgeryPoint {
  lambda: string
  log10: number
}

interface NoiseChartPoint {
  label: string
  qber: number
  threshold: number
  description: string
}

const SERIES: Record<string, { color: string; label: string }> = {
  secure: { color: '#86bf9c', label: 'Secure channel' },
  attack: { color: '#d67f72', label: 'Attack (full intercept)' },
  custom: { color: '#c9a45c', label: 'Custom ratio' },
}

export function LiveChart({
  data,
  keys,
  baseThreshold,
}: {
  data: LiveChartPoint[]
  keys: string[]
  baseThreshold: number
}) {
  return (
    <ResponsiveContainer width="100%" height={260}>
      <LineChart data={data} margin={{ top: 10, right: 20, bottom: 0, left: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1a2338" />
        <XAxis dataKey="processed" stroke="#6d6f82" tick={{ fontSize: 11 }} />
        <YAxis
          stroke="#6d6f82"
          tick={{ fontSize: 11 }}
          tickFormatter={(value: number) => `${(value * 100).toFixed(0)}%`}
        />
        <Tooltip
          contentStyle={{ background: '#0b101e', border: '1px solid rgba(201, 164, 92, 0.4)', borderRadius: 4, fontSize: 12 }}
          formatter={(value) => `${((value as number) * 100).toFixed(3)}%`}
          labelFormatter={(label) => `qubit #${label}`}
        />
        <Legend wrapperStyle={{ fontSize: 12 }} />
        {keys.map((name) => {
          const series = SERIES[name] ?? { color: '#8fb0c9', label: name }
          return (
            <Line
              key={name}
              type="monotone"
              dataKey={`${name}_qber`}
              name={`${series.label} — QBER`}
              stroke={series.color}
              dot={false}
              strokeWidth={2}
              isAnimationActive={false}
            />
          )
        })}
        {keys.map((name) => {
          const series = SERIES[name] ?? { color: '#8fb0c9', label: name }
          return (
            <Line
              key={`${name}-threshold`}
              type="monotone"
              dataKey={`${name}_thr`}
              name={`${series.label} — threshold`}
              stroke={series.color}
              strokeDasharray="6 4"
              strokeWidth={1}
              dot={false}
              isAnimationActive={false}
              legendType="none"
            />
          )
        })}
        <ReferenceLine
          y={baseThreshold}
          stroke="#525a78"
          strokeDasharray="2 2"
          label={{ value: `base ${(baseThreshold * 100).toFixed(0)}%`, fill: '#525a78', fontSize: 10, position: 'insideTopRight' }}
        />
      </LineChart>
    </ResponsiveContainer>
  )
}

export function SweepChart({ data }: { data: SweepPoint[] }) {
  return (
    <ResponsiveContainer width="100%" height={280}>
      <BarChart data={data} margin={{ top: 10, right: 20, bottom: 5, left: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1a2338" />
        <XAxis
          dataKey="ratio"
          stroke="#6d6f82"
          tick={{ fontSize: 11 }}
          tickFormatter={(value: number) => `${Math.round(value * 100)}%`}
        />
        <YAxis
          stroke="#6d6f82"
          tick={{ fontSize: 11 }}
          tickFormatter={(value: number) => `${(value * 100).toFixed(0)}%`}
        />
        <Tooltip
          contentStyle={{ background: '#0b101e', border: '1px solid rgba(201, 164, 92, 0.4)', borderRadius: 4, fontSize: 12 }}
          formatter={(value) => `${((value as number) * 100).toFixed(2)}%`}
          labelFormatter={(label) => `Eve intercepts ${(Number(label) * 100).toFixed(0)}% of qubits`}
        />
        <Legend wrapperStyle={{ fontSize: 12 }} />
        <ReferenceLine
          y={data[0]?.threshold ?? 0.2}
          stroke="#d67f72"
          strokeDasharray="6 4"
          label={{ value: 'detection threshold', fill: '#d67f72', fontSize: 10, position: 'insideTopRight' }}
        />
        <Bar dataKey="qber" name="Measured QBER" fill="#8fb0c9" radius={[2, 2, 0, 0]} />
        <Bar dataKey="theory" name="Theoretical (ratio/3)" fill="#2c3757" radius={[2, 2, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}

export function ForgeryChart({ data }: { data: ForgeryPoint[] }) {
  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={data} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(232, 222, 196, 0.12)" />
        <XAxis dataKey="lambda" stroke="#a89d81" tick={{ fontSize: 11 }} />
        <YAxis
          stroke="#a89d81"
          tick={{ fontSize: 11 }}
          domain={[-45, 0]}
          tickFormatter={(value: number) => `1e${value}`}
        />
        <Tooltip
          contentStyle={{
            background: '#0b101e',
            border: '1px solid rgba(201, 164, 92, 0.4)',
            borderRadius: 4,
            fontSize: 12,
          }}
          formatter={(value) => `P(forgery) = 10^${Number(value).toFixed(1)}`}
        />
        <ReferenceLine
          y={-30}
          stroke="#86bf9c"
          strokeDasharray="4 4"
          label={{ value: '128-bit security', fill: '#86bf9c', fontSize: 10, position: 'insideTopRight' }}
        />
        <Bar dataKey="log10" name="log10 P(forgery)" fill="#c9a45c" radius={[2, 2, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}

export function NoiseEveChart({
  data,
  chartMax,
}: {
  data: NoiseChartPoint[]
  chartMax: number
}) {
  return (
    <ResponsiveContainer width="100%" height={290}>
      <ComposedChart data={data} margin={{ top: 12, right: 18, bottom: 7, left: 2 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1a2338" />
        <XAxis dataKey="label" stroke="#6d6f82" tick={{ fontSize: 10 }} interval={0} />
        <YAxis
          stroke="#6d6f82"
          tick={{ fontSize: 10 }}
          domain={[0, chartMax]}
          tickFormatter={(value: number) => `${(value * 100).toFixed(0)}%`}
        />
        <Tooltip
          contentStyle={{ background: '#0b101e', border: '1px solid rgba(201, 164, 92, 0.4)', borderRadius: 4, fontSize: 11 }}
          formatter={(value, name) => [`${((value as number) * 100).toFixed(2)}%`, name]}
          labelFormatter={(label, payload) => {
            const condition = payload?.[0]?.payload as NoiseChartPoint | undefined
            return condition ? `${label} — ${condition.description}` : label
          }}
        />
        <Legend wrapperStyle={{ fontSize: 11 }} />
        <Bar dataKey="qber" name="Measured QBER" fill="#8fb0c9" radius={[2, 2, 0, 0]} />
        <Line
          dataKey="threshold"
          name="Dynamic threshold"
          type="monotone"
          stroke="#d67f72"
          strokeWidth={2}
          dot={{ r: 3, fill: '#d67f72' }}
        />
      </ComposedChart>
    </ResponsiveContainer>
  )
}
