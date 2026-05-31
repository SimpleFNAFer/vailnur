import { useState, useEffect, useRef, useCallback } from 'react'
import { startScan, getScan, startExploit, getExploit } from './api.js'

function formatBytes(n) {
  if (!n) return ''
  if (n < 1024) return `${n} Б`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} КБ`
  return `${(n / 1024 / 1024).toFixed(1)} МБ`
}

// ---------------------------------------------------------------------------
// Скачать отчёт (ZIP)
// ---------------------------------------------------------------------------
function downloadReport(scanResult, exploitResult) {
  const params = new URLSearchParams()
  if (scanResult?.job_id)   params.set('scan_id',    scanResult.job_id)
  if (exploitResult?.job_id) params.set('exploit_id', exploitResult.job_id)
  const a = document.createElement('a')
  a.href = `/api/report?${params}`
  a.click()
}

// ---------------------------------------------------------------------------
// Переключатель темы
// ---------------------------------------------------------------------------
function useTheme() {
  const [theme, setTheme] = useState(() => localStorage.getItem('theme') || 'system')

  useEffect(() => {
    const apply = (t) => {
      const root = document.documentElement
      if (t === 'system') {
        const dark = window.matchMedia('(prefers-color-scheme: dark)').matches
        root.setAttribute('data-theme', dark ? 'dark' : 'light')
      } else {
        root.setAttribute('data-theme', t)
      }
    }
    apply(theme)
    localStorage.setItem('theme', theme)

    if (theme === 'system') {
      const mq = window.matchMedia('(prefers-color-scheme: dark)')
      const handler = () => apply('system')
      mq.addEventListener('change', handler)
      return () => mq.removeEventListener('change', handler)
    }
  }, [theme])

  return [theme, setTheme]
}

function ThemeSwitcher({ theme, setTheme }) {
  const opts = [
    { key: 'light',  label: '☀', title: 'Светлая' },
    { key: 'dark',   label: '🌙', title: 'Тёмная'  },
    { key: 'system', label: '🖥', title: 'Системная' },
  ]
  return (
    <div className="theme-switcher">
      {opts.map(({ key, label, title }) => (
        <button
          key={key}
          className={`theme-btn${theme === key ? ' active' : ''}`}
          onClick={() => setTheme(key)}
          title={title}
        >
          {label}
        </button>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Вспомогательные компоненты
// ---------------------------------------------------------------------------
function formatParams(params) {
  if (!params || typeof params !== 'object') return ''
  return Object.entries(params)
    .flatMap(([k, vals]) =>
      Array.isArray(vals) ? vals.map((v) => `${k}=${v}`) : [`${k}=${vals}`]
    )
    .join(', ')
}

function ProbBar({ probability }) {
  const pct = Math.round((probability ?? 0) * 100)
  const level = pct >= 70 ? 'prob-high' : pct >= 40 ? 'prob-mid' : 'prob-low'
  return (
    <div className={`prob-bar-wrap ${level}`}>
      <div className="prob-bar-fill" style={{ width: `${pct}%` }} />
      <span className="prob-bar-label">{pct}%</span>
    </div>
  )
}

function BranchProbs({ branchProbs }) {
  if (!branchProbs) return <span className="muted">—</span>
  const fmt = (v) => (v != null ? `${Math.round(v * 100)}%` : '—')
  return (
    <span className="branch-probs">
      <span title="mitch">M:{fmt(branchProbs.mitch)}</span>
      <span title="dwvm">D:{fmt(branchProbs.dwvm)}</span>
      <span title="hackerone">H:{fmt(branchProbs.hackerone)}</span>
    </span>
  )
}

function statusCodeClass(code) {
  if (!code) return ''
  if (code >= 200 && code < 300) return 'code-2xx'
  if (code >= 300 && code < 400) return 'code-3xx'
  return 'code-err'
}

function Spinner({ label }) {
  return (
    <div className="spinner-wrap">
      <div className="spinner" />
      {label && <span className="spinner-label">{label}</span>}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Редактор параметров запроса
// ---------------------------------------------------------------------------
function ParamsEditor({ params, onChange }) {
  const [rows, setRows] = useState(() => {
    if (!params || typeof params !== 'object') return []
    return Object.entries(params).flatMap(([k, vals]) =>
      Array.isArray(vals) ? vals.map((v) => ({ key: k, value: v })) : [{ key: k, value: String(vals) }]
    )
  })

  const handleChange = useCallback(
    (idx, field, val) => {
      const next = rows.map((r, i) => (i === idx ? { ...r, [field]: val } : r))
      setRows(next)
      const rebuilt = {}
      next.forEach(({ key, value }) => {
        if (!rebuilt[key]) rebuilt[key] = []
        rebuilt[key].push(value)
      })
      onChange(rebuilt)
    },
    [rows, onChange]
  )

  if (rows.length === 0) return <div className="params-editor empty">Нет параметров</div>

  return (
    <div className="params-editor">
      {rows.map((row, i) => (
        <div key={i} className="param-row">
          <span className="param-key">{row.key}</span>
          <span className="param-eq">=</span>
          <input
            className="param-input"
            value={row.value}
            onChange={(e) => handleChange(i, 'value', e.target.value)}
          />
        </div>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Секция 1 — Сканирование
// ---------------------------------------------------------------------------
function ScanSection({ onScanDone }) {
  const [url, setUrl] = useState('')
  const [depth, setDepth] = useState(2)
  const [maxPages, setMaxPages] = useState(50)
  const [advOpen, setAdvOpen] = useState(false)
  const [scanState, setScanState] = useState(null)
  const pollRef = useRef(null)

  const stopPolling = () => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
  }
  useEffect(() => () => stopPolling(), [])

  const handleStartScan = async () => {
    if (!url.trim()) return
    stopPolling()
    setScanState({ jobId: null, status: 'pending', pagesCrawled: 0, error: null })
    onScanDone(null)

    let jobId
    try {
      const res = await startScan(url.trim(), Number(depth), Number(maxPages))
      jobId = res.job_id
    } catch (err) {
      setScanState({ jobId: null, status: 'error', pagesCrawled: 0, error: err.message })
      return
    }

    setScanState({ jobId, status: 'pending', pagesCrawled: 0, error: null })
    pollRef.current = setInterval(async () => {
      try {
        const data = await getScan(jobId)
        setScanState({ jobId, status: data.status, pagesCrawled: data.pages_crawled ?? 0, error: data.error ?? null })
        if (data.status === 'done' || data.status === 'error') {
          stopPolling()
          if (data.status === 'done') onScanDone(data)
        }
      } catch (err) {
        setScanState((prev) => ({ ...prev, status: 'error', error: err.message }))
        stopPolling()
      }
    }, 2000)
  }

  const running = scanState && (scanState.status === 'pending' || scanState.status === 'running')

  return (
    <section className="card">
      <h2 className="section-title">
        <span className="section-num">1</span> Сканирование цели
      </h2>

      <div className="form-row">
        <input
          className="url-input"
          type="url"
          placeholder="http://target.local"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          disabled={running}
          onKeyDown={(e) => e.key === 'Enter' && handleStartScan()}
        />
        <button className="btn btn-primary" onClick={handleStartScan} disabled={running || !url.trim()}>
          {running ? 'Сканирую…' : 'Начать сканирование'}
        </button>
      </div>

      <div className="adv-toggle">
        <button className="btn btn-ghost" onClick={() => setAdvOpen((o) => !o)}>
          {advOpen ? '▾ Скрыть параметры' : '▸ Дополнительные параметры'}
        </button>
      </div>

      {advOpen && (
        <div className="adv-panel">
          <label className="adv-label">
            Глубина
            <input className="adv-input" type="number" min={1} max={10} value={depth}
              onChange={(e) => setDepth(e.target.value)} disabled={running} />
          </label>
          <label className="adv-label">
            Макс. страниц
            <input className="adv-input" type="number" min={1} max={500} value={maxPages}
              onChange={(e) => setMaxPages(e.target.value)} disabled={running} />
          </label>
        </div>
      )}

      {scanState && (
        <div className="scan-status">
          {running && <Spinner label={`Проверено страниц: ${scanState.pagesCrawled}`} />}
          {scanState.status === 'done' && (
            <div className="status-ok">Сканирование завершено — проверено страниц: {scanState.pagesCrawled}.</div>
          )}
          {scanState.status === 'error' && (
            <div className="status-err">Ошибка: {scanState.error || 'Неизвестная ошибка'}</div>
          )}
        </div>
      )}
    </section>
  )
}

// ---------------------------------------------------------------------------
// Секция 2 — CSRF-кандидаты
// ---------------------------------------------------------------------------
function CandidatesSection({ scanResult, onExploitDone }) {
  const [selected, setSelected] = useState(new Set())
  const [editedParams, setEditedParams] = useState({})
  const [expandedRows, setExpandedRows] = useState(new Set())
  const [exploiting, setExploiting] = useState(false)
  const pollRef = useRef(null)

  const candidates = scanResult?.candidates ?? []

  const stopPolling = () => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
  }
  useEffect(() => () => stopPolling(), [])

  useEffect(() => {
    setSelected(new Set())
    setEditedParams({})
    setExpandedRows(new Set())
    stopPolling()
    onExploitDone(null)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanResult])

  if (candidates.length === 0) return null

  const allSelected = selected.size === candidates.length
  const toggleAll = () => {
    if (allSelected) setSelected(new Set())
    else setSelected(new Set(candidates.map((c) => c.id)))
  }
  const toggleRow = (id) => {
    const next = new Set(selected)
    if (next.has(id)) next.delete(id); else next.add(id)
    setSelected(next)
  }

  const handleParamChange = (id, newParams) => {
    setEditedParams((prev) => ({ ...prev, [id]: newParams }))
  }

  const handleRunExploit = async () => {
    const targets = candidates
      .filter((c) => selected.has(c.id))
      .map((c) => ({ id: c.id, method: c.method, url: c.url, params: editedParams[c.id] ?? c.params }))
    if (targets.length === 0) return

    setExploiting(true)
    onExploitDone(null)
    stopPolling()

    let jobId
    try {
      const res = await startExploit(targets)
      jobId = res.job_id
    } catch (err) {
      setExploiting(false)
      onExploitDone({ status: 'error', results: [], error: err.message })
      return
    }

    pollRef.current = setInterval(async () => {
      try {
        const data = await getExploit(jobId)
        if (data.status === 'done' || data.status === 'error') {
          stopPolling()
          setExploiting(false)
          onExploitDone(data)
        }
      } catch (err) {
        stopPolling()
        setExploiting(false)
        onExploitDone({ status: 'error', results: [], error: err.message })
      }
    }, 2000)
  }

  return (
    <section className="card">
      <h2 className="section-title">
        <span className="section-num">2</span> CSRF-кандидаты
        <span className="badge">{candidates.length}</span>
      </h2>

      <div className="table-toolbar">
        <button className="btn btn-ghost btn-sm" onClick={toggleAll}>
          {allSelected ? 'Снять выбор' : 'Выбрать все'}
        </button>
        <button className="btn btn-danger" disabled={selected.size === 0 || exploiting} onClick={handleRunExploit}>
          {exploiting ? 'Эксплуатация…' : `Эксплуатировать выбранные (${selected.size})`}
        </button>
      </div>

      {exploiting && <Spinner label="Выполняется эксплуатация…" />}

      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th className="col-check"></th>
              <th>Метод</th>
              <th>URL</th>
              <th>Параметры</th>
              <th>Вероятность эксплуатации</th>
              <th>Оценки моделей</th>
            </tr>
          </thead>
          <tbody>
            {candidates.map((c) => {
              const isExpanded = expandedRows.has(c.id)
              const isSelected = selected.has(c.id)
              const toggleExpand = (id) => setExpandedRows((prev) => {
                const next = new Set(prev)
                if (next.has(id)) next.delete(id); else next.add(id)
                return next
              })
              return (
                <>
                  <tr
                    key={c.id}
                    className={`data-row${isSelected ? ' row-selected' : ''}${isExpanded ? ' row-expanded' : ''}`}
                    onClick={() => toggleExpand(c.id)}
                  >
                    <td className="col-check" onClick={(e) => { e.stopPropagation(); toggleRow(c.id) }}>
                      <input type="checkbox" checked={isSelected} onChange={() => toggleRow(c.id)}
                        onClick={(e) => e.stopPropagation()} />
                    </td>
                    <td>
                      <span className={`method-badge method-${c.method?.toLowerCase()}`}>{c.method}</span>
                    </td>
                    <td className="url-cell" title={c.url}>{c.url}</td>
                    <td className="params-cell">
                      <span className="params-preview">{formatParams(editedParams[c.id] ?? c.params)}</span>
                    </td>
                    <td className="prob-cell"><ProbBar probability={c.probability} /></td>
                    <td><BranchProbs branchProbs={c.branch_probs} /></td>
                  </tr>
                  {isExpanded && (
                    <tr key={`${c.id}-editor`} className="editor-row">
                      <td colSpan={6}>
                        <div className="editor-panel">
                          <div className="editor-header">Параметры для эксплуатации</div>
                          <ParamsEditor
                            params={editedParams[c.id] ?? c.params}
                            onChange={(p) => handleParamChange(c.id, p)}
                          />
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              )
            })}
          </tbody>
        </table>
      </div>
    </section>
  )
}

// ---------------------------------------------------------------------------
// Секция 3 — Результаты эксплуатации
// ---------------------------------------------------------------------------
function ExploitResultsSection({ exploitResult, scanResult, onDownload }) {
  const [expandedRows, setExpandedRows] = useState(new Set())

  if (!exploitResult) return null
  const results = exploitResult.results ?? []

  const toggleExpand = (key) => setExpandedRows((prev) => {
    const next = new Set(prev)
    if (next.has(key)) next.delete(key); else next.add(key)
    return next
  })

  // Форматирует параметры, показывая пустые значения явно
  const formatParamsDetailed = (params) => {
    if (!params || !Object.keys(params).length) return '(нет параметров)'
    return Object.entries(params)
      .flatMap(([k, vals]) => {
        const list = Array.isArray(vals) ? vals : [vals]
        return list.map((v) => `${k} = ${v === '' ? '(по умолчанию)' : v}`)
      })
      .join('\n')
  }

  const statusLabels = { done: 'завершено', error: 'ошибка', running: 'выполняется', pending: 'ожидание' }

  return (
    <section className="card">
      <h2 className="section-title">
        <span className="section-num">3</span> Результаты эксплуатации
        {exploitResult.status && (
          <span className={`status-chip status-${exploitResult.status}`}>
            {statusLabels[exploitResult.status] ?? exploitResult.status}
          </span>
        )}
        {results.length > 0 && (
          <button
            className="btn btn-ghost btn-sm"
            style={{ marginLeft: 'auto' }}
            onClick={() => downloadReport(scanResult, exploitResult)}
          >
            ↓ Сохранить отчёт
          </button>
        )}
      </h2>

      {exploitResult.status === 'error' && (
        <div className="status-err">Ошибка: {exploitResult.error || 'Неизвестная ошибка'}</div>
      )}
      {results.length === 0 && exploitResult.status !== 'error' && (
        <div className="muted">Результатов пока нет.</div>
      )}

      {results.length > 0 && (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Метод</th>
                <th>URL</th>
                <th>Параметры</th>
                <th>Код ответа</th>
                <th>Ответ</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r, i) => {
                const key = r.target_id ?? i
                const isExpanded = expandedRows.has(key)
                const hasParams = r.params && Object.keys(r.params).length > 0
                return (
                  <>
                    <tr
                      key={key}
                      className={`data-row${isExpanded ? ' row-expanded' : ''}`}
                      onClick={() => toggleExpand(key)}
                    >
                      <td><span className={`method-badge method-${r.method?.toLowerCase()}`}>{r.method}</span></td>
                      <td className="url-cell" title={r.url}>{r.url}</td>
                      <td className="params-cell">
                        <span className="params-preview">
                          {hasParams
                            ? Object.entries(r.params)
                                .flatMap(([k, v]) => (Array.isArray(v) ? v : [v]).map((val) => `${k}=${val === '' ? '∅' : val}`))
                                .join(', ')
                            : <span className="muted">—</span>
                          }
                        </span>
                      </td>
                      <td>
                        {r.error
                          ? <span className="code-err" title={r.error}>ERR</span>
                          : <span className={statusCodeClass(r.status_code)}>{r.status_code ?? '—'}</span>
                        }
                      </td>
                      <td className="excerpt-cell">
                        <pre className="response-excerpt">{r.response_excerpt || '—'}</pre>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr key={`${key}-detail`} className="detail-row">
                        <td colSpan={5}>
                          <div className="detail-panel">
                            <div className="detail-meta">
                              <span><b>URL:</b> {r.url}</span>
                              <span><b>Метод:</b> {r.method}</span>
                              <span><b>Код ответа:</b>{' '}
                                {r.error
                                  ? <span className="code-err">{r.error}</span>
                                  : <span className={statusCodeClass(r.status_code)}>{r.status_code}</span>
                                }
                              </span>
                            </div>
                            <div className="detail-header">Параметры запроса</div>
                            <pre className="detail-body" style={{ marginBottom: 10 }}>
                              {formatParamsDetailed(r.params)}
                            </pre>
                            <div className="detail-header">
                              Тело ответа
                              {r.response_size > 0 && (
                                <span className="detail-header-meta">{formatBytes(r.response_size)}</span>
                              )}
                            </div>
                            <pre className="detail-body">{r.response_excerpt || '(пустой ответ)'}</pre>
                            {r.response_url && (
                              <a
                                href={r.response_url}
                                download="response.bin"
                                className="btn-download-response"
                              >
                                ↓ Скачать полный ответ
                              </a>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

// ---------------------------------------------------------------------------
// Корневой компонент
// ---------------------------------------------------------------------------
export default function App() {
  const [scanResult, setScanResult] = useState(null)
  const [exploitResult, setExploitResult] = useState(null)
  const [theme, setTheme] = useTheme()

  return (
    <div className="app">
      <header className="app-header">
        <div className="logo">
          <span className="logo-text">Автоматическое тестирование CSRF</span>
        </div>
        <div className="header-sub">Москва, 2026</div>
        <div className="header-right">
          <ThemeSwitcher theme={theme} setTheme={setTheme} />
        </div>
      </header>

      <main className="app-main">
        <ScanSection onScanDone={setScanResult} />
        <CandidatesSection scanResult={scanResult} onExploitDone={setExploitResult} />
        <ExploitResultsSection exploitResult={exploitResult} scanResult={scanResult} />
      </main>
    </div>
  )
}
