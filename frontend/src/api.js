/**
 * API module — all fetch calls to the Go backend.
 * Base URL is intentionally empty so Vite's proxy handles /api/* → http://localhost:8080
 */

const BASE = ''

/**
 * Start a scan job.
 * @param {string} url        Target URL
 * @param {number} depth      Crawl depth (default 2)
 * @param {number} maxPages   Max pages to crawl (default 50)
 * @returns {Promise<{job_id: string}>}
 */
export async function startScan(url, depth = 2, maxPages = 50) {
  const res = await fetch(`${BASE}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, depth, max_pages: maxPages }),
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`Start scan failed (${res.status}): ${text}`)
  }
  return res.json()
}

/**
 * Poll scan job status.
 * @param {string} jobId
 * @returns {Promise<ScanResult>}
 */
export async function getScan(jobId) {
  const res = await fetch(`${BASE}/api/scan/${encodeURIComponent(jobId)}`)
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`Get scan failed (${res.status}): ${text}`)
  }
  return res.json()
}

/**
 * Start an exploit job.
 * @param {Array<{id: string, method: string, url: string, params: Object}>} targets
 * @returns {Promise<{job_id: string}>}
 */
export async function startExploit(targets) {
  const res = await fetch(`${BASE}/api/exploit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ targets }),
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`Start exploit failed (${res.status}): ${text}`)
  }
  return res.json()
}

/**
 * Poll exploit job status.
 * @param {string} jobId
 * @returns {Promise<ExploitResult>}
 */
export async function getExploit(jobId) {
  const res = await fetch(`${BASE}/api/exploit/${encodeURIComponent(jobId)}`)
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`Get exploit failed (${res.status}): ${text}`)
  }
  return res.json()
}
