import { useDeferredValue, useId, useMemo, useState } from 'react'
import { CopyButton } from '../../lib/CopyButton'
import { readFileText } from '../../lib/download'
import { mdTable } from '../../lib/markdown'
import { SeverityBadge, SeveritySummary } from './FindingList'
import { scanSecrets } from './secrets'
import { mdText, sortFindings } from './types'

const MAX_FILE_BYTES = 5 * 1024 * 1024

export function SecretsTab() {
  const [text, setText] = useState('')
  const [entropy, setEntropy] = useState(false)
  const [fileError, setFileError] = useState<string>()
  const deferred = useDeferredValue(text)
  const id = useId()
  const fileId = useId()

  const findings = useMemo(() => scanSecrets(deferred, { entropy }), [deferred, entropy])
  const markdown = useMemo(
    () =>
      `### Secret scan (redacted)\n\n${mdTable(
        ['Line', 'Rule', 'Severity', 'Match'],
        findings.map((f) => [String(f.line), f.ruleName, f.severity, mdText(f.redacted)]),
      )}\n`,
    [findings],
  )

  return (
    <div className="stack">
      <div className="callout small">
        The text never leaves your browser and is not stored. Matches are shown redacted (first 4 characters only).
      </div>

      <label htmlFor={id}>Paste code, config, logs or a diff</label>
      <textarea id={id} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} rows={12} />
      <div className="row">
        <label className="inline">
          <input type="checkbox" checked={entropy} onChange={(e) => setEntropy(e.target.checked)} />
          Also flag high-entropy strings (more false positives)
        </label>
        <span className="spacer" />
        <label htmlFor={fileId} className="inline small">
          Load a file:
        </label>
        <input
          id={fileId}
          type="file"
          onChange={async (e) => {
            const file = e.target.files?.[0]
            e.target.value = ''
            if (!file) return
            if (file.size > MAX_FILE_BYTES) {
              setFileError(`File is larger than ${MAX_FILE_BYTES / 1024 / 1024} MB.`)
              return
            }
            try {
              setText(await readFileText(file))
              setFileError(undefined)
            } catch (err) {
              setFileError(`Could not read the file: ${(err as Error).message || 'unknown error'}`)
            }
          }}
        />
        <button type="button" className="btn btn-sm" onClick={() => setText('')} disabled={text === ''}>
          Clear
        </button>
      </div>
      {fileError && <div className="callout error" role="alert">{fileError}</div>}

      {deferred.trim() !== '' && (
        <div className="card stack">
          <div className="row">
            <h3 style={{ margin: 0 }}>
              {findings.length === 0 ? 'No secrets found' : `${findings.length} potential secret${findings.length > 1 ? 's' : ''}`}
            </h3>
            <SeveritySummary findings={findings} />
            <span className="spacer" />
            {findings.length > 0 && <CopyButton text={markdown} label="Copy as Markdown" />}
          </div>
          {findings.length === 0 ? (
            <p className="muted small">
              No pattern matched. This is a best-effort regex scan — it does not prove the absence of secrets (custom
              token formats, split strings, encoded values).
            </p>
          ) : (
            <div className="toolbox-table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Line</th>
                    <th>Severity</th>
                    <th>Rule</th>
                    <th>Match (redacted)</th>
                  </tr>
                </thead>
                <tbody>
                  {sortFindings(findings).map((f, i) => (
                    <tr key={`${f.line}-${f.column}-${i}`}>
                      <td className="toolbox-nowrap">
                        {f.line}:{f.column}
                      </td>
                      <td>
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td>
                        <strong>{f.ruleName}</strong>
                        <div className="small muted">{f.description}</div>
                      </td>
                      <td className="toolbox-break">
                        <code>{f.redacted}</code>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {findings.length > 0 && (
        <div className="callout warn">
          <strong>If a real secret was committed or shared:</strong>
          <ol style={{ margin: '.4rem 0 0', paddingLeft: '1.2rem' }}>
            <li>
              <strong>Rotate / revoke it first</strong> at the provider. Treat it as compromised — deleting the line does not
              un-leak it (forks, clones, CI logs, caches).
            </li>
            <li>Check the provider&apos;s audit logs for use of the secret since it was exposed.</li>
            <li>
              Remove it from git history with <code>git filter-repo --replace-text</code> or BFG Repo-Cleaner, force-push,
              and ask GitHub support to purge cached views if the repo is public.
            </li>
            <li>
              Prevent recurrence: move secrets to a secret manager / CI secrets, add a <code>gitleaks</code> pre-commit
              hook and CI job, and enable GitHub secret scanning + push protection.
            </li>
          </ol>
          <p className="small" style={{ marginTop: '.4rem' }}>
            <a href="https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository" target="_blank" rel="noopener noreferrer">
              GitHub: removing sensitive data
            </a>{' '}
            ·{' '}
            <a href="https://github.com/gitleaks/gitleaks" target="_blank" rel="noopener noreferrer">
              gitleaks
            </a>{' '}
            ·{' '}
            <a href="https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html" target="_blank" rel="noopener noreferrer">
              OWASP Secrets Management
            </a>
          </p>
        </div>
      )}
    </div>
  )
}
