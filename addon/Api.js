/**
 * Client for the backend API.
 * The backend's response is also treated as untrusted: it is validated and
 * trimmed before anything reaches the UI.
 */

const VERDICTS = ['Safe', 'Suspicious', 'Malicious'];
const AI_RISKS = ['low', 'medium', 'high'];
const MAX_FINDINGS = 20;

class BackendError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BackendError';
  }
}

/**
 * @param {Object} payload Output of extractEmail()
 * @return {{score: number, verdict: string, findings: Array<Object>}}
 */
function analyzeEmail(payload) {
  const response = UrlFetchApp.fetch(BACKEND_URL + '/analyze', {
    method: 'post',
    contentType: 'application/json',
    headers: { 'X-API-Key': getApiKey() },
    payload: JSON.stringify(payload),
    muteHttpExceptions: true,
  });

  const status = response.getResponseCode();
  if (status === 401) {
    throw new BackendError('The add-on is not authorized by the backend (check API_KEY).');
  }
  if (status !== 200) {
    throw new BackendError('The analysis service returned an error (HTTP ' + status + ').');
  }

  let data;
  try {
    data = JSON.parse(response.getContentText());
  } catch (err) {
    throw new BackendError('The analysis service returned an invalid response.');
  }
  return validateResult(data);
}

/**
 * Accepts only the expected shape, and clamps and trims every field.
 * @param {*} data
 */
function validateResult(data) {
  if (
    !data ||
    typeof data.score !== 'number' ||
    VERDICTS.indexOf(data.verdict) === -1 ||
    !Array.isArray(data.findings)
  ) {
    throw new BackendError('The analysis service returned an unexpected response.');
  }

  return {
    score: Math.max(0, Math.min(100, Math.round(data.score))),
    verdict: data.verdict,
    findings: data.findings.slice(0, MAX_FINDINGS).map((finding) => ({
      check: truncate(finding.check, 40),
      title: truncate(finding.title, 120),
      detail: truncate(finding.detail, 400),
      points: Math.max(0, Math.min(100, Number(finding.points) || 0)),
    })),
    ai: validateAi(data.ai),
  };
}

/**
 * The AI opinion is optional: anything unexpected is simply dropped.
 * @param {*} ai
 * @return {?{risk: string, summary: string}}
 */
function validateAi(ai) {
  if (!ai || AI_RISKS.indexOf(ai.risk) === -1 || typeof ai.summary !== 'string') {
    return null;
  }
  return { risk: ai.risk, summary: truncate(ai.summary, 300) };
}
