/**
 * Configuration.
 * The backend URL is not secret, so it lives in code (and in the manifest's
 * urlFetchWhitelist). The API key IS secret: it is stored in Script Properties
 * (Project Settings > Script Properties) and never committed to the repo.
 */

const BACKEND_URL = 'https://mail-scorer-799255271631.me-west1.run.app';

function getApiKey() {
  const key = PropertiesService.getScriptProperties().getProperty('API_KEY');
  if (!key) {
    throw new ConfigError('API_KEY is not set in Script Properties.');
  }
  return key;
}

class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}
