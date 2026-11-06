/**
 * Helpers for handling untrusted text.
 */

/**
 * Escapes characters that the card renderer would treat as HTML.
 * Without this, "Name <a@b.com>" is shown as just "Name", and an attacker
 * could inject formatting or links into the panel.
 * @param {string} text
 * @return {string}
 */
function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * @param {string} text
 * @param {number} maxLength
 * @return {string}
 */
function truncate(text, maxLength) {
  const value = String(text || '');
  return value.length <= maxLength ? value : value.slice(0, maxLength - 1) + '…';
}
