/**
 * Extracts the data the backend needs from the opened email.
 * The add-on only collects and forwards; all analysis happens in the backend.
 * Limits match the backend's schema, so oversized emails are trimmed here
 * instead of being rejected there.
 */

const LIMITS = {
  sender: 1024,
  subject: 2048,
  authResults: 8192,
  body: 200000,
  attachments: 100,
  filename: 512,
};

/**
 * @param {GmailApp.GmailMessage} message
 * @return {Object} Request body for POST /analyze
 */
function extractEmail(message) {
  return {
    sender: truncate(message.getFrom(), LIMITS.sender),
    reply_to: truncate(message.getReplyTo(), LIMITS.sender) || null,
    subject: truncate(message.getSubject(), LIMITS.subject),
    authentication_results: truncate(findGmailAuthResults(message), LIMITS.authResults) || null,
    body_text: truncate(message.getPlainBody(), LIMITS.body),
    body_html: truncate(message.getBody(), LIMITS.body),
    attachments: message
      .getAttachments({ includeInlineImages: false })
      .slice(0, LIMITS.attachments)
      .map((attachment) => ({
        filename: truncate(attachment.getName(), LIMITS.filename),
        mime_type: truncate(attachment.getContentType(), 255),
        size: attachment.getSize(),
      })),
  };
}

/**
 * Returns the Authentication-Results header that Gmail itself added.
 * An email can contain several such headers, and any of them except Gmail's
 * may have been written by the sender, so we pick the one from mx.google.com.
 * @param {GmailApp.GmailMessage} message
 * @return {string}
 */
function findGmailAuthResults(message) {
  try {
    const raw = message.getRawContent();
    const headerEnd = raw.search(/\r?\n\r?\n/);
    const headerBlock = (headerEnd === -1 ? raw : raw.slice(0, headerEnd))
      // Unfold headers that continue on the next line.
      .replace(/\r?\n[ \t]+/g, ' ');

    for (const line of headerBlock.split(/\r?\n/)) {
      const match = /^authentication-results:\s*(.*)$/i.exec(line);
      if (match && match[1].trim().toLowerCase().indexOf('mx.google.com') === 0) {
        return match[1].trim();
      }
    }
    return '';
  } catch (err) {
    // Raw content can fail on very large messages. The backend still checks
    // that the value comes from mx.google.com before trusting it.
    console.warn('Raw headers unavailable, using getHeader instead');
    return message.getHeader('Authentication-Results') || '';
  }
}
