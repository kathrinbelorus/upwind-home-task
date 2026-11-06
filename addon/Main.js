/**
 * Entry points of the add-on.
 * Google calls these functions, as configured in appsscript.json.
 */

/**
 * Runs when the add-on is opened without a selected email.
 */
function onHomepage(e) {
  return buildHomepageCard();
}

/**
 * Runs every time the user opens an email: extract, analyze, display.
 * @param {Object} e Event object from Gmail (holds the message ID and an access token).
 */
function onGmailMessageOpen(e) {
  // The access token gives permission to read ONLY the currently opened message.
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  const message = GmailApp.getMessageById(e.gmail.messageId);
  const email = { from: message.getFrom(), subject: message.getSubject() };

  try {
    const result = analyzeEmail(extractEmail(message));
    return buildResultCard(email, result);
  } catch (err) {
    // Log the error, never the email itself. Apps Script service errors
    // describe the failure (permissions, network), not message content.
    console.error('Analysis failed: ' + err.name + ': ' + err.message);
    const known = err instanceof ConfigError || err instanceof BackendError;
    return buildErrorCard(
      known ? err.message : 'The analysis service could not be reached. Please try again.'
    );
  }
}
