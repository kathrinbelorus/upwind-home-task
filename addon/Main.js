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
 * Runs every time the user opens an email.
 * @param {Object} e Event object from Gmail (holds the message ID and an access token).
 */
function onGmailMessageOpen(e) {
  // The access token gives permission to read ONLY the currently opened message.
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  const message = GmailApp.getMessageById(e.gmail.messageId);

  const email = {
    from: message.getFrom(),
    subject: message.getSubject(),
  };

  return buildMessageCard(email);
}
