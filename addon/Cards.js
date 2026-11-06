/**
 * UI layer: builds the cards shown in the Gmail side panel.
 * Kept separate from Main.js so the UI can change without touching the logic.
 */

function buildHomepageCard() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Mail Scorer'))
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText('Open an email to analyze it.')
      )
    )
    .build();
}

/**
 * @param {{from: string, subject: string}} email
 */
function buildMessageCard(email) {
  // Email fields are untrusted input. Card text supports basic HTML,
  // so every value from the email is escaped before display.
  const section = CardService.newCardSection()
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('From')
        .setText(escapeHtml(email.from))
        .setWrapText(true)
    )
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Subject')
        .setText(escapeHtml(email.subject || '(no subject)'))
        .setWrapText(true)
    );

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Mail Scorer'))
    .addSection(section)
    .build();
}

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
