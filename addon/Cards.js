/**
 * UI layer: builds the cards shown in the Gmail side panel.
 * Card text supports basic HTML, so every value that came from the email or
 * from the backend is passed through escapeHtml() before display.
 */

const VERDICT_STYLE = {
  Safe: {
    icon: '🟢',
    color: '#188038',
    advice: 'No significant warning signs were found.',
  },
  Suspicious: {
    icon: '🟠',
    color: '#e37400',
    advice: "Be careful. Don't click links or open attachments unless you trust the sender.",
  },
  Malicious: {
    icon: '🔴',
    color: '#d93025',
    advice: "This looks like phishing or malware. Don't click links, open attachments or reply.",
  },
};

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
 * @param {{score: number, verdict: string, findings: Array<Object>}} result
 */
function buildResultCard(email, result) {
  const style = VERDICT_STYLE[result.verdict];

  const summary = CardService.newCardSection()
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Verdict')
        .setText(`<font color="${style.color}"><b>${style.icon} ${result.verdict}</b></font>`)
        .setBottomLabel(`Risk score: ${result.score} / 100`)
    )
    .addWidget(CardService.newTextParagraph().setText(style.advice));

  const reasons = CardService.newCardSection().setHeader('Why');
  if (result.findings.length === 0) {
    reasons.addWidget(CardService.newTextParagraph().setText('No warning signs found.'));
  } else {
    result.findings.forEach((finding) => {
      reasons.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(`+${finding.points} · ${escapeHtml(finding.check)}`)
          .setText(`<b>${escapeHtml(finding.title)}</b><br>${escapeHtml(finding.detail)}`)
          .setWrapText(true)
      );
    });
  }

  const message = CardService.newCardSection()
    .setHeader('Message')
    .setCollapsible(true)
    .addWidget(
      CardService.newDecoratedText().setTopLabel('From').setText(escapeHtml(email.from)).setWrapText(true)
    )
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Subject')
        .setText(escapeHtml(email.subject || '(no subject)'))
        .setWrapText(true)
    );

  const footer = CardService.newCardSection().addWidget(
    CardService.newTextParagraph().setText(
      '<font color="#5f6368">Automated analysis of headers, links, text and attachment names. ' +
        'Links and files are never opened. Results can be wrong.</font>'
    )
  );

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Mail Scorer'))
    .addSection(summary)
    .addSection(reasons)
    .addSection(message)
    .addSection(footer)
    .build();
}

/**
 * @param {string} reason Safe, non-sensitive explanation for the user.
 */
function buildErrorCard(reason) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Mail Scorer'))
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel('Error')
            .setText("<b>Couldn't analyze this email</b>")
        )
        .addWidget(CardService.newTextParagraph().setText(escapeHtml(reason)))
    )
    .build();
}
