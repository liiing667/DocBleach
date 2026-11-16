package xyz.docbleach.module.pdf;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.io.MemoryUsageSetting;
import org.apache.pdfbox.io.RandomAccessRead;
import org.apache.pdfbox.io.ScratchFile;
import org.apache.pdfbox.pdfparser.PDFParser;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDDocumentNameDictionary;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;
import org.apache.pdfbox.pdmodel.interactive.action.PDAction;
import org.apache.pdfbox.pdmodel.interactive.documentnavigation.outline.PDDocumentOutline;
import org.apache.pdfbox.pdmodel.interactive.documentnavigation.outline.PDOutlineItem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.docbleach.api.BleachSession;
import xyz.docbleach.api.exception.BleachException;
import xyz.docbleach.api.threat.Threat;
import xyz.docbleach.api.threat.ThreatAction;
import xyz.docbleach.api.threat.ThreatSeverity;
import xyz.docbleach.api.threat.ThreatType;

class PdfBleachSession {

  private static final Logger LOGGER = LoggerFactory.getLogger(PdfBleachSession.class);
  private static final String[] COMMON_PASSWORDS =
      new String[]{null, "", "test", "example", "sample", "malware", "infected", "password"};
  private static final MemoryUsageSetting MEMORY_USAGE_SETTING =
      MemoryUsageSetting.setupMixed(1024 * 100);

  private final BleachSession session;
  private final SanitizationBudget budget;
  private final Set<COSDictionary> reportedActionDictionaries =
      Collections.newSetFromMap(new IdentityHashMap<COSDictionary, Boolean>());
  private final COSObjectBleach cosObjectBleach;
  private final PDActionBleach actionBleach;
  private final PDEmbeddedFileBleach embeddedFileBleach;

  PdfBleachSession(BleachSession session) {
    this.session = session;
    this.budget = new SanitizationBudget();
    this.actionBleach = new PDActionBleach(this);
    this.embeddedFileBleach = new PDEmbeddedFileBleach(this);
    this.cosObjectBleach = new COSObjectBleach(this, actionBleach, embeddedFileBleach);
  }

  void sanitize(RandomAccessRead source, OutputStream outputStream)
      throws IOException, BleachException {
    final PDDocument doc = getDocument(source);

    final PDDocumentCatalog docCatalog = doc.getDocumentCatalog();

    embeddedFileBleach.registerDocument(doc);
    sanitizeNamed(docCatalog.getNames());
    PDDocumentCatalogBleach catalogBleach = new PDDocumentCatalogBleach(this);
    catalogBleach.sanitize(docCatalog);
    sanitizeDocumentOutline(doc.getDocumentCatalog().getDocumentOutline());

    cosObjectBleach.sanitizeObjects(doc.getDocument().getObjects());

    if (budget.isExhausted()) {
      LOGGER.warn(
          "Sanitization budget exhausted (objects: {}, depth: {}, embedded files: {}); "
              + "remaining unreachable content was not inspected",
          budget.getTraversedObjects(),
          budget.getMaxDepthReached(),
          budget.getEmbeddedFiles());
      recordThreat(
          ThreatType.UNRECOGNIZED_CONTENT,
          ThreatSeverity.HIGH,
          "PDF Document",
          "Sanitization budget exhausted, uninspected content dropped");
    }

    doc.save(outputStream);
    doc.close();
  }

  private void sanitizeDocumentOutline(PDDocumentOutline documentOutline) {
    if (documentOutline == null) {
      return;
    }
    documentOutline.children().forEach(this::sanitizeDocumentOutlineItem);
  }

  private void sanitizeDocumentOutlineItem(PDOutlineItem item) {
    PDAction action = item.getAction();
    if (action == null) {
      return;
    }
    if (actionBleach.sanitizeAction(action, "Document Outline Item") == null) {
      LOGGER.debug("Found&removed dangerous action on outline item (was {})", action);
      item.setAction(null);
    } else {
      LOGGER.trace("Keeping innocuous action on outline item ({})", action);
    }
  }

  private void sanitizeNamed(PDDocumentNameDictionary names) {
    if (names == null) {
      return;
    }

    embeddedFileBleach.sanitize(names.getEmbeddedFiles());

    if (names.getJavaScript() != null) {
      recordThreat(
          ThreatType.ACTIVE_CONTENT, ThreatSeverity.HIGH, "Name Dictionary", "Named JavaScript");
      names.setJavascript(null);
    }
  }

  private PDDocument getDocument(RandomAccessRead source) throws IOException, BleachException {
    PDDocument doc;
    for (String pwd : COMMON_PASSWORDS) {
      ScratchFile scratchFile = new ScratchFile(MEMORY_USAGE_SETTING);
      doc = testPassword(scratchFile, source, pwd);
      if (doc != null) {
        LOGGER.debug("Password was guessed: '{}'", pwd);
        doc.protect(new StandardProtectionPolicy(pwd, pwd, doc.getCurrentAccessPermission()));
        return doc;
      }
      scratchFile.close();
    }

    // @TODO: fetch password from config?

    throw new BleachException("PDF is protected with an unknown password");
  }

  @SuppressFBWarnings(
      value = "EXS_EXCEPTION_SOFTENING_RETURN_FALSE",
      justification = "This method is an helper to check the password")
  private PDDocument testPassword(ScratchFile inFile, RandomAccessRead source, String password)
      throws IOException {
    PDFParser parser = new PDFParser(source, password, inFile);
    try {
      parser.parse();
      return parser.getPDDocument();
    } catch (InvalidPasswordException e) {
      LOGGER.error("The tested password is invalid");
      return null;
    } finally {
      source.rewind((int) source.getPosition());
    }
  }

  void recordJavascriptThreat(String location, String details) {
    recordThreat(ThreatType.ACTIVE_CONTENT, ThreatSeverity.HIGH, location, details);
  }

  void recordActionThreat(String location, PDAction action) {
    markActionThreatReported(action.getCOSObject());
    recordActionThreat(location, action.getCOSObject());
  }

  void recordActionThreat(String location, COSDictionary actionDictionary) {
    markActionThreatReported(actionDictionary);
    String subtype = actionDictionary.getNameAsString(COSName.S);
    recordThreat(
        ThreatType.ACTIVE_CONTENT,
        ThreatSeverity.HIGH,
        location,
        "Dangerous action removed: " + subtype);
  }

  /**
   * Records an action threat found by the generic COS object backstop. Actions already reported by
   * the high level catalog/annotation passes are not reported a second time.
   */
  void recordBackstopActionThreat(String location, COSDictionary actionDictionary) {
    if (!reportedActionDictionaries.add(actionDictionary)) {
      return;
    }
    recordActionThreat(location, actionDictionary);
  }

  void markActionThreatReported(COSDictionary actionDictionary) {
    reportedActionDictionaries.add(actionDictionary);
  }

  void recordEmbeddedFileThreat(String location, String details, ThreatSeverity severity) {
    recordThreat(ThreatType.BINARY_CONTENT, severity, location, details);
  }

  void recordThreat(
      ThreatType type, ThreatSeverity severity, String location, String details) {
    Threat threat = Threat.builder()
        .type(type)
        .severity(severity)
        .details(details)
        .location(location)
        .action(ThreatAction.REMOVE)
        .build();

    session.recordThreat(threat);
  }

  BleachSession getSession() {
    return session;
  }

  SanitizationBudget getBudget() {
    return budget;
  }

  PDActionBleach getActionBleach() {
    return actionBleach;
  }

  PDEmbeddedFileBleach getEmbeddedFileBleach() {
    return embeddedFileBleach;
  }
}
