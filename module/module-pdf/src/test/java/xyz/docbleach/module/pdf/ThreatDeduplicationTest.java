package xyz.docbleach.module.pdf;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static xyz.docbleach.api.BleachTestBase.assertThreatsFound;

import java.io.IOException;
import java.util.Collections;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionJavaScript;
import org.junit.jupiter.api.Test;
import xyz.docbleach.api.BleachSession;

class ThreatDeduplicationTest {

  @Test
  void backstopDoesNotDoubleReportActionsAlreadyRemovedByHighLevelPass()
      throws IOException {
    BleachSession session = mock(BleachSession.class);
    PdfBleachSession pdfBleachSession = new PdfBleachSession(session);

    PDActionJavaScript action = new PDActionJavaScript();
    // The catalog/annotation pass already removed and reported this very dictionary
    pdfBleachSession.recordActionThreat("Document Catalog", action);
    assertThreatsFound(session, 1);
    reset(session);

    // The generic COS backstop reaches the same indirect object afterwards
    COSObjectBleach backstop =
        new COSObjectBleach(
            pdfBleachSession,
            pdfBleachSession.getActionBleach(),
            pdfBleachSession.getEmbeddedFileBleach());
    backstop.sanitizeObjects(
        Collections.singletonList(new COSObject(action.getCOSObject())));

    assertThreatsFound(session, 0);
  }
}
