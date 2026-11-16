package xyz.docbleach.module.pdf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDEmbeddedFilesNameTreeNode;
import org.apache.pdfbox.pdmodel.PDDocumentNameDictionary;
import org.apache.pdfbox.pdmodel.common.filespecification.PDComplexFileSpecification;
import org.apache.pdfbox.pdmodel.common.filespecification.PDEmbeddedFile;
import org.junit.jupiter.api.Test;
import xyz.docbleach.api.BleachSession;
import xyz.docbleach.api.bleach.CompositeBleach;
import xyz.docbleach.api.budget.ResourceBudget;
import xyz.docbleach.api.budget.ResourceBudgetExceededException;
import xyz.docbleach.api.threat.ThreatType;

class PdfBleachBudgetTest {

  private static BleachSession session(ResourceBudget budget) {
    return new BleachSession(new CompositeBleach(new PdfBleach()), budget);
  }

  private static byte[] pdfWithEmbeddedFile(String name, byte[] content) throws Exception {
    try (PDDocument doc = new PDDocument()) {
      doc.addPage(new org.apache.pdfbox.pdmodel.PDPage());

      PDEmbeddedFile embeddedFile = new PDEmbeddedFile(doc, new ByteArrayInputStream(content));
      embeddedFile.setSubtype("text/plain");
      embeddedFile.setSize(content.length);

      PDComplexFileSpecification fileSpec = new PDComplexFileSpecification();
      fileSpec.setFile(name);
      fileSpec.setEmbeddedFile(embeddedFile);

      PDEmbeddedFilesNameTreeNode embeddedFiles = new PDEmbeddedFilesNameTreeNode();
      java.util.Map<String, PDComplexFileSpecification> names = new java.util.HashMap<>();
      names.put(name, fileSpec);
      embeddedFiles.setNames(names);

      PDDocumentNameDictionary namesDictionary = new PDDocumentNameDictionary(doc.getDocumentCatalog());
      namesDictionary.setEmbeddedFiles(embeddedFiles);
      doc.getDocumentCatalog().setNames(namesDictionary);

      ByteArrayOutputStream output = new ByteArrayOutputStream();
      doc.save(output);
      return output.toByteArray();
    }
  }

  @Test
  void pdfWithSmallEmbeddedFileIsSanitizedWithoutRegression() throws Exception {
    byte[] input = pdfWithEmbeddedFile("note.txt", "hello".getBytes());
    BleachSession session = session(new ResourceBudget());
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    session.sanitize(new ByteArrayInputStream(input), output);

    assertTrue(output.size() > 0);
    assertTrue(
        session.getThreats().stream().noneMatch(threat -> threat.type() == ThreatType.RESOURCE_LIMIT));
  }

  @Test
  void oversizedEmbeddedFileTripsTheChainBudgetAndRecordsItsLayer() throws Exception {
    byte[] payload = new byte[64 * 1024];
    byte[] input = pdfWithEmbeddedFile("payload.bin", payload);
    java.util.List<xyz.docbleach.api.threat.Threat> threats = new java.util.ArrayList<>();
    ResourceBudget budget =
        new ResourceBudget(
            // Above the physical PDF size (parsing succeeds) but below parsing + the
            // decompressed embedded payload, so the embedded-file layer triggers the abort.
            100 * 1024,
            ResourceBudget.DEFAULT_MAX_ENTRIES,
            ResourceBudget.DEFAULT_MAX_DEPTH,
            ResourceBudget.DEFAULT_TIME_LIMIT_MILLIS,
            threats::add);
    BleachSession session = session(budget);

    ResourceBudgetExceededException exception =
        assertThrows(
            ResourceBudgetExceededException.class,
            () ->
                session.sanitize(
                    new ByteArrayInputStream(input), new ByteArrayOutputStream()));

    assertEquals(ResourceBudget.Limit.TOTAL_BYTES, exception.getLimit());
    assertTrue(exception.getLocation().contains("pdf-embedded:payload.bin"),
        exception.getLocation());
    assertEquals(
        1,
        threats.stream()
            .filter(threat -> threat.type() == ThreatType.RESOURCE_LIMIT)
            .count());
  }
}
