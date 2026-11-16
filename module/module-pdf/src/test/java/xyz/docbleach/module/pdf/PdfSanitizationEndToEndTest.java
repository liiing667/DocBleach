package xyz.docbleach.module.pdf;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDDocumentNameDictionary;
import org.apache.pdfbox.pdmodel.PDEmbeddedFilesNameTreeNode;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.filespecification.PDComplexFileSpecification;
import org.apache.pdfbox.pdmodel.common.filespecification.PDEmbeddedFile;
import org.apache.pdfbox.pdmodel.interactive.action.PDAction;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionJavaScript;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionLaunch;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionURI;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationFileAttachment;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationLink;
import org.junit.jupiter.api.Test;
import xyz.docbleach.api.BleachSession;
import xyz.docbleach.api.threat.Threat;

class PdfSanitizationEndToEndTest {

  private static final byte[] EMBEDDED_PAYLOAD = "nested payload".getBytes();

  @Test
  void hiddenCatalogAndAnnotationThreatsAreRemovedWhileLinksSurvive() throws Exception {
    byte[] rawPdf = buildMaliciousPdf();

    BleachSession session = new BleachSession(new PdfBleach());
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    new PdfBleach().sanitize(new ByteArrayInputStream(rawPdf), out, session);

    assertTrue(session.threatCount() >= 3, "threats were recorded: " + session.getThreats());
    assertTrue(
        session.getThreats().stream().map(Threat::details).anyMatch(d -> d.contains("Launch")));

    try (PDDocument sanitized = PDDocument.load(out.toByteArray())) {
      PDDocumentCatalog catalog = sanitized.getDocumentCatalog();
      assertNull(catalog.getOpenAction(), "dangerous catalog OpenAction must be removed");

      PDAnnotationLink link =
          (PDAnnotationLink) catalog.getPages().get(0).getAnnotations().get(0);
      assertNotNull(link.getAction(), "innocuous URI link must keep working");
      assertEquals(
          "https://example.org", ((PDActionURI) link.getAction()).getURI());

      PDAnnotationFileAttachment attachment = null;
      for (PDAnnotation annotation : catalog.getPages().get(0).getAnnotations()) {
        if (annotation instanceof PDAnnotationFileAttachment) {
          attachment = (PDAnnotationFileAttachment) annotation;
        }
      }
      assertNotNull(attachment);
      COSDictionary fileSpec = attachment.getCOSObject().getCOSDictionary(
          COSName.getPDFName("FS"));
      assertNotNull(fileSpec);
      PDComplexFileSpecification spec = new PDComplexFileSpecification(fileSpec);
      assertNotNull(spec.getEmbeddedFile(), "attachment must still be present after recursion");
    }
  }

  @Test
  void embeddedFilesAreRecursivelyBleachedUnderTheSameSession() throws Exception {
    byte[] rawPdf = buildPdfWithEmbeddedFile();

    BleachSession session = new BleachSession(new PdfBleach());
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    new PdfBleach().sanitize(new ByteArrayInputStream(rawPdf), out, session);

    try (PDDocument sanitized = PDDocument.load(out.toByteArray())) {
      PDEmbeddedFilesNameTreeNode tree =
          sanitized.getDocumentCatalog().getNames().getEmbeddedFiles();
      PDComplexFileSpecification spec = tree.getValue("attachment.txt");
      assertNotNull(spec);
      PDEmbeddedFile embeddedFile = spec.getEmbeddedFile();
      assertNotNull(embeddedFile);
      assertArrayEquals(EMBEDDED_PAYLOAD, embeddedFile.toByteArray());
    }
  }

  @Test
  void nestedPdfEmbeddedFileIsRecursivelySanitized() throws Exception {
    byte[] innerPdf = buildPdfWithJavaScriptOpenAction();
    byte[] outerPdf = buildPdfEmbedding(innerPdf, "inner.pdf", "application/pdf");

    BleachSession session = new BleachSession(new PdfBleach());
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    new PdfBleach().sanitize(new ByteArrayInputStream(outerPdf), out, session);

    try (PDDocument outer = PDDocument.load(out.toByteArray())) {
      PDComplexFileSpecification spec =
          outer.getDocumentCatalog().getNames().getEmbeddedFiles().getValue("inner.pdf");
      byte[] sanitizedInner = spec.getEmbeddedFile().toByteArray();
      assertTrue(sanitizedInner.length > 0);
      try (PDDocument inner = PDDocument.load(sanitizedInner)) {
        PDAction openAction = (PDAction) inner.getDocumentCatalog().getOpenAction();
        assertNull(openAction, "JavaScript inside the nested PDF must be removed");
      }
    }
    assertTrue(
        session.getThreats().stream()
            .anyMatch(threat -> threat.details().contains("JavaScript")),
        "the nested JavaScript threat was reported in the same threat report");
  }

  private byte[] buildPdfWithJavaScriptOpenAction() throws IOException {
    try (PDDocument doc = new PDDocument()) {
      doc.addPage(new PDPage());
      doc.getDocumentCatalog().setOpenAction(new PDActionJavaScript("app.alert(1)"));
      return save(doc);
    }
  }

  private byte[] buildPdfEmbedding(byte[] content, String name, String subtype)
      throws IOException {
    try (PDDocument doc = new PDDocument()) {
      doc.addPage(new PDPage());
      PDComplexFileSpecification fileSpec = new PDComplexFileSpecification();
      fileSpec.setFile(name);
      PDEmbeddedFile embeddedFile =
          new PDEmbeddedFile(doc, new ByteArrayInputStream(content));
      embeddedFile.setSubtype(subtype);
      fileSpec.setEmbeddedFile(embeddedFile);

      Map<String, PDComplexFileSpecification> names = new HashMap<>();
      names.put(name, fileSpec);
      PDEmbeddedFilesNameTreeNode tree = new PDEmbeddedFilesNameTreeNode();
      tree.setNames(names);

      PDDocumentNameDictionary nameDictionary =
          new PDDocumentNameDictionary(doc.getDocumentCatalog());
      nameDictionary.setEmbeddedFiles(tree);
      doc.getDocumentCatalog().setNames(nameDictionary);

      return save(doc);
    }
  }

  private byte[] buildMaliciousPdf() throws IOException {
    try (PDDocument doc = new PDDocument()) {
      PDDocumentCatalog catalog = doc.getDocumentCatalog();
      PDPage page = new PDPage();
      doc.addPage(page);

      // Launch action hidden at the document level
      catalog.setOpenAction(new PDActionLaunch());

      // Innocuous external link that must keep working
      PDAnnotationLink link = new PDAnnotationLink();
      PDActionURI uri = new PDActionURI();
      uri.setURI("https://example.org");
      link.setAction(uri);
      page.getAnnotations().add(link);

      // JavaScript hidden on an annotation, plus a recursively handled attachment
      PDAnnotationLink maliciousLink = new PDAnnotationLink();
      maliciousLink.setAction(new PDActionJavaScript("app.alert(1)"));
      page.getAnnotations().add(maliciousLink);

      PDAnnotationFileAttachment attachment = new PDAnnotationFileAttachment();
      PDComplexFileSpecification fileSpec = new PDComplexFileSpecification();
      fileSpec.setFile("attachment.txt");
      PDEmbeddedFile embeddedFile =
          new PDEmbeddedFile(doc, new ByteArrayInputStream(EMBEDDED_PAYLOAD));
      fileSpec.setEmbeddedFile(embeddedFile);
      attachment.setFile(fileSpec);
      page.getAnnotations().add(attachment);

      return save(doc);
    }
  }

  private byte[] buildPdfWithEmbeddedFile() throws IOException {
    try (PDDocument doc = new PDDocument()) {
      doc.addPage(new PDPage());
      PDDocumentCatalog catalog = doc.getDocumentCatalog();

      PDComplexFileSpecification fileSpec = new PDComplexFileSpecification();
      fileSpec.setFile("attachment.txt");
      fileSpec.setEmbeddedFile(
          new PDEmbeddedFile(doc, new ByteArrayInputStream(EMBEDDED_PAYLOAD)));

      Map<String, PDComplexFileSpecification> names = new HashMap<>();
      names.put("attachment.txt", fileSpec);
      PDEmbeddedFilesNameTreeNode tree = new PDEmbeddedFilesNameTreeNode();
      tree.setNames(names);

      PDDocumentNameDictionary nameDictionary = new PDDocumentNameDictionary(catalog);
      nameDictionary.setEmbeddedFiles(tree);
      catalog.setNames(nameDictionary);

      return save(doc);
    }
  }

  private byte[] save(PDDocument doc) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    doc.save(out);
    return out.toByteArray();
  }
}
