package xyz.docbleach.module.pdf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDEmbeddedFilesNameTreeNode;
import org.apache.pdfbox.pdmodel.common.COSObjectable;
import org.apache.pdfbox.pdmodel.common.PDNameTreeNode;
import org.apache.pdfbox.pdmodel.common.filespecification.PDComplexFileSpecification;
import org.apache.pdfbox.pdmodel.common.filespecification.PDEmbeddedFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.docbleach.api.exception.BleachException;
import xyz.docbleach.api.threat.ThreatSeverity;

/**
 * Handles embedded files wherever they are referenced: the document name tree, file attachment
 * annotations, action dictionaries and the EF/RF entries of file specifications. Every embedded
 * file is recursively bleached and every step consumes the session-wide {@link
 * SanitizationBudget}, so deeply nested or duplicated payloads cannot escape the recursion limits.
 */
class PDEmbeddedFileBleach {

  private static final Logger LOGGER = LoggerFactory.getLogger(PDEmbeddedFileBleach.class);
  private static final COSName RELATED_FILES = COSName.getPDFName("RF");

  private final PdfBleachSession pdfBleachSession;
  private final Set<COSDictionary> sanitizedSpecs =
      Collections.newSetFromMap(new IdentityHashMap<COSDictionary, Boolean>());
  private PDDocument doc;

  PDEmbeddedFileBleach(PdfBleachSession pdfBleachSession) {
    this.pdfBleachSession = pdfBleachSession;
  }

  void registerDocument(PDDocument document) {
    this.doc = document;
  }

  boolean isFileSpecification(COSDictionary dictionary) {
    if (COSName.FILESPEC.equals(dictionary.getCOSName(COSName.TYPE))) {
      return true;
    }
    return dictionary.getDictionaryObject(COSName.EF) != null
        || dictionary.getDictionaryObject(RELATED_FILES) != null;
  }

  void sanitizeFileSpecification(COSDictionary dictionary) {
    if (!sanitizedSpecs.add(dictionary)) {
      return;
    }
    sanitizeEmbeddedFile(new PDComplexFileSpecification(dictionary));
    sanitizeRelatedFiles(dictionary);
  }

  private void sanitizeRelatedFiles(COSDictionary dictionary) {
    COSBase relatedFiles = dictionary.getDictionaryObject(RELATED_FILES);
    if (!(relatedFiles instanceof COSDictionary)) {
      return;
    }
    COSDictionary relatedFilesDictionary = (COSDictionary) relatedFiles;
    for (COSName key : new ArrayList<>(relatedFilesDictionary.keySet())) {
      COSBase value = relatedFilesDictionary.getDictionaryObject(key);
      if (value instanceof COSArray) {
        for (COSBase spec : (COSArray) value) {
          sanitizeIfFileSpecification(spec);
        }
      } else {
        sanitizeIfFileSpecification(value);
      }
    }
  }

  private void sanitizeIfFileSpecification(COSBase base) {
    COSBase dereferenced = base instanceof COSObject ? ((COSObject) base).getObject() : base;
    if (dereferenced instanceof COSDictionary
        && isFileSpecification((COSDictionary) dereferenced)) {
      sanitizeFileSpecification((COSDictionary) dereferenced);
    }
  }

  private void sanitizeEmbeddedFile(PDComplexFileSpecification fileSpec) {
    if (!pdfBleachSession.getBudget().claimEmbeddedFile()) {
      LOGGER.warn("Embedded file budget exhausted, dropping {}", fileSpec.getFilename());
      pdfBleachSession.recordEmbeddedFileThreat(
          "Embedded File",
          "Embedded file dropped: sanitization budget exhausted",
          ThreatSeverity.HIGH);
      dropEmbeddedFiles(fileSpec);
      return;
    }

    LOGGER.trace("Embedded file found: {}", fileSpec.getFilename());

    fileSpec.setEmbeddedFile(sanitizeEmbeddedFile(fileSpec.getEmbeddedFile()));
    fileSpec.setEmbeddedFileDos(sanitizeEmbeddedFile(fileSpec.getEmbeddedFileDos()));
    fileSpec.setEmbeddedFileMac(sanitizeEmbeddedFile(fileSpec.getEmbeddedFileMac()));
    fileSpec.setEmbeddedFileUnicode(sanitizeEmbeddedFile(fileSpec.getEmbeddedFileUnicode()));
    fileSpec.setEmbeddedFileUnix(sanitizeEmbeddedFile(fileSpec.getEmbeddedFileUnix()));
  }

  private void dropEmbeddedFiles(PDComplexFileSpecification fileSpec) {
    fileSpec.setEmbeddedFile(null);
    fileSpec.setEmbeddedFileDos(null);
    fileSpec.setEmbeddedFileMac(null);
    fileSpec.setEmbeddedFileUnicode(null);
    fileSpec.setEmbeddedFileUnix(null);
  }

  private PDEmbeddedFile sanitizeEmbeddedFile(PDEmbeddedFile file) {
    if (file == null) {
      return null;
    }

    LOGGER.debug(
        "Sanitizing file: Size: {}, Mime-Type: {}, ", file.getSize(), file.getSubtype());

    ByteArrayInputStream is;
    try {
      is = new ByteArrayInputStream(file.toByteArray());
    } catch (IOException e) {
      LOGGER.error("Error during original's file read", e);
      return null;
    }
    ByteArrayOutputStream os = new ByteArrayOutputStream();

    try {
      pdfBleachSession.getSession().sanitize(is, os);
    } catch (BleachException e) {
      LOGGER.error("Error during the bleach process", e);
      return null;
    }

    if (os.size() == 0) {
      // No bleach was able to handle this content: keep the original bytes instead of
      // silently replacing the attachment by an empty file.
      LOGGER.trace("No inner bleach matched, keeping embedded file untouched");
      return file;
    }

    ByteArrayInputStream fakeFile = new ByteArrayInputStream(os.toByteArray());

    PDEmbeddedFile bleachedFile;
    try {
      bleachedFile = new PDEmbeddedFile(doc, fakeFile, COSName.FLATE_DECODE);
      bleachedFile.setCreationDate(file.getCreationDate());
      bleachedFile.setModDate(file.getModDate());
    } catch (IOException e) {
      LOGGER.error("Error when creating the new sane file", e);
      return null;
    }

    // We copy the properties of the real embedded file
    bleachedFile.setSubtype(file.getSubtype());
    bleachedFile.setSize(os.size());
    bleachedFile.setMacCreator(file.getMacCreator());
    bleachedFile.setMacResFork(file.getMacResFork());
    bleachedFile.setMacSubtype(file.getMacSubtype());

    // We remove the real file
    file.setSize(0);
    file.setFile(null);

    try {
      // And we empty it
      file.createOutputStream().close();
    } catch (IOException e) {
      LOGGER.error("Error when trying to empty the original embedded file", e);
      // Not severe, don't abort operations.
    }
    return bleachedFile;
  }

  private <T extends COSObjectable> void sanitizeRecursiveNameTree(
      PDNameTreeNode<T> efTree, Consumer<T> callback) {
    if (efTree == null) {
      return;
    }
    if (pdfBleachSession.getBudget().isExhausted()) {
      LOGGER.warn("Embedded file name tree traversal stopped, budget is exhausted");
      return;
    }

    Map<String, T> names;
    try {
      names = efTree.getNames();
    } catch (IOException e) {
      LOGGER.error("Error in sanitizeRecursiveNameTree", e);
      return;
    }

    if (names != null) {
      names.values().forEach(callback);
    }
    if (efTree.getKids() == null) {
      return;
    }
    for (PDNameTreeNode<T> node : efTree.getKids()) {
      sanitizeRecursiveNameTree(node, callback);
    }
  }

  void sanitize(PDEmbeddedFilesNameTreeNode embeddedFiles) {
    sanitizeRecursiveNameTree(
        embeddedFiles,
        fileSpec -> sanitizeFileSpecification(fileSpec.getCOSObject()));
  }
}
