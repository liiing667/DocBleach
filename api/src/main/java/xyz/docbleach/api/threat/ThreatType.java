package xyz.docbleach.api.threat;

/**
 * Used to group threats together
 */
public enum ThreatType {
  /**
   * Macros, JavaScript, ActiveX, AcroForms, DDEAUTO
   */
  ACTIVE_CONTENT,

  /**
   * Word Template linking to an external "thing", ...
   */
  EXTERNAL_CONTENT,

  /**
   * OLE Objects, ...
   */
  BINARY_CONTENT,

  /**
   * OLE Objects, strange image in a document ...
   */
  UNRECOGNIZED_CONTENT,

  /**
   * Compression bombs, deeply nested documents or any input exhausting the shared resource
   * budget (decompressed size, entry count, recursion depth or processing time)
   */
  RESOURCE_LIMIT
}
