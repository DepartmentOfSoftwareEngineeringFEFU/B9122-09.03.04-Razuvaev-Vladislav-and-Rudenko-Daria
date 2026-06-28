package analys.sbom.core.dto;

public enum SbomFormat {

  CYCLONEDX_JSON("CycloneDX JSON", "*.json", "application/json"),
  CYCLONEDX_XML("CycloneDX XML", "*.xml", "application/xml"),
  SPDX_JSON("SPDX JSON", "*.json", "application/json"),
  SPDX_XML("SPDX XML (RDF)", "*.xml", "application/xml");

  public final String displayName;
  public final String extension;
  public final String mimeType;

  SbomFormat(String displayName, String extension, String mimeType) {
    this.displayName = displayName;
    this.extension = extension;
    this.mimeType = mimeType;
  }

  public boolean isCycloneDx() {
    return this == CYCLONEDX_JSON || this == CYCLONEDX_XML;
  }

  public boolean isSpdx() {
    return this == SPDX_JSON || this == SPDX_XML;
  }

  public boolean isJson() {
    return this == CYCLONEDX_JSON || this == SPDX_JSON;
  }
}