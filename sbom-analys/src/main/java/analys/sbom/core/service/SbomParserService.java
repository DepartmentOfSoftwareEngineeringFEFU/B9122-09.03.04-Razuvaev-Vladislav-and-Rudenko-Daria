package analys.sbom.core.service;

import analys.sbom.core.dto.NormalizedComponent;
import analys.sbom.core.dto.SbomFormat;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.parsers.JsonParser;
import org.cyclonedx.parsers.XmlParser;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class SbomParserService {

  public Bom parse(MultipartFile file, SbomFormat format) {
    byte[] bytes;
    try {
      bytes = file.getBytes();
    } catch (Exception e) {
      throw new IllegalStateException("Не удалось прочитать файл: "
          + file.getOriginalFilename(), e);
    }

    return switch (format) {
      case CYCLONEDX_JSON -> parseCycloneDxJson(bytes, file.getOriginalFilename());
      case CYCLONEDX_XML -> parseCycloneDxXml(bytes, file.getOriginalFilename());
      case SPDX_JSON -> parseSpdxJson(bytes, file.getOriginalFilename());
      case SPDX_XML -> parseSpdxXml(bytes, file.getOriginalFilename());
    };
  }

  public Bom parse(MultipartFile file) {
    byte[] bytes;
    try {
      bytes = file.getBytes();
    } catch (Exception e) {
      throw new IllegalStateException("Не удалось прочитать файл: "
          + file.getOriginalFilename(), e);
    }

    try {
      Bom bom = new JsonParser().parse(new ByteArrayInputStream(bytes));
      log.info("SBOM распознан как CycloneDX JSON: {}", file.getOriginalFilename());
      return bom;
    } catch (Exception ignored) {
    }

    try {
      Bom bom = new XmlParser().parse(new ByteArrayInputStream(bytes));
      log.info("SBOM распознан как CycloneDX XML: {}", file.getOriginalFilename());
      return bom;
    } catch (Exception ignored) {
    }

    try {
      Bom bom = parseSpdxJson(bytes, file.getOriginalFilename());
      log.info("SBOM распознан как SPDX JSON: {}", file.getOriginalFilename());
      return bom;
    } catch (Exception ignored) {
    }

    throw new IllegalStateException(
        "Не удалось распарсить SBOM: неизвестный формат — " + file.getOriginalFilename());
  }

  private Bom parseCycloneDxJson(byte[] bytes, String filename) {
    try {
      Bom bom = new JsonParser().parse(new ByteArrayInputStream(bytes));
      log.info("CycloneDX JSON: {}", filename);
      return bom;
    } catch (Exception e) {
      throw new IllegalStateException("Ошибка парсинга CycloneDX JSON: " + filename, e);
    }
  }

  private Bom parseCycloneDxXml(byte[] bytes, String filename) {
    try {
      Bom bom = new XmlParser().parse(new ByteArrayInputStream(bytes));
      log.info("CycloneDX XML: {}", filename);
      return bom;
    } catch (Exception e) {
      throw new IllegalStateException("Ошибка парсинга CycloneDX XML: " + filename, e);
    }
  }

  private Bom parseSpdxJson(byte[] bytes, String filename) {
    try {
      String json = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);

      if (!json.contains("\"SPDXID\"") && !json.contains("\"spdxVersion\"")) {
        throw new IllegalArgumentException("Не является SPDX JSON");
      }

      com.fasterxml.jackson.databind.ObjectMapper mapper =
          new com.fasterxml.jackson.databind.ObjectMapper();
      com.fasterxml.jackson.databind.JsonNode root = mapper.readTree(bytes);

      Bom bom = new Bom();

      String docName = root.path("name").asText("unknown");
      org.cyclonedx.model.Metadata metadata = new org.cyclonedx.model.Metadata();
      org.cyclonedx.model.Component rootComp = new org.cyclonedx.model.Component();
      rootComp.setName(docName);
      rootComp.setBomRef("spdx-root");
      metadata.setComponent(rootComp);
      bom.setMetadata(metadata);

      List<org.cyclonedx.model.Component> components = new ArrayList<>();
      com.fasterxml.jackson.databind.JsonNode packages = root.path("packages");
      if (packages.isArray()) {
        for (com.fasterxml.jackson.databind.JsonNode pkg : packages) {
          String spdxId = pkg.path("SPDXID").asText();
          String name = pkg.path("name").asText();
          String version = pkg.path("versionInfo").asText(null);

            if ("SPDXRef-DOCUMENT".equals(spdxId)) {
                continue;
            }

          org.cyclonedx.model.Component comp = new org.cyclonedx.model.Component();
          comp.setType(org.cyclonedx.model.Component.Type.LIBRARY);
          comp.setBomRef(spdxId);
          comp.setName(name);
          comp.setVersion(version);

          com.fasterxml.jackson.databind.JsonNode refs = pkg.path("externalRefs");
          if (refs.isArray()) {
            for (com.fasterxml.jackson.databind.JsonNode ref : refs) {
              if ("purl".equals(ref.path("referenceType").asText())) {
                comp.setPurl(ref.path("referenceLocator").asText());
                break;
              }
            }
          }

          components.add(comp);
        }
      }
      bom.setComponents(components);

      Map<String, List<String>> depMap = new HashMap<>();
      com.fasterxml.jackson.databind.JsonNode rels = root.path("relationships");
      if (rels.isArray()) {
        for (com.fasterxml.jackson.databind.JsonNode rel : rels) {
          String type = rel.path("relationshipType").asText();
          String srcId = rel.path("spdxElementId").asText();
          String dstId = rel.path("relatedSpdxElement").asText();
          // DEPENDS_ON = прямая зависимость
          if ("DEPENDS_ON".equals(type) || "DYNAMIC_LINK".equals(type)
              || "STATIC_LINK".equals(type)) {
            depMap.computeIfAbsent(srcId, k -> new ArrayList<>()).add(dstId);
          }
        }
      }

      List<org.cyclonedx.model.Dependency> dependencies = new ArrayList<>();
      depMap.forEach((src, children) -> {
        org.cyclonedx.model.Dependency dep = new org.cyclonedx.model.Dependency(src);
        children.forEach(child -> dep.addDependency(
            new org.cyclonedx.model.Dependency(child)));
        dependencies.add(dep);
      });
      bom.setDependencies(dependencies);

      log.info("SPDX JSON адаптирован: {} компонентов из {}", components.size(), filename);
      return bom;

    } catch (Exception e) {
      throw new IllegalStateException("Ошибка парсинга SPDX JSON: " + filename, e);
    }
  }

  private Bom parseSpdxXml(byte[] bytes, String filename) {
    try {
      String xml = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);

      if (!xml.contains("spdx") && !xml.contains("SPDX")) {
        throw new IllegalArgumentException("Не является SPDX XML/RDF");
      }

      try {
        return new XmlParser().parse(new ByteArrayInputStream(bytes));
      } catch (Exception ignored) {
      }

      Bom bom = new Bom();
      List<org.cyclonedx.model.Component> components = new ArrayList<>();

      java.util.regex.Pattern namePattern = java.util.regex.Pattern
          .compile("<spdx:name>([^<]+)</spdx:name>");
      java.util.regex.Pattern versionPattern = java.util.regex.Pattern
          .compile("<spdx:versionInfo>([^<]+)</spdx:versionInfo>");

      java.util.regex.Matcher nameMatcher = namePattern.matcher(xml);
      java.util.regex.Matcher versionMatcher = versionPattern.matcher(xml);

      List<String> names = new ArrayList<>();
      List<String> versions = new ArrayList<>();
        while (nameMatcher.find()) {
            names.add(nameMatcher.group(1).trim());
        }
        while (versionMatcher.find()) {
            versions.add(versionMatcher.group(1).trim());
        }

      for (int i = 0; i < names.size(); i++) {
        org.cyclonedx.model.Component comp = new org.cyclonedx.model.Component();
        comp.setType(org.cyclonedx.model.Component.Type.LIBRARY);
        comp.setName(names.get(i));
        comp.setBomRef("spdx-rdf-" + i);
          if (i < versions.size()) {
              comp.setVersion(versions.get(i));
          }
        components.add(comp);
      }

      bom.setComponents(components);
      log.info("SPDX XML/RDF адаптирован: {} компонентов из {}", components.size(), filename);
      return bom;

    } catch (Exception e) {
      throw new IllegalStateException("Ошибка парсинга SPDX XML: " + filename, e);
    }
  }

  public List<NormalizedComponent> normalize(Bom bom) {
      if (bom.getComponents() == null) {
          return List.of();
      }
    return bom.getComponents().stream()
        .map(this::toNormalized)
        .toList();
  }

  public String extractProjectName(Bom bom) {
    try {
      if (bom.getMetadata() != null
          && bom.getMetadata().getComponent() != null
          && bom.getMetadata().getComponent().getName() != null) {
        return bom.getMetadata().getComponent().getName();
      }
    } catch (Exception e) {
      log.warn("Не удалось извлечь projectName из metadata: {}", e.getMessage());
    }
    return "unknown";
  }

  private NormalizedComponent toNormalized(Component component) {
    return NormalizedComponent.builder()
        .name(component.getName())
        .version(component.getVersion())
        .purl(component.getPurl())
        .ecosystem(extractEcosystem(component.getPurl()))
        .build();
  }

  private String extractEcosystem(String purl) {
      if (purl == null || purl.isBlank()) {
          return "generic";
      }
    try {
      String withoutPkg = purl.substring(purl.indexOf(':') + 1);
      int slashIdx = withoutPkg.indexOf('/');
      return slashIdx > 0 ? withoutPkg.substring(0, slashIdx) : "generic";
    } catch (Exception e) {
      return "generic";
    }
  }
}