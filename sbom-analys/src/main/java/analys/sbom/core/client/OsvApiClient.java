package analys.sbom.core.client;

import analys.sbom.core.dto.NormalizedComponent;
import analys.sbom.core.entity.VulnerabilityEntity;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
@RequiredArgsConstructor
public class OsvApiClient {

  private static final String OSV_QUERY_URL = "https://api.osv.dev/v1/query";
  private static final long CACHE_TTL_MS = 24 * 60 * 60 * 1000L; // 24 часа

  private final RestTemplate restTemplate;
  private final ObjectMapper objectMapper;

  private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

  public List<VulnerabilityEntity> queryVulnerabilities(NormalizedComponent component) {
    String cacheKey = buildCacheKey(component);

    CacheEntry cached = cache.get(cacheKey);
    if (cached != null && !cached.isExpired()) {
      log.debug("OSV кэш-попадание для: {}", cacheKey);
      return cached.result;
    }

    List<VulnerabilityEntity> result = fetchFromOsv(component);

    cache.put(cacheKey, new CacheEntry(result));
    return result;
  }

  private List<VulnerabilityEntity> fetchFromOsv(NormalizedComponent component) {
    try {
      String body = buildRequestBody(component);
      if (body == null) return Collections.emptyList();

      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);
      HttpEntity<String> request = new HttpEntity<>(body, headers);

      log.debug("OSV запрос: {} {}", component.getName(), component.getVersion());

      ResponseEntity<String> response = restTemplate.postForEntity(
          OSV_QUERY_URL, request, String.class);

      if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
        return Collections.emptyList();
      }

      return parseResponse(response.getBody(), component);

    } catch (Exception e) {
      log.warn("Ошибка OSV API для компонента {}: {}", component.getName(), e.getMessage());
      CacheEntry stale = cache.get(buildCacheKey(component));
      return stale != null ? stale.result : Collections.emptyList();
    }
  }

  private String buildRequestBody(NormalizedComponent component) throws Exception {
    Map<String, Object> body = new LinkedHashMap<>();

    if (component.getVersion() != null && !component.getVersion().isBlank()) {
      body.put("version", component.getVersion());
    }

    if (component.getPurl() != null) {
      body.put("package", Map.of("purl", normalizePurl(component.getPurl())));
    } else if (component.getName() != null && component.getEcosystem() != null) {
      body.put("package", Map.of(
          "name", component.getName(),
          "ecosystem", toOsvEcosystem(component.getEcosystem())
      ));
    } else {
      return null;
    }

    return objectMapper.writeValueAsString(body);
  }

  private String normalizePurl(String purl) {
    if (purl == null) return null;
    int atIdx = purl.indexOf('@');
    return atIdx > 0 ? purl.substring(0, atIdx) : purl;
  }

  private String toOsvEcosystem(String ecosystem) {
    if (ecosystem == null) return "generic";
    return switch (ecosystem.toLowerCase()) {
      case "maven"            -> "Maven";
      case "npm"              -> "npm";
      case "pypi"             -> "PyPI";
      case "go", "golang"     -> "Go";
      case "nuget"            -> "NuGet";
      case "gem", "rubygems"  -> "RubyGems";
      case "cargo", "crates"  -> "crates.io";
      case "composer"         -> "Packagist";
      case "hex"              -> "Hex";
      case "pub"              -> "Pub";
      default                 -> ecosystem;
    };
  }

  private List<VulnerabilityEntity> parseResponse(String json, NormalizedComponent component) {
    List<VulnerabilityEntity> result = new ArrayList<>();
    try {
      JsonNode root = objectMapper.readTree(json);
      JsonNode vulns = root.path("vulns");
      if (!vulns.isArray()) return Collections.emptyList();

      for (JsonNode vulnNode : vulns) {
        VulnerabilityEntity entity = toEntity(vulnNode, component);
        if (entity != null) result.add(entity);
      }
    } catch (Exception e) {
      log.warn("Ошибка парсинга ответа OSV: {}", e.getMessage());
    }
    return result;
  }

  private VulnerabilityEntity toEntity(JsonNode vuln, NormalizedComponent component) {
    String osvId = vuln.path("id").asText(null);
    if (osvId == null) return null;

    String cveId = osvId;
    for (JsonNode alias : vuln.path("aliases")) {
      String a = alias.asText("");
      if (a.startsWith("CVE-")) { cveId = a; break; }
    }

    String description = vuln.path("summary").asText("");
    if (description.isBlank()) {
      description = vuln.path("details").asText("Описание отсутствует");
    }
    if (description.length() > 1000) description = description.substring(0, 997) + "...";

    String severity = extractSeverity(vuln);

    String versionStart = null;
    String versionEnd   = null;
    JsonNode affected = vuln.path("affected");
    if (affected.isArray() && !affected.isEmpty()) {
      for (JsonNode range : affected.get(0).path("ranges")) {
        for (JsonNode event : range.path("events")) {
          if (event.has("introduced")) {
            String v = event.path("introduced").asText("0");
            if (!"0".equals(v)) versionStart = v;
          }
          if (event.has("fixed")) {
            versionEnd = event.path("fixed").asText();
          }
        }
      }
    }

    return VulnerabilityEntity.builder()
        .id(UUID.randomUUID())
        .cveId(cveId)
        .packageName(component.getName())
        .ecosystem(toOsvEcosystem(component.getEcosystem()))
        .versionStart(versionStart)
        .versionEnd(versionEnd)
        .severity(severity)
        .description(description)
        .build();
  }

  private String extractSeverity(JsonNode vuln) {
    String dbSev = vuln.path("database_specific").path("severity").asText("");
    if (!dbSev.isBlank()) return normalizeSeverity(dbSev);

    for (JsonNode sev : vuln.path("severity")) {
      String type  = sev.path("type").asText("");
      String score = sev.path("score").asText("");
      if (type.startsWith("CVSS") && !score.isBlank()) {
        return cvssVectorToSeverity(score);
      }
    }

    return "UNKNOWN";
  }

  private String normalizeSeverity(String raw) {
    return switch (raw.toUpperCase()) {
      case "CRITICAL"           -> "CRITICAL";
      case "HIGH"               -> "HIGH";
      case "MODERATE", "MEDIUM" -> "MEDIUM";
      case "LOW"                -> "LOW";
      default                   -> raw.toUpperCase();
    };
  }

  private String cvssVectorToSeverity(String score) {
    try {
      double val = Double.parseDouble(score);
      if (val >= 9.0) return "CRITICAL";
      if (val >= 7.0) return "HIGH";
      if (val >= 4.0) return "MEDIUM";
      return "LOW";
    } catch (NumberFormatException ignored) {
      return "UNKNOWN";
    }
  }

  private String buildCacheKey(NormalizedComponent c) {
    String base = c.getPurl() != null ? c.getPurl() : (c.getEcosystem() + ":" + c.getName());
    return base + "@" + c.getVersion();
  }

  private static class CacheEntry {
    final List<VulnerabilityEntity> result;
    final long createdAt = System.currentTimeMillis();

    CacheEntry(List<VulnerabilityEntity> result) {
      this.result = result;
    }

    boolean isExpired() {
      return System.currentTimeMillis() - createdAt > CACHE_TTL_MS;
    }
  }
}