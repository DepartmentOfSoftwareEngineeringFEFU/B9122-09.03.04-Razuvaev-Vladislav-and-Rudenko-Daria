package analys.sbom.core.service;

import analys.sbom.core.dto.*;
import analys.sbom.core.entity.*;
import analys.sbom.core.repository.AnalysisRepository;
import analys.sbom.core.repository.AnalysisVulnerabilityLinkRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.cyclonedx.model.Bom;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultEdge;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AnalysisService {

  private final SbomParserService parserService;
  private final DependencyGraphService graphService;
  private final VulnerabilityService vulnerabilityService;
  private final RecommendationService recommendationService;
  private final AnalysisRepository analysisRepository;
  private final AnalysisVulnerabilityLinkRepository linkRepository;

  @PersistenceContext
  private EntityManager entityManager;

  @Transactional
  public FullAnalysisResponse analyze(MultipartFile file) {

    Bom bom = parserService.parse(file);
    List<NormalizedComponent> components = parserService.normalize(bom);
    String projectName = parserService.extractProjectName(bom);

    Graph<String, DefaultEdge> graph = graphService.buildGraph(bom);
    Map<String, String> displayNames = buildDisplayNames(bom);
    Map<String, String> nameToBomRef = buildNameToBomRef(bom);

    Map<NormalizedComponent, List<VulnerabilityEntity>> vulnsByComponent = new LinkedHashMap<>();
    for (NormalizedComponent component : components) {
      List<VulnerabilityEntity> vulns = vulnerabilityService.find(component);
      if (!vulns.isEmpty()) {
        vulnsByComponent.put(component, vulns);
      }
    }

    Map<UUID, VulnerabilityEntity> uniqueVulns = new LinkedHashMap<>();
    vulnsByComponent.values().forEach(list ->
        list.forEach(v -> uniqueVulns.put(v.getId(), v)));

    for (VulnerabilityEntity vuln : uniqueVulns.values()) {
      entityManager.persist(vuln);
    }
    entityManager.flush();

    List<ComponentVulnerabilityDto> findings = new ArrayList<>();
    int vulnerableCount = 0;

    for (Map.Entry<NormalizedComponent, List<VulnerabilityEntity>> entry
        : vulnsByComponent.entrySet()) {

      NormalizedComponent component = entry.getKey();
      List<VulnerabilityEntity> vulns = entry.getValue();
      vulnerableCount++;

      String bomRef = nameToBomRef.get(component.getName());
      int depth = bomRef != null ? graphService.computeDepth(graph, bomRef) : -1;
      boolean isDirect = depth == 1;
      String path = bomRef != null
          ? graphService.findPath(graph, bomRef, displayNames)
          : component.getName();

      List<VulnerabilitySummaryDto> vulnDtos = vulns.stream()
          .map(v -> {
            RecommendationDto rec = recommendationService
                .buildRecommendation(v, Math.max(depth, 0), isDirect);
            return VulnerabilitySummaryDto.builder()
                .id(v.getId().toString())
                .cveId(v.getCveId())
                .severity(v.getSeverity())
                .description(v.getDescription())
                .versionStart(v.getVersionStart())
                .versionEnd(v.getVersionEnd())
                .dependencyPath(path)
                .depth(Math.max(depth, 0))
                .isDirect(isDirect)
                .recommendation(rec)
                .build();
          })
          .collect(Collectors.toList());

      findings.add(ComponentVulnerabilityDto.builder()
          .componentName(component.getName())
          .version(component.getVersion())
          .purl(component.getPurl())
          .vulnerabilities(vulnDtos)
          .build());
    }

    AnalysisEntity analysis = AnalysisEntity.builder()
        .projectName(projectName)
        .sbomName(file.getOriginalFilename())
        .status("DONE")
        .createdAt(Instant.now())
        .totalComponents(components.size())
        .vulnerableComponents(vulnerableCount)
        .build();
    analysis = analysisRepository.save(analysis);

    List<AnalysisVulnerabilityLink> links = new ArrayList<>();
    for (ComponentVulnerabilityDto finding : findings) {
      for (VulnerabilitySummaryDto vuln : finding.getVulnerabilities()) {
        links.add(AnalysisVulnerabilityLink.builder()
            .analysisId(analysis.getId())
            .vulnerabilityId(UUID.fromString(vuln.getId()))
            .componentName(finding.getComponentName())
            .componentVersion(finding.getVersion())
            .purl(finding.getPurl())
            .build());
      }
    }
    if (!links.isEmpty()) {
      linkRepository.saveAll(links);
    }

    log.info("Анализ завершён: {} компонентов, {} уязвимых",
        components.size(), vulnerableCount);
    return toResponse(analysis, findings);
  }

  @Transactional(readOnly = true)
  public FullAnalysisResponse getAnalysisResult(UUID analysisId) {
    AnalysisEntity analysis = analysisRepository.findById(analysisId)
        .orElseThrow(() -> new IllegalArgumentException("Analysis not found: " + analysisId));

    List<AnalysisVulnerabilityLink> links = linkRepository.findByAnalysisId(analysisId);

    Map<String, List<VulnerabilitySummaryDto>> byComponent = links.stream()
        .collect(Collectors.groupingBy(
            AnalysisVulnerabilityLink::getComponentName,
            Collectors.mapping(link -> {
              VulnerabilityEntity v = link.getVulnerability();
              return VulnerabilitySummaryDto.builder()
                  .id(v.getId().toString())
                  .cveId(v.getCveId())
                  .severity(v.getSeverity())
                  .description(v.getDescription())
                  .versionStart(v.getVersionStart())
                  .versionEnd(v.getVersionEnd())
                  .build();
            }, Collectors.toList())
        ));

    List<ComponentVulnerabilityDto> findings = byComponent.entrySet().stream()
        .map(entry -> {
          AnalysisVulnerabilityLink first = links.stream()
              .filter(l -> l.getComponentName().equals(entry.getKey()))
              .findFirst().orElseThrow();
          return ComponentVulnerabilityDto.builder()
              .componentName(entry.getKey())
              .version(first.getComponentVersion())
              .purl(first.getPurl())
              .vulnerabilities(entry.getValue())
              .build();
        }).toList();

    return toResponse(analysis, findings);
  }

  @Transactional
  public FullAnalysisResponse analyze(File file) throws IOException {
    org.springframework.mock.web.MockMultipartFile multipart =
        new org.springframework.mock.web.MockMultipartFile(
            "file", file.getName(), "application/json",
            new FileInputStream(file));
    return analyze(multipart);
  }

  private FullAnalysisResponse toResponse(AnalysisEntity analysis,
      List<ComponentVulnerabilityDto> findings) {
    return FullAnalysisResponse.builder()
        .id(analysis.getId())
        .projectName(analysis.getProjectName())
        .sbomName(analysis.getSbomName())
        .createdAt(analysis.getCreatedAt())
        .status(analysis.getStatus())
        .totalComponents(analysis.getTotalComponents())
        .vulnerableComponents(analysis.getVulnerableComponents())
        .findings(findings)
        .build();
  }

  private Map<String, String> buildDisplayNames(Bom bom) {
    Map<String, String> map = new HashMap<>();
    if (bom.getComponents() == null) {
      return map;
    }
    bom.getComponents().forEach(c -> {
      if (c.getBomRef() != null) {
        String ver = c.getVersion() != null ? " " + c.getVersion() : "";
        map.put(c.getBomRef(), c.getName() + ver);
      }
    });
    return map;
  }

  private Map<String, String> buildNameToBomRef(Bom bom) {
    Map<String, String> map = new HashMap<>();
    if (bom.getComponents() == null) {
      return map;
    }
    bom.getComponents().forEach(c -> {
      if (c.getName() != null && c.getBomRef() != null) {
        map.putIfAbsent(c.getName(), c.getBomRef());
      }
    });
    return map;
  }
}