package analys.sbom.controllers;

import analys.sbom.core.dto.AnalysisResponse;
import analys.sbom.core.dto.ComponentVulnerabilityDto;
import analys.sbom.core.dto.FullAnalysisResponse;
import analys.sbom.core.service.AnalysisService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/analysis")
@RequiredArgsConstructor
public class AnalysisController {

  private final AnalysisService analysisService;

  @PostMapping("/sbom")
  public ResponseEntity<FullAnalysisResponse> analyze(@RequestParam("file") MultipartFile file) {
    FullAnalysisResponse response = analysisService.analyze(file);
    return ResponseEntity.ok(response);
  }

  @GetMapping("/{id}")
  public ResponseEntity<FullAnalysisResponse> getAnalysis(@PathVariable UUID id) {
    FullAnalysisResponse response = analysisService.getAnalysisResult(id);
    return ResponseEntity.ok(response);
  }

  @GetMapping("/{id}/vulnerabilities")
  public ResponseEntity<List<ComponentVulnerabilityDto>> getVulnerabilities(@PathVariable UUID id) {
    FullAnalysisResponse full = analysisService.getAnalysisResult(id);
    return ResponseEntity.ok(full.getFindings());
  }
}