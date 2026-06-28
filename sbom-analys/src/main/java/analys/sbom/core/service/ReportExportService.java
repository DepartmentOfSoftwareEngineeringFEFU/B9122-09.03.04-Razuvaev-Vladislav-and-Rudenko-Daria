package analys.sbom.core.service;

import analys.sbom.core.dto.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class ReportExportService {

  private static final DateTimeFormatter DT_FMT =
      DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss");


  public void exportTxt(FullAnalysisResponse result, Path outputPath) throws Exception {
    StringBuilder sb = new StringBuilder();

    sb.append("=".repeat(64)).append("\n");
    sb.append("  SBOM ANALYZER — ОТЧЁТ О БЕЗОПАСНОСТИ\n");
    sb.append("=".repeat(64)).append("\n\n");

    sb.append("Проект:          ").append(nvl(result.getProjectName())).append("\n");
    sb.append("SBOM-файл:       ").append(nvl(result.getSbomName())).append("\n");
    sb.append("Дата анализа:    ").append(LocalDateTime.now().format(DT_FMT)).append("\n");
    sb.append("Статус:          ").append(nvl(result.getStatus())).append("\n");
    sb.append("Компонентов:     ").append(result.getTotalComponents()).append("\n");
    sb.append("Уязвимых:        ").append(result.getVulnerableComponents()).append("\n\n");

    long critical = countBySeverity(result, "CRITICAL");
    long high = countBySeverity(result, "HIGH");
    long medium = countBySeverity(result, "MEDIUM");
    long low = countBySeverity(result, "LOW");

    sb.append("─".repeat(64)).append("\n");
    sb.append("  СВОДКА ПО КРИТИЧНОСТИ\n");
    sb.append("─".repeat(64)).append("\n");
    sb.append(String.format("  ★ CRITICAL : %d\n", critical));
    sb.append(String.format("  ▲ HIGH     : %d\n", high));
    sb.append(String.format("  ◆ MEDIUM   : %d\n", medium));
    sb.append(String.format("  ● LOW      : %d\n", low));
    sb.append("\n");

    sb.append("─".repeat(64)).append("\n");
    sb.append("  ДЕТАЛИ УЯЗВИМОСТЕЙ\n");
    sb.append("─".repeat(64)).append("\n\n");

    for (ComponentVulnerabilityDto comp : result.getFindings()) {
      sb.append("▶ ").append(comp.getComponentName())
          .append(" ").append(nvl(comp.getVersion())).append("\n");

      for (VulnerabilitySummaryDto vuln : comp.getVulnerabilities()) {
        sb.append("  ┌─ CVE: ").append(nvl(vuln.getCveId()))
            .append("  [").append(nvl(vuln.getSeverity())).append("]\n");
        sb.append("  │  Описание: ")
            .append(truncate(nvl(vuln.getDescription()), 80)).append("\n");

        if (vuln.getDependencyPath() != null) {
          sb.append("  │  Путь: ").append(vuln.getDependencyPath()).append("\n");
        }

        RecommendationDto rec = vuln.getRecommendation();
        if (rec != null) {
          sb.append("  │  Действие: ").append(rec.getPrimaryAction().toUpperCase())
              .append("  |  SLA: ").append(rec.getSlaDays()).append(" дн.")
              .append("  |  Трудозатраты: ").append(rec.getEstimatedEffort()).append("\n");
          if (rec.getFixVersion() != null) {
            sb.append("  │  Фикс: обновить до ").append(rec.getFixVersion()).append("\n");
          }
          sb.append("  │  Обоснование: ").append(nvl(rec.getRationale())).append("\n");
          sb.append("  │  Шаги:\n");
          for (String step : rec.getSteps().split("\n")) {
            if (!step.isBlank()) {
              sb.append("  │    ").append(step).append("\n");
            }
          }
        }
        sb.append("  └─\n\n");
      }
    }

    sb.append("─".repeat(64)).append("\n");
    sb.append("  Сформировано SBOM Analyzer · OSV.dev API\n");
    sb.append("─".repeat(64)).append("\n");

    Files.writeString(outputPath, sb.toString(), java.nio.charset.StandardCharsets.UTF_8);
    log.info("TXT отчёт сохранён: {}", outputPath);
  }

  public void exportJson(FullAnalysisResponse result, Path outputPath) throws Exception {
    ObjectMapper mapper = new ObjectMapper()
        .registerModule(new JavaTimeModule())
        .enable(SerializationFeature.INDENT_OUTPUT)
        .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    var report = new java.util.LinkedHashMap<String, Object>();
    report.put("reportVersion", "1.0");
    report.put("generatedAt", LocalDateTime.now().format(DT_FMT));
    report.put("tool", "SBOM Analyzer / OSV.dev API");

    var summary = new java.util.LinkedHashMap<String, Object>();
    summary.put("projectName", result.getProjectName());
    summary.put("sbomFile", result.getSbomName());
    summary.put("analysisId", result.getId());
    summary.put("status", result.getStatus());
    summary.put("totalComponents", result.getTotalComponents());
    summary.put("vulnerableComponents", result.getVulnerableComponents());
    summary.put("criticalCount", countBySeverity(result, "CRITICAL"));
    summary.put("highCount", countBySeverity(result, "HIGH"));
    summary.put("mediumCount", countBySeverity(result, "MEDIUM"));
    summary.put("lowCount", countBySeverity(result, "LOW"));
    report.put("summary", summary);

    var findings = result.getFindings().stream().map(comp -> {
      var compMap = new java.util.LinkedHashMap<String, Object>();
      compMap.put("component", comp.getComponentName());
      compMap.put("version", comp.getVersion());
      compMap.put("purl", comp.getPurl());
      compMap.put("vulnerabilities", comp.getVulnerabilities().stream().map(vuln -> {
        var vMap = new java.util.LinkedHashMap<String, Object>();
        vMap.put("cveId", vuln.getCveId());
        vMap.put("severity", vuln.getSeverity());
        vMap.put("description", vuln.getDescription());
        vMap.put("versionStart", vuln.getVersionStart());
        vMap.put("versionEnd", vuln.getVersionEnd());
        vMap.put("dependencyPath", vuln.getDependencyPath());
        vMap.put("depth", vuln.getDepth());
        vMap.put("isDirect", vuln.isDirect());

        RecommendationDto rec = vuln.getRecommendation();
        if (rec != null) {
          var recMap = new java.util.LinkedHashMap<String, Object>();
          recMap.put("priority", rec.getPriority());
          recMap.put("primaryAction", rec.getPrimaryAction());
          recMap.put("fixVersion", rec.getFixVersion());
          recMap.put("slaDays", rec.getSlaDays());
          recMap.put("estimatedEffort", rec.getEstimatedEffort());
          recMap.put("rationale", rec.getRationale());
          recMap.put("steps", rec.getSteps());
          vMap.put("recommendation", recMap);
        }
        return vMap;
      }).toList());
      return compMap;
    }).toList();

    report.put("findings", findings);

    mapper.writeValue(outputPath.toFile(), report);
    log.info("JSON отчёт сохранён: {}", outputPath);
  }

  public void exportHtml(FullAnalysisResponse result, Path outputPath) throws Exception {
    long critical = countBySeverity(result, "CRITICAL");
    long high = countBySeverity(result, "HIGH");
    long medium = countBySeverity(result, "MEDIUM");
    long low = countBySeverity(result, "LOW");

    StringBuilder sb = new StringBuilder();
    sb.append("""
        <!DOCTYPE html>
        <html lang="ru">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SBOM Security Report</title>
        <style>
          *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
          body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a;
                 color: #e2e8f0; line-height: 1.6; }
          .container { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }
          /* Header */
          .header { background: #1e293b; border-radius: 12px; padding: 28px 32px;
                    margin-bottom: 24px; border-left: 4px solid #4f46e5; }
          .header h1 { font-size: 24px; color: #e2e8f0; margin-bottom: 4px; }
          .header .sub { color: #64748b; font-size: 13px; }
          .meta { display: flex; gap: 32px; margin-top: 16px; flex-wrap: wrap; }
          .meta-item { display: flex; flex-direction: column; gap: 2px; }
          .meta-item .label { font-size: 11px; color: #475569; text-transform: uppercase; }
          .meta-item .value { font-size: 14px; color: #cbd5e1; font-weight: 600; }
          /* Stats */
          .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                   gap: 12px; margin-bottom: 24px; }
          .stat-card { background: #1e293b; border-radius: 10px; padding: 16px 20px;
                       border: 1px solid #334155; }
          .stat-card .label { font-size: 11px; color: #64748b; margin-bottom: 6px; }
          .stat-card .value { font-size: 28px; font-weight: 700; }
          .v-critical { color: #fca5a5; } .v-high { color: #fdba74; }
          .v-medium   { color: #fcd34d; } .v-low  { color: #86efac; }
          .v-safe     { color: #4ade80; } .v-total { color: #e2e8f0; }
          .v-vuln     { color: #f87171; }
          /* Badge */
          .badge { display: inline-block; padding: 2px 10px; border-radius: 4px;
                   font-size: 11px; font-weight: 700; border: 1px solid; }
          .badge-CRITICAL { background:#450a0a; color:#fca5a5; border-color:#7f1d1d; }
          .badge-HIGH     { background:#431407; color:#fdba74; border-color:#92400e; }
          .badge-MEDIUM   { background:#422006; color:#fcd34d; border-color:#78350f; }
          .badge-LOW      { background:#052e16; color:#86efac; border-color:#14532d; }
          .badge-upgrade  { background:#1e1b4b; color:#a5b4fc; border-color:#4338ca; }
          .badge-mitigate { background:#1c1917; color:#d6d3d1; border-color:#57534e; }
          .badge-isolate  { background:#2d1b69; color:#c4b5fd; border-color:#7c3aed; }
          .badge-monitor  { background:#0c1a2e; color:#7dd3fc; border-color:#0369a1; }
          /* Table */
          table { width: 100%; border-collapse: collapse; background: #1e293b;
                  border-radius: 10px; overflow: hidden; margin-bottom: 24px; }
          th { background: #334155; padding: 12px 14px; text-align: left;
               font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: .05em; }
          td { padding: 11px 14px; border-bottom: 1px solid #0f172a; font-size: 13px;
               vertical-align: top; }
          tr:last-child td { border-bottom: none; }
          tr:hover td { background: #1a2a44; }
          /* Component card */
          .comp-card { background: #1e293b; border-radius: 10px; margin-bottom: 16px;
                       border: 1px solid #334155; overflow: hidden; }
          .comp-header { background: #334155; padding: 12px 18px; display: flex;
                         align-items: center; gap: 12px; }
          .comp-name { font-weight: 700; font-size: 15px; }
          .comp-version { color: #64748b; font-size: 13px; }
          /* Vuln row */
          .vuln-item { padding: 14px 18px; border-bottom: 1px solid #0f172a; }
          .vuln-item:last-child { border-bottom: none; }
          .vuln-header { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
          .cve-id { font-weight: 700; font-size: 14px; color: #cbd5e1; }
          .vuln-desc { color: #94a3b8; font-size: 13px; margin-bottom: 10px; }
          .rec-box { background: #0f172a; border-radius: 8px; padding: 12px 14px;
                     border-left: 3px solid #4f46e5; }
          .rec-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px,1fr));
                      gap: 10px; margin-bottom: 10px; }
          .rec-card { background: #1e293b; border-radius: 6px; padding: 8px 10px;
                      border: 1px solid #334155; }
          .rec-card .rlabel { font-size: 10px; color: #475569; }
          .rec-card .rvalue { font-size: 13px; font-weight: 700; color: #e2e8f0; }
          .steps { margin-top: 10px; }
          .step  { display: flex; gap: 10px; padding: 6px 0;
                   border-bottom: 1px solid #1e293b; font-size: 13px; }
          .step:last-child { border-bottom: none; }
          .step-num { color: #4f46e5; font-weight: 700; min-width: 20px; }
          /* Path */
          .path-chip { display: inline-block; background: #0f172a; border: 1px solid #334155;
                       border-radius: 20px; padding: 2px 10px; font-size: 11px;
                       color: #64748b; margin-top: 4px; }
          /* Footer */
          .footer { text-align: center; color: #334155; font-size: 12px; margin-top: 40px; }
        </style>
        </head>
        <body>
        <div class="container">
        """);

    sb.append("<div class='header'>")
        .append("<h1>🔒 SBOM Security Report</h1>")
        .append("<div class='sub'>Анализ уязвимостей программных зависимостей</div>")
        .append("<div class='meta'>")
        .append(metaItem("Проект", result.getProjectName()))
        .append(metaItem("SBOM-файл", result.getSbomName()))
        .append(metaItem("Дата", LocalDateTime.now().format(DT_FMT)))
        .append(metaItem("Статус", result.getStatus()))
        .append("</div></div>\n");

    sb.append("<div class='stats'>")
        .append(statCard("Компонентов", result.getTotalComponents(), "v-total"))
        .append(statCard("Уязвимых", result.getVulnerableComponents(), "v-vuln"))
        .append(statCard("★ Critical", critical, "v-critical"))
        .append(statCard("▲ High", high, "v-high"))
        .append(statCard("◆ Medium", medium, "v-medium"))
        .append(statCard("● Low", low, "v-low"))
        .append(
            statCard("✓ Безопасных", result.getTotalComponents() - result.getVulnerableComponents(),
                "v-safe"))
        .append("</div>\n");

    sb.append("<h2 style='margin:24px 0 12px;font-size:16px;color:#94a3b8;'>Сводная таблица</h2>")
        .append("<table><thead><tr>")
        .append("<th>Компонент</th><th>Версия</th><th>CVE</th>")
        .append("<th>Severity</th><th>Действие</th><th>SLA</th><th>Путь</th>")
        .append("</tr></thead><tbody>\n");

    for (ComponentVulnerabilityDto comp : result.getFindings()) {
      for (VulnerabilitySummaryDto vuln : comp.getVulnerabilities()) {
        RecommendationDto rec = vuln.getRecommendation();
        String sev = nvl(vuln.getSeverity());
        String action = rec != null ? rec.getPrimaryAction() : "—";
        String sla = rec != null ? rec.getSlaDays() + " д." : "—";
        String path = vuln.getDependencyPath() != null
            ? vuln.getDependencyPath() : "—";

        sb.append("<tr>")
            .append(td(esc(comp.getComponentName())))
            .append(td(esc(nvl(comp.getVersion()))))
            .append(td("<code style='font-size:12px;'>" + esc(nvl(vuln.getCveId())) + "</code>"))
            .append(td("<span class='badge badge-" + sev + "'>" + sev + "</span>"))
            .append(td("<span class='badge badge-" + action + "'>" + action + "</span>"))
            .append(td(sla))
            .append(td("<span style='font-size:11px;color:#475569;'>"
                + esc(truncate(path, 60)) + "</span>"))
            .append("</tr>\n");
      }
    }
    sb.append("</tbody></table>\n");

    sb.append(
        "<h2 style='margin:24px 0 12px;font-size:16px;color:#94a3b8;'>Детальные рекомендации</h2>\n");

    for (ComponentVulnerabilityDto comp : result.getFindings()) {
      sb.append("<div class='comp-card'>")
          .append("<div class='comp-header'>")
          .append("<span class='comp-name'>").append(esc(comp.getComponentName())).append("</span>")
          .append("<span class='comp-version'>").append(esc(nvl(comp.getVersion())))
          .append("</span>")
          .append("</div>\n");

      for (VulnerabilitySummaryDto vuln : comp.getVulnerabilities()) {
        RecommendationDto rec = vuln.getRecommendation();
        String sev = nvl(vuln.getSeverity());

        sb.append("<div class='vuln-item'>")
            .append("<div class='vuln-header'>")
            .append("<span class='cve-id'>").append(esc(nvl(vuln.getCveId()))).append("</span>")
            .append("<span class='badge badge-").append(sev).append("'>").append(sev)
            .append("</span>")
            .append("</div>")
            .append("<div class='vuln-desc'>")
            .append(esc(truncate(nvl(vuln.getDescription()), 200))).append("</div>");

        if (vuln.getDependencyPath() != null) {
          sb.append("<span class='path-chip'>🔗 ").append(esc(vuln.getDependencyPath()))
              .append("</span>");
        }

        if (rec != null) {
          sb.append("<div class='rec-box' style='margin-top:10px;'>")
              .append("<div class='rec-grid'>")
              .append(recCard("Приоритет", rec.getPriority()))
              .append(recCard("Действие", rec.getPrimaryAction().toUpperCase()))
              .append(recCard("Трудозатраты", rec.getEstimatedEffort()))
              .append(recCard("SLA", rec.getSlaDays() + " дней"));
          if (rec.getFixVersion() != null) {
            sb.append(recCard("Целевая версия", rec.getFixVersion()));
          }
          sb.append("</div>");

          if (rec.getRationale() != null) {
            sb.append("<div style='font-size:12px;color:#64748b;margin-bottom:8px;'>")
                .append("⚖ ").append(esc(rec.getRationale())).append("</div>");
          }

          if (rec.getSteps() != null) {
            sb.append("<div class='steps'>");
            for (String line : rec.getSteps().split("\n")) {
              if (line.isBlank()) {
                continue;
              }
              boolean numbered = line.matches("^\\d+\\..*");
              String num = numbered ? line.substring(0, line.indexOf('.') + 1) : "•";
              String text = numbered ? line.substring(line.indexOf('.') + 1).trim() : line;
              sb.append("<div class='step'>")
                  .append("<span class='step-num'>").append(num).append("</span>")
                  .append("<span>").append(esc(text)).append("</span>")
                  .append("</div>");
            }
            sb.append("</div>");
          }

          sb.append("</div>"); // rec-box
        }
        sb.append("</div>\n"); // vuln-item
      }
      sb.append("</div>\n"); // comp-card
    }

    sb.append(
            "<div class='footer'>Сформировано SBOM Analyzer &nbsp;·&nbsp; OSV.dev API &nbsp;·&nbsp; ")
        .append(LocalDateTime.now().format(DT_FMT))
        .append("</div></div></body></html>\n");

    Files.writeString(outputPath, sb.toString(), java.nio.charset.StandardCharsets.UTF_8);
    log.info("HTML отчёт сохранён: {}", outputPath);
  }

  private String metaItem(String label, String value) {
    return "<div class='meta-item'><span class='label'>" + esc(label) + "</span>"
        + "<span class='value'>" + esc(nvl(value)) + "</span></div>";
  }

  private String statCard(String label, long value, String colorClass) {
    return "<div class='stat-card'><div class='label'>" + label + "</div>"
        + "<div class='value " + colorClass + "'>" + value + "</div></div>";
  }

  private String recCard(String label, String value) {
    return "<div class='rec-card'><div class='rlabel'>" + esc(label) + "</div>"
        + "<div class='rvalue'>" + esc(nvl(value)) + "</div></div>";
  }

  private String td(String content) {
    return "<td>" + content + "</td>";
  }

  private String esc(String s) {
    if (s == null) {
      return "—";
    }
    return s.replace("&", "&amp;").replace("<", "&lt;")
        .replace(">", "&gt;").replace("\"", "&quot;");
  }

  private long countBySeverity(FullAnalysisResponse result, String severity) {
    return result.getFindings().stream()
        .flatMap(f -> f.getVulnerabilities().stream())
        .filter(v -> severity.equalsIgnoreCase(v.getSeverity()))
        .count();
  }

  private String truncate(String s, int max) {
    if (s == null) {
      return "—";
    }
    return s.length() > max ? s.substring(0, max - 1) + "…" : s;
  }

  private String nvl(String s) {
    return s != null ? s : "—";
  }

  private String nvl(Object o) {
    return o != null ? o.toString() : "—";
  }
}