package analys.sbom.core.service;

import analys.sbom.core.dto.RecommendationDto;
import analys.sbom.core.entity.VulnerabilityEntity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class RecommendationService {

  private static final double W_CVSS = 0.40;
  private static final double W_EXPLOIT = 0.25;
  private static final double W_DIRECT = 0.20;
  private static final double W_DEPTH = 0.15;

  public RecommendationDto buildRecommendation(
      VulnerabilityEntity vuln,
      int depth,
      boolean isDirect) {

    double cvssScore = estimateCvssScore(vuln.getSeverity());
    boolean hasExploit = false;

    double depthFactor = depth == 0 ? 1.0 : 1.0 / depth;
    double priorityScore = W_CVSS * (cvssScore / 10.0)
        + W_EXPLOIT * (hasExploit ? 1.0 : 0.0)
        + W_DIRECT * (isDirect ? 1.0 : 0.0)
        + W_DEPTH * depthFactor;

    String priority = scoreToPriority(cvssScore, hasExploit, priorityScore);

    boolean hasFix = vuln.getVersionEnd() != null && !vuln.getVersionEnd().isBlank();
    String action = selectAction(cvssScore, hasFix, isDirect, hasExploit);

    String steps = buildSteps(vuln, action, hasFix);
    String effort = estimateEffort(action, vuln.getVersionStart(), vuln.getVersionEnd());
    int sla = slaForPriority(priority);
    String rationale = buildRationale(cvssScore, isDirect, depth, hasFix, hasExploit);

    return RecommendationDto.builder()
        .cveId(vuln.getCveId())
        .priority(priority)
        .primaryAction(action)
        .steps(steps)
        .estimatedEffort(effort)
        .slaDays(sla)
        .rationale(rationale)
        .fixVersion(vuln.getVersionEnd())
        .build();
  }

  private double estimateCvssScore(String severity) {
    if (severity == null) {
      return 5.0;
    }
    return switch (severity.toUpperCase()) {
      case "CRITICAL" -> 9.5;
      case "HIGH" -> 8.0;
      case "MEDIUM" -> 5.5;
      case "LOW" -> 2.5;
      default -> 5.0;
    };
  }

  private String scoreToPriority(double cvss, boolean exploit, double score) {
    if (cvss >= 9.0 || (cvss >= 7.0 && exploit)) {
      return "CRITICAL";
    }
    if (cvss >= 7.0) {
      return "HIGH";
    }
    if (cvss >= 4.0) {
      return "MEDIUM";
    }
    return "LOW";
  }

  private String selectAction(double cvss, boolean hasFix, boolean isDirect, boolean exploit) {
    if (cvss >= 9.0 && exploit) {
      return "isolate";
    }
    if (cvss >= 7.0 && hasFix && isDirect) {
      return "upgrade";
    }
    if (cvss >= 7.0 && hasFix) {
      return "upgrade";
    }
    if (cvss >= 7.0) {
      return "mitigate";
    }
    if (cvss >= 4.0 && hasFix) {
      return "upgrade";
    }
    if (cvss >= 4.0) {
      return "mitigate";
    }
    if (hasFix) {
      return "upgrade";
    }
    return "monitor";
  }

  private String buildSteps(VulnerabilityEntity vuln, String action, boolean hasFix) {
    String pkg = vuln.getPackageName();
    String fix = vuln.getVersionEnd();

    return switch (action) {
      case "upgrade" -> String.format(
          "1. Обновите %s до версии %s или выше.\n" +
              "2. Запустите тесты после обновления.\n" +
              "3. Убедитесь в отсутствии breaking changes в changelog.\n" +
              "4. Зафиксируйте изменение в SBOM.",
          pkg, fix != null ? fix : "последней стабильной");

      case "mitigate" -> String.format(
          "1. Исправление для %s (%s) недоступно.\n" +
              "2. Примените workaround согласно advisory %s.\n" +
              "3. Ограничьте использование уязвимой функциональности.\n" +
              "4. Отслеживайте появление патча в репозитории.",
          pkg, vuln.getCveId(), vuln.getCveId());

      case "replace" -> String.format(
          "1. Найдите альтернативную библиотеку для замены %s.\n" +
              "2. Оцените трудозатраты на миграцию.\n" +
              "3. Реализуйте замену в отдельной ветке.\n" +
              "4. Обновите SBOM после замены компонента.",
          pkg);

      case "isolate" -> String.format(
          "1. КРИТИЧНО: немедленно изолируйте компонент %s (%s).\n" +
              "2. Отключите или ограничьте доступ к уязвимому функционалу.\n" +
              "3. Примените аварийный патч: обновитесь до %s.\n" +
              "4. Уведомьте команду безопасности.",
          pkg, vuln.getCveId(), fix != null ? fix : "последней версии");

      default -> String.format(
          "1. Отслеживайте обновления для %s.\n" +
              "2. Добавьте в план технического долга.\n" +
              "3. Проверяйте появление патча еженедельно.",
          pkg);
    };
  }

  private String estimateEffort(String action, String versionStart, String versionEnd) {
    return switch (action) {
      case "isolate" -> "HIGH";
      case "replace" -> "HIGH";
      case "mitigate" -> "MEDIUM";
      case "upgrade" -> isMajorUpgrade(versionStart, versionEnd) ? "HIGH" : "LOW";
      default -> "LOW";
    };
  }

  private boolean isMajorUpgrade(String from, String to) {
    if (from == null || to == null) {
      return false;
    }
    try {
      int majorFrom = Integer.parseInt(from.split("\\.")[0]);
      int majorTo = Integer.parseInt(to.split("\\.")[0]);
      return majorTo > majorFrom;
    } catch (Exception e) {
      return false;
    }
  }

  private int slaForPriority(String priority) {
    return switch (priority) {
      case "CRITICAL" -> 1;
      case "HIGH" -> 7;
      case "MEDIUM" -> 30;
      default -> 90;
    };
  }

  private String buildRationale(double cvss, boolean isDirect,
      int depth, boolean hasFix, boolean exploit) {
    StringBuilder sb = new StringBuilder();
    sb.append(String.format("CVSS: %.1f", cvss));
    sb.append(isDirect
        ? ", прямая зависимость"
        : String.format(", транзитивная зависимость (глубина %d)", depth));
    if (exploit) {
      sb.append(", известный эксплойт");
    }
    sb.append(hasFix ? ", патч доступен" : ", патч отсутствует");
    return sb.toString();
  }
}