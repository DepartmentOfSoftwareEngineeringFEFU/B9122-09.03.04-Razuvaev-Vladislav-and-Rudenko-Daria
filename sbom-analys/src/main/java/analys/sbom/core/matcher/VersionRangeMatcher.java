package analys.sbom.core.matcher;

import lombok.experimental.UtilityClass;
import org.apache.maven.artifact.versioning.ComparableVersion;

@UtilityClass
public class VersionRangeMatcher {

  public boolean isAffected(
      String version,
      String startInclusive,
      String endExclusive) {

    if (version == null) {
      return false;
    }

    ComparableVersion current = new ComparableVersion(version);

    if (startInclusive != null) {
      ComparableVersion start = new ComparableVersion(startInclusive);
      if (current.compareTo(start) < 0) {
        return false;
      }
    }

    if (endExclusive != null) {
      ComparableVersion end = new ComparableVersion(endExclusive);
      if (current.compareTo(end) >= 0) {
        return false;
      }
    }

    return true;
  }
}