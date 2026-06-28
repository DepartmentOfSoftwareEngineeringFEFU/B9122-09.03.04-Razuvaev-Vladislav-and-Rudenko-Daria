package analys.sbom.core.service;

import analys.sbom.core.dto.GraphNode;
import lombok.extern.slf4j.Slf4j;
import org.cyclonedx.model.Bom;
import org.jgrapht.Graph;
import org.jgrapht.alg.shortestpath.DijkstraShortestPath;
import org.jgrapht.graph.DefaultDirectedGraph;
import org.jgrapht.graph.DefaultEdge;
import org.springframework.stereotype.Service;

import java.util.*;

@Slf4j
@Service
public class DependencyGraphService {

  public Graph<String, DefaultEdge> buildGraph(Bom bom) {
    Graph<String, DefaultEdge> graph = new DefaultDirectedGraph<>(DefaultEdge.class);

    if (bom.getComponents() != null) {
      bom.getComponents().forEach(c -> {
        if (c.getBomRef() != null) {
          graph.addVertex(c.getBomRef());
        }
      });
    }

    if (bom.getDependencies() != null) {
      bom.getDependencies().forEach(dep -> {
        String src = dep.getRef();
        if (src == null) {
          return;
        }
        if (!graph.containsVertex(src)) {
          graph.addVertex(src);
        }

        if (dep.getDependencies() != null) {
          dep.getDependencies().forEach(child -> {
            String dst = child.getRef();
            if (dst == null) {
              return;
            }
            if (!graph.containsVertex(dst)) {
              graph.addVertex(dst);
            }
            if (!src.equals(dst)) {
              try {
                graph.addEdge(src, dst);
              } catch (Exception ignored) {
              } // игнорируем дублирующие рёбра
            }
          });
        }
      });
    }

    return graph;
  }

  public Map<String, GraphNode> buildGraphNodes(
      Bom bom,
      Set<String> vulnerableRefs,
      Map<String, String> vulnSeverity,
      Map<String, Set<String>> vulnCves) {

    Map<String, String> displayNames = new HashMap<>();
    if (bom.getComponents() != null) {
      bom.getComponents().forEach(c -> {
        if (c.getBomRef() != null) {
          String ver = c.getVersion() != null ? " " + c.getVersion() : "";
          displayNames.put(c.getBomRef(), c.getName() + ver);
        }
      });
    }

    Map<String, List<String>> childrenMap = new HashMap<>();
    if (bom.getDependencies() != null) {
      bom.getDependencies().forEach(dep -> {
        if (dep.getRef() == null) {
          return;
        }
        List<String> children = childrenMap.computeIfAbsent(dep.getRef(), k -> new ArrayList<>());
        if (dep.getDependencies() != null) {
          dep.getDependencies().forEach(child -> {
            if (child.getRef() != null) {
              children.add(child.getRef());
            }
          });
        }
      });
    }

    Set<String> allRefs = new HashSet<>(displayNames.keySet());
    Set<String> referenced = new HashSet<>();
    childrenMap.values().forEach(referenced::addAll);
    Set<String> roots = new HashSet<>(allRefs);
    roots.removeAll(referenced);
    if (roots.isEmpty()) {
      roots.addAll(allRefs); // все независимы
    }

    Map<String, Integer> depthMap = new HashMap<>();
    Queue<String> queue = new LinkedList<>(roots);
    roots.forEach(r -> depthMap.put(r, 0));

    while (!queue.isEmpty()) {
      String current = queue.poll();
      int d = depthMap.getOrDefault(current, 0);
      List<String> children = childrenMap.getOrDefault(current, List.of());
      for (String child : children) {
        if (!depthMap.containsKey(child)) {
          depthMap.put(child, d + 1);
          queue.add(child);
        }
      }
    }

    Set<String> directRefs = new HashSet<>();
    roots.forEach(r -> directRefs.addAll(
        childrenMap.getOrDefault(r, List.of())));

    Map<String, GraphNode> result = new LinkedHashMap<>();
    for (String ref : allRefs) {
      boolean isVulnerable = vulnerableRefs.contains(ref);
      result.put(ref, GraphNode.builder()
          .bomRef(ref)
          .displayName(displayNames.getOrDefault(ref, ref))
          .depth(depthMap.getOrDefault(ref, 0))
          .isDirect(directRefs.contains(ref))
          .vulnerable(isVulnerable)
          .maxSeverity(isVulnerable ? vulnSeverity.getOrDefault(ref, "UNKNOWN") : null)
          .vulnerableCves(isVulnerable ? vulnCves.getOrDefault(ref, Set.of()) : Set.of())
          .childRefs(childrenMap.getOrDefault(ref, List.of()))
          .build());
    }

    return result;
  }

  public String findPath(
      Graph<String, DefaultEdge> graph,
      String target,
      Map<String, String> displayNames) {

    String root = graph.vertexSet().stream()
        .filter(v -> graph.inDegreeOf(v) == 0)
        .findFirst()
        .orElse(null);

    if (root == null || root.equals(target)) {
      return displayNames.getOrDefault(target, target);
    }

    try {
      var path = DijkstraShortestPath.findPathBetween(graph, root, target);
      if (path == null) {
        return displayNames.getOrDefault(target, target);
      }

      List<String> labels = new ArrayList<>();
      for (String v : path.getVertexList()) {
        labels.add(displayNames.getOrDefault(v, v));
      }
      return String.join(" → ", labels);

    } catch (Exception e) {
      log.debug("Не удалось найти путь до {}: {}", target, e.getMessage());
      return displayNames.getOrDefault(target, target);
    }
  }

  public Set<String> findRoots(Graph<String, DefaultEdge> graph) {
    Set<String> roots = new HashSet<>();
    graph.vertexSet().forEach(v -> {
      if (graph.inDegreeOf(v) == 0) {
        roots.add(v);
      }
    });
    return roots.isEmpty() ? graph.vertexSet() : roots;
  }

  public int computeDepth(Graph<String, DefaultEdge> graph, String target) {
    Set<String> roots = findRoots(graph);
    if (roots.contains(target)) {
      return 0;
    }

    Map<String, Integer> depthMap = new HashMap<>();
    Queue<String> queue = new LinkedList<>(roots);
    roots.forEach(r -> depthMap.put(r, 0));

    while (!queue.isEmpty()) {
      String curr = queue.poll();
      int d = depthMap.get(curr);
      for (DefaultEdge e : graph.outgoingEdgesOf(curr)) {
        String next = graph.getEdgeTarget(e);
        if (!depthMap.containsKey(next)) {
          depthMap.put(next, d + 1);
          queue.add(next);
          if (next.equals(target)) {
            return d + 1;
          }
        }
      }
    }

    return depthMap.getOrDefault(target, -1);
  }
}