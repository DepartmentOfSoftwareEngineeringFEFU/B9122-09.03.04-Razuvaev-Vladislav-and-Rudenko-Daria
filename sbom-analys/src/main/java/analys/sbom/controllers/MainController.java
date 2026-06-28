package analys.sbom.controllers;

import analys.sbom.core.dto.*;
import analys.sbom.core.service.AnalysisService;
import analys.sbom.core.service.DependencyGraphService;
import analys.sbom.core.service.ReportExportService;
import analys.sbom.core.service.SbomParserService;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.geometry.Pos;
import javafx.geometry.VPos;
import javafx.scene.Scene;
import javafx.scene.canvas.Canvas;
import javafx.scene.canvas.GraphicsContext;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.scene.text.TextAlignment;
import javafx.stage.*;
import org.cyclonedx.model.Bom;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.stereotype.Controller;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

@Controller
public class MainController {

  @FXML
  private TextField filePathField;
  @FXML
  private Label statusLabel;
  @FXML
  private Label statTotal, statVulnerable, statCriticalHigh, statMediumLow, statSafe, statProject;
  @FXML
  private Label vulnCountLabel;
  @FXML
  private Label formatLabel;

  @FXML
  private TableView<Row> vulnerabilitiesTable;
  @FXML
  private TableColumn<Row, String> componentColumn, versionColumn, vulnColumn;
  @FXML
  private TableColumn<Row, String> severityColumn, recommendColumn, descriptionColumn, pathColumn;

  @Autowired
  private AnalysisService analysisService;
  @Autowired
  private SbomParserService parserService;
  @Autowired
  private DependencyGraphService graphService;
  @Autowired
  private ReportExportService exportService;

  private File selectedFile;
  private SbomFormat selectedFormat = SbomFormat.CYCLONEDX_JSON;
  private FullAnalysisResponse lastResult;
  private Bom lastBom;

  private static final Color BG_BASE = Color.web("#0f172a"), BG_NODE = Color.web("#1e293b"),
      BG_ROOT = Color.web("#1e1b4b"), BORDER_DEF = Color.web("#334155"), BORDER_ROOT = Color.web(
      "#4338ca"),
      C_CRITICAL = Color.web("#fca5a5"), C_HIGH = Color.web("#fdba74"),
      C_MEDIUM = Color.web("#fcd34d"), C_LOW = Color.web("#86efac"),
      C_TEXT = Color.web("#e2e8f0"), C_MUTED = Color.web("#64748b"),
      BG_CRITICAL = Color.web("#450a0a"), BG_HIGH = Color.web("#431407"),
      BG_MEDIUM = Color.web("#422006"), BG_LOW = Color.web("#052e16");
  private static final double NODE_W = 180, NODE_H = 48, H_GAP = 38, V_GAP = 80, PAD_TOP = 50, PAD_LEFT = 50;

  @FXML
  public void initialize() {
    componentColumn.setCellValueFactory(c -> c.getValue().componentProperty());
    versionColumn.setCellValueFactory(c -> c.getValue().versionProperty());
    vulnColumn.setCellValueFactory(c -> c.getValue().vulnProperty());
    severityColumn.setCellValueFactory(c -> c.getValue().severityProperty());
    recommendColumn.setCellValueFactory(c -> c.getValue().recommendProperty());
    descriptionColumn.setCellValueFactory(c -> c.getValue().descriptionProperty());
    if (pathColumn != null) {
      pathColumn.setCellValueFactory(c -> c.getValue().pathProperty());
    }

    severityColumn.setCellFactory(col -> new TableCell<>() {
      @Override
      protected void updateItem(String item, boolean empty) {
        super.updateItem(item, empty);
        if (empty || item == null) {
          setGraphic(null);
          setText(null);
          return;
        }
        Label b = new Label(item);
        b.setStyle(severityBadgeStyle(item));
        setGraphic(b);
        setText(null);
      }
    });
    recommendColumn.setCellFactory(col -> new TableCell<>() {
      @Override
      protected void updateItem(String item, boolean empty) {
        super.updateItem(item, empty);
        if (empty || item == null || item.isBlank()) {
          setGraphic(null);
          setText(null);
          return;
        }
        Button btn = new Button(item);
        btn.setStyle(actionBtnStyle(item));
        btn.setCursor(javafx.scene.Cursor.HAND);
        btn.setOnAction(e -> {
          Row row = getTableView().getItems().get(getIndex());
          if (row != null) {
            openRecommendationModal(row);
          }
        });
        setGraphic(btn);
        setText(null);
      }
    });
    vulnerabilitiesTable.setRowFactory(tv -> {
      TableRow<Row> row = new TableRow<>();
      row.setOnMouseClicked(e -> {
        if (e.getClickCount() == 2 && !row.isEmpty()) {
          openRecommendationModal(row.getItem());
        }
      });
      return row;
    });
  }

  @FXML
  private void chooseFile() {
    Stage dlg = new Stage();
    dlg.initModality(Modality.APPLICATION_MODAL);
    dlg.initOwner(filePathField.getScene().getWindow());
    dlg.setTitle("Выбор формата SBOM");
    dlg.setResizable(false);

    VBox root = new VBox(0);
    root.setStyle("-fx-background-color:#0f172a;");
    HBox hdr = new HBox();
    hdr.setStyle(
        "-fx-background-color:#16213e;-fx-padding:18 24 18 24;-fx-border-color:transparent transparent #2d3748 transparent;-fx-border-width:0 0 1 0;");
    Label titleLbl = new Label("Выберите формат SBOM-файла");
    titleLbl.setStyle("-fx-font-size:15px;-fx-font-weight:bold;-fx-text-fill:#e2e8f0;");
    hdr.getChildren().add(titleLbl);

    VBox body = new VBox(8);
    body.setStyle("-fx-padding:20 24 20 24;");
    Label hint = new Label(
        "CycloneDX — основной формат (лучшая интеграция с OSV.dev и деревом зависимостей).\nSPDX — стандарт ISO/IEC 5962, фокус на лицензиях и совместимости.");
    hint.setStyle("-fx-text-fill:#64748b;-fx-font-size:12px;-fx-wrap-text:true;");
    hint.setWrapText(true);
    body.getChildren().add(hint);
    body.getChildren().add(new Separator());

    ToggleGroup group = new ToggleGroup();
    record FmtOpt(SbomFormat fmt, String desc, String color) {

    }
    List<FmtOpt> opts = List.of(
        new FmtOpt(SbomFormat.CYCLONEDX_JSON,
            "Рекомендуется · полная поддержка дерева зависимостей и OSV API", "#1e1b4b"),
        new FmtOpt(SbomFormat.CYCLONEDX_XML, "CycloneDX в XML-синтаксисе", "#1e293b"),
        new FmtOpt(SbomFormat.SPDX_JSON, "SPDX JSON (ISO/IEC 5962) · фокус на лицензиях",
            "#052e16"),
        new FmtOpt(SbomFormat.SPDX_XML, "SPDX RDF/XML · совместимость с экосистемой SPDX",
            "#1e293b")
    );
    for (FmtOpt o : opts) {
      VBox box = new VBox(2);
      box.setStyle("-fx-background-color:" + o.color()
          + ";-fx-border-color:#2d3748;-fx-border-width:1;-fx-border-radius:8;-fx-background-radius:8;-fx-padding:12 16 12 16;-fx-cursor:hand;");
      RadioButton rb = new RadioButton(o.fmt().displayName);
      rb.setToggleGroup(group);
      rb.setUserData(o.fmt());
      rb.setStyle("-fx-text-fill:#e2e8f0;-fx-font-size:13px;-fx-font-weight:bold;");
      if (o.fmt() == selectedFormat) {
        rb.setSelected(true);
      }
      Label desc = new Label(o.desc());
      desc.setStyle("-fx-text-fill:#64748b;-fx-font-size:11px;");
      box.getChildren().addAll(rb, desc);
      body.getChildren().add(box);
    }

    HBox footer = new HBox(12);
    footer.setStyle(
        "-fx-background-color:#16213e;-fx-padding:16 24 16 24;-fx-border-color:#2d3748 transparent transparent transparent;-fx-border-width:1 0 0 0;");
    footer.setAlignment(Pos.CENTER_RIGHT);
    Button cancelBtn = new Button("Отмена");
    cancelBtn.setStyle(
        "-fx-background-color:#1e293b;-fx-text-fill:#94a3b8;-fx-border-color:#2d3748;-fx-border-width:1;-fx-border-radius:7;-fx-background-radius:7;-fx-padding:8 18 8 18;-fx-cursor:hand;");
    cancelBtn.setOnAction(e -> dlg.close());
    Button okBtn = new Button("Выбрать файл →");
    okBtn.setStyle(
        "-fx-background-color:#4f46e5;-fx-text-fill:white;-fx-border-radius:7;-fx-background-radius:7;-fx-padding:8 18 8 18;-fx-font-weight:bold;-fx-cursor:hand;");
    okBtn.setOnAction(e -> {
      Toggle sel = group.getSelectedToggle();
      if (sel != null) {
        selectedFormat = (SbomFormat) sel.getUserData();
      }
      dlg.close();
      openFilePicker();
    });
    footer.getChildren().addAll(cancelBtn, okBtn);
    root.getChildren().addAll(hdr, body, footer);
    dlg.setScene(new Scene(root, 450, 500));
    dlg.showAndWait();
  }

  private void openFilePicker() {
    FileChooser fc = new FileChooser();
    fc.setTitle("Выберите SBOM файл (" + selectedFormat.displayName + ")");
    if (selectedFormat.isJson()) {
      fc.getExtensionFilters()
          .addAll(new FileChooser.ExtensionFilter(selectedFormat.displayName, "*.json"),
              new FileChooser.ExtensionFilter("Все файлы", "*.*"));
    } else {
      fc.getExtensionFilters()
          .addAll(new FileChooser.ExtensionFilter(selectedFormat.displayName, "*.xml"),
              new FileChooser.ExtensionFilter("Все файлы", "*.*"));
    }
    selectedFile = fc.showOpenDialog(filePathField.getScene().getWindow());
    if (selectedFile != null) {
      filePathField.setText(selectedFile.getAbsolutePath());
      if (formatLabel != null) {
        formatLabel.setText(selectedFormat.displayName);
      }
      setStatus("Файл выбран: " + selectedFile.getName() + "  [" + selectedFormat.displayName + "]",
          "normal");
    }
  }

  @FXML
  private void analyze() {
    if (selectedFile == null) {
      setStatus("Сначала выберите SBOM файл", "error");
      return;
    }
    setStatus("Анализ запущен... [" + selectedFormat.displayName + "]", "busy");
    try {
      byte[] bytes = Files.readAllBytes(selectedFile.toPath());
      MockMultipartFile mf = new MockMultipartFile("file", selectedFile.getName(),
          selectedFormat.mimeType, bytes);
      lastResult = analysisService.analyze(mf);
      lastBom = parserService.parse(mf, selectedFormat);
      updateStats(lastResult);
      fillTable(lastResult.getFindings());
      setStatus("Анализ завершён ✓  [" + selectedFormat.displayName
          + "]  |  Нажмите на действие для рекомендации или «Граф»", "ok");
    } catch (IOException e) {
      setStatus("Ошибка чтения файла: " + e.getMessage(), "error");
    } catch (Exception e) {
      setStatus("Ошибка: " + e.getMessage(), "error");
      e.printStackTrace();
    }
  }

  private void updateStats(FullAnalysisResponse r) {
    int total = r.getTotalComponents(), vuln = r.getVulnerableComponents();
    long ch = count(r, "CRITICAL", "HIGH"), ml = count(r, "MEDIUM", "LOW");
    statTotal.setText(String.valueOf(total));
    statVulnerable.setText(String.valueOf(vuln));
    statCriticalHigh.setText(String.valueOf(ch));
    statMediumLow.setText(String.valueOf(ml));
    statSafe.setText(String.valueOf(total - vuln));
    statProject.setText(nvl(r.getProjectName()));
  }

  private long count(FullAnalysisResponse r, String... sevs) {
    Set<String> s = Set.of(sevs);
    return r.getFindings().stream().flatMap(f -> f.getVulnerabilities().stream())
        .filter(v -> s.contains(v.getSeverity())).count();
  }

  private void fillTable(List<ComponentVulnerabilityDto> findings) {
    ObservableList<Row> rows = FXCollections.observableArrayList();
    for (ComponentVulnerabilityDto comp : findings) {
      for (VulnerabilitySummaryDto vuln : comp.getVulnerabilities()) {
        String action =
            vuln.getRecommendation() != null ? vuln.getRecommendation().getPrimaryAction() : "";
        rows.add(new Row(comp.getComponentName(), nvl(comp.getVersion()), nvl(vuln.getCveId()),
            nvl(vuln.getSeverity()), action, nvl(vuln.getDescription()),
            nvl(vuln.getDependencyPath()), vuln, comp));
      }
    }
    vulnerabilitiesTable.setItems(rows);
    if (vulnCountLabel != null) {
      vulnCountLabel.setText(rows.size() + " уязвимостей");
    }
  }

  @FXML
  private void exportReport() {
    if (lastResult == null) {
      setStatus("Сначала запустите анализ", "error");
      return;
    }
    Stage dlg = new Stage();
    dlg.initModality(Modality.APPLICATION_MODAL);
    dlg.initOwner(vulnerabilitiesTable.getScene().getWindow());
    dlg.setTitle("Экспорт отчёта");
    dlg.setResizable(false);
    VBox root = new VBox(0);
    root.setStyle("-fx-background-color:#0f172a;");
    HBox hdr = new HBox();
    hdr.setStyle(
        "-fx-background-color:#16213e;-fx-padding:18 24 18 24;-fx-border-color:transparent transparent #2d3748 transparent;-fx-border-width:0 0 1 0;");
    Label t = new Label("Выберите формат отчёта");
    t.setStyle("-fx-font-size:15px;-fx-font-weight:bold;-fx-text-fill:#e2e8f0;");
    hdr.getChildren().add(t);
    VBox body = new VBox(10);
    body.setStyle("-fx-padding:20 24 20 24;");
    record Opt(String fmt, String name, String desc, String bg, String border) {

    }
    List<Opt> opts = List.of(
        new Opt("TXT", "Текстовый отчёт (.txt)", "Быстрый просмотр · читается в любом редакторе",
            "#1e293b", "#334155"),
        new Opt("JSON", "JSON отчёт (.json)", "Машиночитаемый · интеграция с CI/CD пайплайнами",
            "#1e1b4b", "#4338ca"),
        new Opt("HTML", "HTML отчёт (.html)", "Презентация заказчику · открывается в браузере",
            "#052e16", "#14532d")
    );
    for (Opt o : opts) {
      Button btn = new Button();
      btn.setMaxWidth(Double.MAX_VALUE);
      btn.setStyle("-fx-background-color:" + o.bg() + ";-fx-border-color:" + o.border()
          + ";-fx-border-width:1;-fx-border-radius:8;-fx-background-radius:8;-fx-padding:0;-fx-cursor:hand;");
      VBox inner = new VBox(3);
      inner.setStyle("-fx-padding:14 16 14 16;");
      Label ln = new Label("📄 " + o.name());
      ln.setStyle("-fx-font-size:13px;-fx-font-weight:bold;-fx-text-fill:#e2e8f0;");
      Label ld = new Label(o.desc());
      ld.setStyle("-fx-font-size:11px;-fx-text-fill:#64748b;");
      inner.getChildren().addAll(ln, ld);
      btn.setGraphic(inner);
      String fmt = o.fmt();
      btn.setOnAction(e -> {
        dlg.close();
        saveReportAs(fmt);
      });
      body.getChildren().add(btn);
    }
    Button cancelBtn = new Button("Отмена");
    cancelBtn.setStyle(
        "-fx-background-color:transparent;-fx-text-fill:#475569;-fx-border-color:transparent;-fx-cursor:hand;-fx-font-size:12px;");
    cancelBtn.setOnAction(e -> dlg.close());
    HBox cr = new HBox(cancelBtn);
    cr.setAlignment(Pos.CENTER_RIGHT);
    cr.setStyle("-fx-padding:8 24 16 24;");
    root.getChildren().addAll(hdr, body, cr);
    dlg.setScene(new Scene(root, 420, 360));
    dlg.showAndWait();
  }

  private void saveReportAs(String format) {
    FileChooser fc = new FileChooser();
    fc.setTitle("Сохранить отчёт");
    String ext = "." + format.toLowerCase();
    fc.getExtensionFilters().add(new FileChooser.ExtensionFilter(format, "*" + ext));
    fc.setInitialFileName(
        "sbom_report_" + lastResult.getProjectName().replaceAll("[^a-zA-Z0-9]", "_") + ext);
    File file = fc.showSaveDialog(vulnerabilitiesTable.getScene().getWindow());
    if (file == null) {
      return;
    }
    try {
      Path path = file.toPath();
      switch (format) {
        case "TXT" -> exportService.exportTxt(lastResult, path);
        case "JSON" -> exportService.exportJson(lastResult, path);
        case "HTML" -> exportService.exportHtml(lastResult, path);
      }
      setStatus("Отчёт сохранён (" + format + "): " + file.getName(), "ok");
    } catch (Exception e) {
      setStatus("Ошибка экспорта: " + e.getMessage(), "error");
      e.printStackTrace();
    }
  }

  @FXML
  private void openGraph() {
    if (lastResult == null || lastBom == null) {
      setStatus("Сначала запустите анализ", "error");
      return;
    }
    Stage gs = new Stage();
    gs.initModality(Modality.NONE);
    gs.initOwner(vulnerabilitiesTable.getScene().getWindow());
    gs.setTitle("Граф зависимостей · " + lastResult.getProjectName());
    gs.setWidth(1100);
    gs.setHeight(750);
    VBox root = new VBox(0);
    root.setStyle("-fx-background-color:#0f172a;");
    HBox hdr = new HBox(16);
    hdr.setStyle(
        "-fx-background-color:#16213e;-fx-padding:14 20 14 20;-fx-border-color:transparent transparent #2d3748 transparent;-fx-border-width:0 0 1 0;");
    hdr.setAlignment(Pos.CENTER_LEFT);
    Label titleLbl = new Label("Граф зависимостей · " + lastResult.getProjectName());
    titleLbl.setStyle("-fx-font-size:15px;-fx-font-weight:bold;-fx-text-fill:#e2e8f0;");
    Region sp = new Region();
    HBox.setHgrow(sp, Priority.ALWAYS);
    HBox legend = new HBox(14);
    legend.setAlignment(Pos.CENTER);
    legend.getChildren()
        .addAll(li("★ CRITICAL", "#fca5a5"), li("▲ HIGH", "#fdba74"), li("◆ MEDIUM", "#fcd34d"),
            li("● LOW", "#86efac"), li("✓ OK", "#475569"));
    Button expBtn = new Button("Экспорт отчёта");
    expBtn.setStyle(
        "-fx-background-color:#4f46e5;-fx-text-fill:white;-fx-border-radius:7;-fx-background-radius:7;-fx-padding:8 16 8 16;-fx-font-size:12px;-fx-cursor:hand;");
    expBtn.setOnAction(e -> exportReport());
    hdr.getChildren().addAll(titleLbl, sp, legend, expBtn);
    Canvas canvas = new Canvas(1000, 700);
    ScrollPane sp2 = new ScrollPane(canvas);
    sp2.setStyle(
        "-fx-background-color:#0f172a;-fx-background:#0f172a;-fx-border-color:transparent;");
    sp2.setPannable(true);
    VBox.setVgrow(sp2, Priority.ALWAYS);
    Label info = new Label("Нажмите на узел для информации");
    info.setStyle(
        "-fx-background-color:#16213e;-fx-text-fill:#475569;-fx-font-size:12px;-fx-padding:10 20 10 20;-fx-border-color:#2d3748 transparent transparent transparent;-fx-border-width:1 0 0 0;");
    info.setMaxWidth(Double.MAX_VALUE);
    root.getChildren().addAll(hdr, sp2, info);
    gs.setScene(new Scene(root, 1100, 750));
    gs.show();
    Map<String, NodePos> pos = drawGraphOnCanvas(canvas, lastBom, lastResult.getFindings());
    canvas.setOnMouseClicked(evt -> {
      for (NodePos np : pos.values()) {
        if (evt.getX() >= np.x && evt.getX() <= np.x + NODE_W && evt.getY() >= np.y
            && evt.getY() <= np.y + NODE_H) {
          showNodeInfo(np, lastResult.getFindings(), info);
          break;
        }
      }
    });
  }

  private Label li(String text, String color) {
    Label l = new Label(text);
    l.setStyle("-fx-text-fill:" + color + ";-fx-font-size:11px;");
    return l;
  }

  private void showNodeInfo(NodePos np, List<ComponentVulnerabilityDto> findings, Label info) {
    findings.stream().filter(f -> f.getComponentName().equals(np.refToName)).findFirst()
        .ifPresentOrElse(
            comp -> {
              long cnt = comp.getVulnerabilities().size();
              String cves = comp.getVulnerabilities().stream()
                  .map(VulnerabilitySummaryDto::getCveId).filter(Objects::nonNull).limit(3)
                  .reduce((a, b) -> a + "·" + b).orElse("—");
              info.setText(
                  "⚠  " + np.display.replace("\n", " ") + " — " + cnt + " уязвимостей   " + cves);
              info.setStyle(
                  "-fx-background-color:#16213e;-fx-text-fill:#fb923c;-fx-font-size:12px;-fx-padding:10 20 10 20;-fx-border-color:#2d3748 transparent transparent transparent;-fx-border-width:1 0 0 0;");
            },
            () -> {
              info.setText("✓  " + np.display.replace("\n", " ") + " — безопасен");
              info.setStyle(
                  "-fx-background-color:#16213e;-fx-text-fill:#4ade80;-fx-font-size:12px;-fx-padding:10 20 10 20;-fx-border-color:#2d3748 transparent transparent transparent;-fx-border-width:1 0 0 0;");
            });
  }

  private void openRecommendationModal(Row row) {
    VulnerabilitySummaryDto vuln = row.vulnDto;
    RecommendationDto rec = vuln != null ? vuln.getRecommendation() : null;
    Stage modal = new Stage();
    modal.initModality(Modality.APPLICATION_MODAL);
    modal.initOwner(vulnerabilitiesTable.getScene().getWindow());
    modal.setTitle("Рекомендация · " + row.vulnProperty().get());
    modal.setResizable(true);
    VBox root = new VBox(0);
    root.setStyle("-fx-background-color:#0f172a;");
    HBox hdr = new HBox(16);
    hdr.setStyle(
        "-fx-background-color:#16213e;-fx-padding:20 24 20 24;-fx-border-color:transparent transparent #2d3748 transparent;-fx-border-width:0 0 1 0;");
    hdr.setAlignment(Pos.CENTER_LEFT);
    VBox tbox = new VBox(4);
    Label tc = new Label(nvl(row.vulnProperty().get()));
    tc.setStyle("-fx-font-size:18px;-fx-font-weight:bold;-fx-text-fill:#e2e8f0;");
    Label ts = new Label(
        nvl(row.componentProperty().get()) + "  " + nvl(row.versionProperty().get()));
    ts.setStyle("-fx-font-size:13px;-fx-text-fill:#64748b;");
    tbox.getChildren().addAll(tc, ts);
    Region spr = new Region();
    HBox.setHgrow(spr, Priority.ALWAYS);
    Label badge = new Label(nvl(row.severityProperty().get()));
    badge.setStyle(severityBadgeStyle(row.severityProperty().get())
        + "-fx-font-size:14px;-fx-padding:6 16 6 16;");
    hdr.getChildren().addAll(tbox, spr, badge);
    ScrollPane scroll = new ScrollPane();
    scroll.setFitToWidth(true);
    scroll.setStyle(
        "-fx-background-color:#0f172a;-fx-background:#0f172a;-fx-border-color:transparent;");
    VBox body = new VBox(16);
    body.setStyle("-fx-padding:24;");
    body.setPrefWidth(640);
    body.getChildren().add(sec("📋 Описание", nvl(row.descriptionProperty().get())));
    if (vuln != null && vuln.getDependencyPath() != null) {
      body.getChildren().add(sec("🔗 Путь",
          vuln.getDependencyPath() + (vuln.isDirect() ? "\n\n✓ Прямая (глубина " + vuln.getDepth()
                                                        + ")"
              : "\n\n⚠ Транзитивная (глубина " + vuln.getDepth() + ")")));
    }
    if (vuln != null && (vuln.getVersionStart() != null || vuln.getVersionEnd() != null)) {
      body.getChildren().add(sec("📌 Версии",
          "Затронуто: " + (vuln.getVersionStart() != null ? "от " + vuln.getVersionStart() + " "
              : "") + (vuln.getVersionEnd() != null ? "до " + vuln.getVersionEnd() : "(все)")));
    }
    if (rec != null) {
      HBox cards = new HBox(12);
      cards.getChildren().addAll(ic("Приоритет", rec.getPriority(), pcs(rec.getPriority())),
          ic("Действие", rec.getPrimaryAction().toUpperCase(), acs()),
          ic("Трудозатраты", rec.getEstimatedEffort(), ecs(rec.getEstimatedEffort())),
          ic("SLA", rec.getSlaDays() + " дней", scs(rec.getSlaDays())));
      body.getChildren().add(cards);
      if (rec.getRationale() != null) {
        body.getChildren().add(sec("⚖ Обоснование", rec.getRationale()));
      }
      if (rec.getFixVersion() != null) {
        body.getChildren()
            .add(sec("✅ Целевая версия", "Обновите до: " + rec.getFixVersion() + " или выше"));
      }
      if (rec.getSteps() != null) {
        body.getChildren().add(stepsSection(rec.getSteps()));
      }
    }
    scroll.setContent(body);
    VBox.setVgrow(scroll, Priority.ALWAYS);
    HBox footer = new HBox(12);
    footer.setStyle(
        "-fx-background-color:#16213e;-fx-padding:16 24 16 24;-fx-border-color:#2d3748 transparent transparent transparent;-fx-border-width:1 0 0 0;");
    footer.setAlignment(Pos.CENTER_RIGHT);
    Button closeBtn = new Button("Закрыть");
    closeBtn.setStyle(
        "-fx-background-color:#1e293b;-fx-text-fill:#94a3b8;-fx-border-color:#2d3748;-fx-border-width:1;-fx-border-radius:7;-fx-background-radius:7;-fx-padding:9 20 9 20;-fx-font-size:13px;-fx-cursor:hand;");
    closeBtn.setOnAction(e -> modal.close());
    Button savBtn = new Button("Сохранить TXT");
    savBtn.setStyle(
        "-fx-background-color:#4f46e5;-fx-text-fill:white;-fx-border-radius:7;-fx-background-radius:7;-fx-padding:9 16 9 16;-fx-font-size:12px;-fx-cursor:hand;");
    savBtn.setOnAction(e -> {
      FileChooser fc = new FileChooser();
      fc.setTitle("Сохранить");
      fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text", "*.txt"));
      fc.setInitialFileName(row.vulnProperty().get() + "_rec.txt");
      File f = fc.showSaveDialog(modal);
      if (f == null) {
        return;
      }
      try {
        Files.writeString(f.toPath(),
            "CVE: " + row.vulnProperty().get() + "\nКомпонент: " + row.componentProperty().get()
                + " " + row.versionProperty().get() + "\nSeverity: " + row.severityProperty().get()
                + "\n\n" + row.descriptionProperty().get() + (rec != null ? "\n\nПриоритет: "
                                                                            + rec.getPriority()
                                                                            + "\nДействие: "
                                                                            + rec.getPrimaryAction()
                                                                            + "\nSLA: "
                                                                            + rec.getSlaDays()
                                                                            + " дней\n\nШаги:\n"
                                                                            + rec.getSteps() : ""));
        setStatus("Сохранено: " + f.getName(), "ok");
      } catch (IOException ex) {
        setStatus("Ошибка: " + ex.getMessage(), "error");
      }
    });
    footer.getChildren().addAll(savBtn, closeBtn);
    root.getChildren().addAll(hdr, scroll, footer);
    VBox.setVgrow(scroll, Priority.ALWAYS);
    modal.setScene(new Scene(root, 680, 620));
    modal.show();
  }

  private VBox sec(String title, String content) {
    Label lbl = new Label(title);
    lbl.setStyle("-fx-font-size:12px;-fx-font-weight:bold;-fx-text-fill:#64748b;");
    Label txt = new Label(content);
    txt.setStyle("-fx-font-size:13px;-fx-text-fill:#e2e8f0;-fx-wrap-text:true;");
    txt.setWrapText(true);
    txt.setMaxWidth(Double.MAX_VALUE);
    VBox card = new VBox(8);
    card.setStyle(
        "-fx-background-color:#16213e;-fx-border-color:#2d3748;-fx-border-width:1;-fx-border-radius:8;-fx-background-radius:8;-fx-padding:14 16 14 16;");
    card.getChildren().addAll(lbl, txt);
    VBox box = new VBox(8);
    box.getChildren().add(card);
    return box;
  }

  private VBox stepsSection(String stepsText) {
    Label title = new Label("🛠 Пошаговые инструкции");
    title.setStyle("-fx-font-size:12px;-fx-font-weight:bold;-fx-text-fill:#64748b;");
    VBox card = new VBox(0);
    card.setStyle(
        "-fx-background-color:#16213e;-fx-border-color:#4f46e5;-fx-border-width:1;-fx-border-radius:8;-fx-background-radius:8;");
    HBox ch = new HBox();
    ch.setStyle(
        "-fx-background-color:#1e1b4b;-fx-padding:10 16 10 16;-fx-background-radius:8 8 0 0;");
    Label hint = new Label("Выполните по порядку");
    hint.setStyle("-fx-font-size:11px;-fx-text-fill:#a5b4fc;");
    ch.getChildren().add(hint);
    VBox steps = new VBox(10);
    steps.setStyle("-fx-padding:14 16 14 16;");
    for (String line : stepsText.split("\n")) {
      if (line.isBlank()) {
        continue;
      }
      boolean num = line.matches("^\\d+\\..*");
      Label mk = new Label(num ? line.substring(0, line.indexOf('.') + 1) : "•");
      mk.setStyle(
          "-fx-font-size:13px;-fx-font-weight:bold;-fx-text-fill:#4f46e5;-fx-min-width:24;");
      String text = num ? line.substring(line.indexOf('.') + 1).trim() : line;
      Label tx = new Label(text);
      tx.setStyle("-fx-font-size:13px;-fx-text-fill:#e2e8f0;-fx-wrap-text:true;");
      tx.setWrapText(true);
      HBox.setHgrow(tx, Priority.ALWAYS);
      HBox row = new HBox(12);
      row.setAlignment(Pos.TOP_LEFT);
      row.getChildren().addAll(mk, tx);
      steps.getChildren().add(row);
      steps.getChildren().add(new Separator());
    }
    card.getChildren().addAll(ch, steps);
    VBox box = new VBox(8);
    box.getChildren().addAll(title, card);
    return box;
  }

  private VBox ic(String label, String value, String style) {
    VBox card = new VBox(4);
    card.setStyle(style);
    card.setAlignment(Pos.CENTER);
    card.setPrefWidth(140);
    HBox.setHgrow(card, Priority.ALWAYS);
    Label l = new Label(label);
    l.setStyle("-fx-font-size:10px;-fx-text-fill:#64748b;");
    Label v = new Label(nvl(value));
    v.setStyle("-fx-font-size:15px;-fx-font-weight:bold;-fx-text-fill:#e2e8f0;");
    card.getChildren().addAll(l, v);
    return card;
  }

  private String pcs(String p) {
    String bg = switch (p != null ? p : "") {
      case "CRITICAL" -> "#450a0a";
      case "HIGH" -> "#431407";
      case "MEDIUM" -> "#422006";
      case "LOW" -> "#052e16";
      default -> "#1e293b";
    };
    String br = switch (p != null ? p : "") {
      case "CRITICAL" -> "#7f1d1d";
      case "HIGH" -> "#92400e";
      case "MEDIUM" -> "#78350f";
      case "LOW" -> "#14532d";
      default -> "#2d3748";
    };
    return "-fx-background-color:" + bg + ";-fx-border-color:" + br
        + ";-fx-border-width:1;-fx-border-radius:8;-fx-background-radius:8;-fx-padding:14 16 14 16;";
  }

  private String acs() {
    return "-fx-background-color:#1e1b4b;-fx-border-color:#4338ca;-fx-border-width:1;-fx-border-radius:8;-fx-background-radius:8;-fx-padding:14 16 14 16;";
  }

  private String ecs(String e) {
    String bg = switch (e != null ? e : "") {
      case "HIGH" -> "#431407";
      case "MEDIUM" -> "#422006";
      default -> "#1e293b";
    };
    return "-fx-background-color:" + bg
        + ";-fx-border-color:#2d3748;-fx-border-width:1;-fx-border-radius:8;-fx-background-radius:8;-fx-padding:14 16 14 16;";
  }

  private String scs(int d) {
    String bg = d <= 1 ? "#450a0a" : d <= 7 ? "#431407" : d <= 30 ? "#422006" : "#1e293b";
    return "-fx-background-color:" + bg
        + ";-fx-border-color:#2d3748;-fx-border-width:1;-fx-border-radius:8;-fx-background-radius:8;-fx-padding:14 16 14 16;";
  }

  private void setStatus(String t, String s) {
    statusLabel.setText(t);
    statusLabel.setStyle("-fx-font-size:12px;-fx-text-fill:" + switch (s) {
      case "ok" -> "#4ade80";
      case "warn" -> "#fb923c";
      case "error" -> "#f87171";
      case "busy" -> "#818cf8";
      default -> "#64748b";
    } + ";");
  }

  private Color sevColor(String s) {
    if (s == null) {
      return C_MUTED;
    }
    return switch (s.toUpperCase()) {
      case "CRITICAL" -> C_CRITICAL;
      case "HIGH" -> C_HIGH;
      case "MEDIUM" -> C_MEDIUM;
      case "LOW" -> C_LOW;
      default -> C_MUTED;
    };
  }

  private Color nodeBg(String s) {
    if (s == null) {
      return BG_NODE;
    }
    return switch (s.toUpperCase()) {
      case "CRITICAL" -> BG_CRITICAL;
      case "HIGH" -> BG_HIGH;
      case "MEDIUM" -> BG_MEDIUM;
      case "LOW" -> BG_LOW;
      default -> BG_NODE;
    };
  }

  private Color nodeBorder(String s) {
    if (s == null) {
      return BORDER_DEF;
    }
    return switch (s.toUpperCase()) {
      case "CRITICAL" -> Color.web("#7f1d1d");
      case "HIGH" -> Color.web("#92400e");
      case "MEDIUM" -> Color.web("#78350f");
      case "LOW" -> Color.web("#14532d");
      default -> BORDER_DEF;
    };
  }

  private String sevMarkerChar(String s) {
    if (s == null) {
      return "?";
    }
    return switch (s.toUpperCase()) {
      case "CRITICAL" -> "★";
      case "HIGH" -> "▲";
      case "MEDIUM" -> "◆";
      case "LOW" -> "●";
      default -> "?";
    };
  }

  private int sevScore(String s) {
    if (s == null) {
      return 0;
    }
    return switch (s.toUpperCase()) {
      case "CRITICAL" -> 4;
      case "HIGH" -> 3;
      case "MEDIUM" -> 2;
      case "LOW" -> 1;
      default -> 0;
    };
  }

  private String severityBadgeStyle(String s) {
    return switch (s != null ? s.toUpperCase() : "") {
      case "CRITICAL" ->
          "-fx-background-color:#450a0a;-fx-text-fill:#fca5a5;-fx-border-color:#7f1d1d;-fx-border-width:1;-fx-border-radius:4;-fx-background-radius:4;-fx-padding:2 8 2 8;-fx-font-size:11px;-fx-font-weight:bold;";
      case "HIGH" ->
          "-fx-background-color:#431407;-fx-text-fill:#fdba74;-fx-border-color:#92400e;-fx-border-width:1;-fx-border-radius:4;-fx-background-radius:4;-fx-padding:2 8 2 8;-fx-font-size:11px;-fx-font-weight:bold;";
      case "MEDIUM" ->
          "-fx-background-color:#422006;-fx-text-fill:#fcd34d;-fx-border-color:#78350f;-fx-border-width:1;-fx-border-radius:4;-fx-background-radius:4;-fx-padding:2 8 2 8;-fx-font-size:11px;";
      case "LOW" ->
          "-fx-background-color:#052e16;-fx-text-fill:#86efac;-fx-border-color:#14532d;-fx-border-width:1;-fx-border-radius:4;-fx-background-radius:4;-fx-padding:2 8 2 8;-fx-font-size:11px;";
      default ->
          "-fx-background-color:#1e293b;-fx-text-fill:#64748b;-fx-border-color:#2d3748;-fx-border-width:1;-fx-border-radius:4;-fx-background-radius:4;-fx-padding:2 8 2 8;-fx-font-size:11px;";
    };
  }

  private String actionBtnStyle(String a) {
    return switch (a != null ? a.toLowerCase() : "") {
      case "upgrade" ->
          "-fx-background-color:#1e1b4b;-fx-text-fill:#a5b4fc;-fx-border-color:#4338ca;-fx-border-width:1;-fx-border-radius:5;-fx-background-radius:5;-fx-padding:3 10 3 10;-fx-font-size:11px;-fx-cursor:hand;";
      case "isolate" ->
          "-fx-background-color:#2d1b69;-fx-text-fill:#c4b5fd;-fx-border-color:#7c3aed;-fx-border-width:1;-fx-border-radius:5;-fx-background-radius:5;-fx-padding:3 10 3 10;-fx-font-size:11px;-fx-cursor:hand;";
      case "mitigate", "replace" ->
          "-fx-background-color:#1c1917;-fx-text-fill:#d6d3d1;-fx-border-color:#57534e;-fx-border-width:1;-fx-border-radius:5;-fx-background-radius:5;-fx-padding:3 10 3 10;-fx-font-size:11px;-fx-cursor:hand;";
      case "monitor" ->
          "-fx-background-color:#0c1a2e;-fx-text-fill:#7dd3fc;-fx-border-color:#0369a1;-fx-border-width:1;-fx-border-radius:5;-fx-background-radius:5;-fx-padding:3 10 3 10;-fx-font-size:11px;-fx-cursor:hand;";
      default ->
          "-fx-background-color:#1e293b;-fx-text-fill:#64748b;-fx-border-color:#2d3748;-fx-border-width:1;-fx-border-radius:5;-fx-background-radius:5;-fx-padding:3 10 3 10;-fx-font-size:11px;-fx-cursor:hand;";
    };
  }

  private String trunc(String s, int max) {
    if (s == null) {
      return "";
    }
    return s.length() > max ? s.substring(0, max - 1) + "…" : s;
  }

  private String nvl(String s) {
    return s != null ? s : "—";
  }

  private static class NodePos {

    String ref, display, severity, refToName;
    double x, y;
    boolean isRoot, vulnerable;

    NodePos(String r, String d, String s, String n, double x, double y, boolean root, boolean v) {
      ref = r;
      display = d;
      severity = s;
      refToName = n;
      this.x = x;
      this.y = y;
      isRoot = root;
      vulnerable = v;
    }
  }

  private Map<String, NodePos> drawGraphOnCanvas(Canvas canvas, Bom bom,
      List<ComponentVulnerabilityDto> findings) {
    Map<String, String> vbn = new HashMap<>();
    for (ComponentVulnerabilityDto c : findings) {
      c.getVulnerabilities().stream().map(VulnerabilitySummaryDto::getSeverity)
          .max(Comparator.comparingInt(this::sevScore))
          .ifPresent(s -> vbn.put(c.getComponentName(), s));
    }
    Map<String, String> dn = new LinkedHashMap<>(), rtn = new HashMap<>();
    if (bom.getComponents() != null) {
      bom.getComponents().forEach(c -> {
        if (c.getBomRef() == null) {
          return;
        }
        String v = c.getVersion() != null ? "\n" + c.getVersion() : "";
        dn.put(c.getBomRef(), c.getName() + v);
        rtn.put(c.getBomRef(), c.getName());
      });
    }
    if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
      var mc = bom.getMetadata().getComponent();
      if (mc.getBomRef() != null) {
        String v = mc.getVersion() != null ? "\n" + mc.getVersion() : "";
        dn.put(mc.getBomRef(), mc.getName() + v);
        rtn.put(mc.getBomRef(), mc.getName() != null ? mc.getName() : mc.getBomRef());
      }
    }
    Map<String, List<String>> cm = new LinkedHashMap<>();
    if (bom.getDependencies() != null) {
      bom.getDependencies().forEach(dep -> {
        if (dep.getRef() == null) {
          return;
        }
        List<String> ch = cm.computeIfAbsent(dep.getRef(), k -> new ArrayList<>());
        if (dep.getDependencies() != null) {
          dep.getDependencies().forEach(child -> {
            if (child.getRef() != null) {
              ch.add(child.getRef());
            }
          });
        }
      });
    }
    Set<String> ar = new LinkedHashSet<>();
    ar.addAll(dn.keySet());
    ar.addAll(cm.keySet());
    Set<String> ref = new HashSet<>();
    cm.values().forEach(ref::addAll);
    List<String> roots = ar.stream().filter(r -> !ref.contains(r)).toList();
    if (roots.isEmpty() && !ar.isEmpty()) {
      roots = List.of(ar.iterator().next());
    }
    Map<String, Integer> lm = new HashMap<>();
    Queue<String> q = new LinkedList<>(roots);
    roots.forEach(r -> lm.put(r, 0));
    while (!q.isEmpty()) {
      String cur = q.poll();
      int lv = lm.get(cur);
      for (String child : cm.getOrDefault(cur, List.of())) {
        int nl = lv + 1;
        if (!lm.containsKey(child) || lm.get(child) < nl) {
          lm.put(child, nl);
          q.add(child);
        }
      }
    }
    int ml = lm.values().stream().mapToInt(i -> i).max().orElse(0);
    for (String r : ar) {
      if (!lm.containsKey(r)) {
        lm.put(r, ml + 1);
      }
    }
    Map<Integer, List<String>> bl = new TreeMap<>();
    lm.forEach((r, lv) -> bl.computeIfAbsent(lv, k -> new ArrayList<>()).add(r));
    int maxR = bl.values().stream().mapToInt(List::size).max().orElse(1);
    double cW = Math.max(800, maxR * (NODE_W + H_GAP) + PAD_LEFT * 2), cH = Math.max(500,
        bl.size() * (NODE_H + V_GAP) + PAD_TOP + 80);
    canvas.setWidth(cW);
    canvas.setHeight(cH);
    GraphicsContext gc = canvas.getGraphicsContext2D();
    gc.setFill(BG_BASE);
    gc.fillRect(0, 0, cW, cH);
    Map<String, NodePos> pos = new LinkedHashMap<>();
    for (Map.Entry<Integer, List<String>> e : bl.entrySet()) {
      int lvl = e.getKey();
      List<String> refs = e.getValue();
      double rW = refs.size() * NODE_W + (refs.size() - 1) * H_GAP, sX = (cW - rW) / 2.0, y =
          PAD_TOP + lvl * (NODE_H + V_GAP);
      for (int i = 0; i < refs.size(); i++) {
        String r = refs.get(i), n = rtn.getOrDefault(r, r), s = vbn.get(n);
        double x = sX + i * (NODE_W + H_GAP);
        pos.put(r, new NodePos(r, dn.getOrDefault(r, r), s, n, x, y, lvl == 0, s != null));
      }
    }
    for (Map.Entry<String, List<String>> e : cm.entrySet()) {
      NodePos src = pos.get(e.getKey());
      if (src == null) {
        continue;
      }
      for (String cr : e.getValue()) {
        NodePos dst = pos.get(cr);
        if (dst != null) {
          drawArrow(gc, src, dst);
        }
      }
    }
    for (NodePos np : pos.values()) {
      drawNode(gc, np);
    }
    return pos;
  }

  private void drawNode(GraphicsContext gc, NodePos np) {
    double x = np.x, y = np.y, w = NODE_W, h = NODE_H, r = 8;
    Color bg, bo, tx, sub;
    String mk;
    if (np.isRoot) {
      bg = BG_ROOT;
      bo = BORDER_ROOT;
      tx = Color.web("#c7d2fe");
      sub = Color.web("#818cf8");
      mk = "";
    } else if (np.vulnerable) {
      bg = nodeBg(np.severity);
      bo = nodeBorder(np.severity);
      tx = sevColor(np.severity);
      sub = sevColor(np.severity).darker();
      mk = sevMarkerChar(np.severity);
    } else {
      bg = BG_NODE;
      bo = BORDER_DEF;
      tx = C_TEXT;
      sub = Color.web("#4ade80");
      mk = "✓";
    }
    gc.setFill(Color.color(0, 0, 0, .25));
    rr(gc, x + 2, y + 3, w, h, r, true, false);
    gc.setFill(bg);
    rr(gc, x, y, w, h, r, true, false);
    gc.setStroke(bo);
    gc.setLineWidth(1.2);
    rr(gc, x, y, w, h, r, false, true);
    if (np.vulnerable) {
      gc.setFill(bo);
      rr(gc, x, y, 4, h, r, true, false);
    }
    String[] pts = np.display.split("\n", 2);
    gc.setTextAlign(TextAlignment.CENTER);
    gc.setTextBaseline(VPos.CENTER);
    if (pts.length > 1) {
      gc.setFont(Font.font("Segoe UI", FontWeight.BOLD, 12));
      gc.setFill(tx);
      gc.fillText(trunc(pts[0], 22), x + w / 2, y + h / 2 - 8);
      gc.setFont(Font.font("Segoe UI", 10));
      gc.setFill(sub);
      gc.fillText(pts[1], x + w / 2, y + h / 2 + 8);
    } else {
      gc.setFont(Font.font("Segoe UI", FontWeight.BOLD, 12));
      gc.setFill(tx);
      gc.fillText(trunc(pts[0], 24), x + w / 2, y + h / 2);
    }
    if (!mk.isEmpty()) {
      gc.setFont(Font.font("Segoe UI", 13));
      gc.setFill(np.isRoot ? Color.web("#818cf8")
          : (np.vulnerable ? sevColor(np.severity) : Color.web("#4ade80")));
      gc.setTextAlign(TextAlignment.RIGHT);
      gc.fillText(mk, x + w - 8, y + h / 2);
      gc.setTextAlign(TextAlignment.CENTER);
    }
  }

  private void drawArrow(GraphicsContext gc, NodePos src, NodePos dst) {
    double x1 = src.x + NODE_W / 2, y1 = src.y + NODE_H, x2 = dst.x + NODE_W / 2, y2 = dst.y, cy =
        (y1 + y2) / 2;
    gc.setStroke(Color.web("#4f46e5", .4));
    gc.setLineWidth(1.5);
    gc.beginPath();
    gc.moveTo(x1, y1);
    gc.bezierCurveTo(x1, cy, x2, cy, x2, y2);
    gc.stroke();
    gc.setFill(Color.web("#4f46e5", .6));
    double len = 8, ang = Math.PI / 6;
    gc.beginPath();
    gc.moveTo(x2, y2);
    gc.lineTo(x2 - len * Math.cos(-ang), y2 - len * Math.sin(-ang));
    gc.lineTo(x2 - len * Math.cos(ang), y2 - len * Math.sin(ang));
    gc.closePath();
    gc.fill();
  }

  private void rr(GraphicsContext gc, double x, double y, double w, double h, double r,
      boolean fill, boolean stroke) {
    gc.beginPath();
    gc.moveTo(x + r, y);
    gc.lineTo(x + w - r, y);
    gc.arcTo(x + w, y, x + w, y + r, r);
    gc.lineTo(x + w, y + h - r);
    gc.arcTo(x + w, y + h, x + w - r, y + h, r);
    gc.lineTo(x + r, y + h);
    gc.arcTo(x, y + h, x, y + h - r, r);
    gc.lineTo(x, y + r);
    gc.arcTo(x, y, x + r, y, r);
    gc.closePath();
    if (fill) {
      gc.fill();
    }
    if (stroke) {
      gc.stroke();
    }
  }

  public static class Row {

    private final SimpleStringProperty component = new SimpleStringProperty(), version = new SimpleStringProperty(), vuln = new SimpleStringProperty(), severity = new SimpleStringProperty(), recommend = new SimpleStringProperty(), description = new SimpleStringProperty(), path = new SimpleStringProperty();
    final VulnerabilitySummaryDto vulnDto;
    final ComponentVulnerabilityDto compDto;

    public Row(String c, String v, String vl, String s, String r, String d, String p,
        VulnerabilitySummaryDto vd, ComponentVulnerabilityDto cd) {
      component.set(c);
      version.set(v);
      vuln.set(vl);
      severity.set(s);
      recommend.set(r);
      description.set(d);
      path.set(p);
      vulnDto = vd;
      compDto = cd;
    }

    public SimpleStringProperty componentProperty() {
      return component;
    }

    public SimpleStringProperty versionProperty() {
      return version;
    }

    public SimpleStringProperty vulnProperty() {
      return vuln;
    }

    public SimpleStringProperty severityProperty() {
      return severity;
    }

    public SimpleStringProperty recommendProperty() {
      return recommend;
    }

    public SimpleStringProperty descriptionProperty() {
      return description;
    }

    public SimpleStringProperty pathProperty() {
      return path;
    }
  }
}