"""
FILE-INTEL: Main GUI Application
Vintage-themed PyQt6 desktop interface
"""

import sys
import os
from pathlib import Path
from typing import Optional, List
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFileDialog, QProgressBar, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QFrame, QScrollArea, QGroupBox, QMessageBox, QTabWidget,
    QLineEdit, QCheckBox, QComboBox, QStatusBar, QMenuBar,
    QMenu, QToolBar, QAbstractItemView
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize, QMimeData
from PyQt6.QtGui import (
    QFont, QPalette, QColor, QDragEnterEvent, QDropEvent,
    QAction, QIcon, QPixmap
)


class ScanWorker(QThread):
    """Background worker for file scanning"""
    
    progress = pyqtSignal(str, float)  # message, percentage
    result = pyqtSignal(object)  # ScanResult
    finished_all = pyqtSignal(list)  # List of ScanResults
    error = pyqtSignal(str)
    
    def __init__(self, scanner, files: List[str], options: dict):
        super().__init__()
        self.scanner = scanner
        self.files = files
        self.options = options
        self._cancelled = False
    
    def run(self):
        results = []
        total = len(self.files)
        
        for i, file_path in enumerate(self.files):
            if self._cancelled:
                break
            
            self.progress.emit(f"Scanning {Path(file_path).name}...", (i / total) * 100)
            
            try:
                result = self.scanner.scan_file(
                    file_path,
                    deep_scan=self.options.get('deep_scan', True),
                    enable_yara=self.options.get('enable_yara', True),
                    enable_online_lookup=self.options.get('online_lookup', False)
                )
                results.append(result)
                self.result.emit(result)
                
            except Exception as e:
                self.error.emit(f"Error scanning {file_path}: {e}")
        
        self.progress.emit("Scan complete", 100)
        self.finished_all.emit(results)
    
    def cancel(self):
        self._cancelled = True
        self.scanner.cancel_scan()


class DropZone(QFrame):
    """Drag and drop zone for files"""
    
    files_dropped = pyqtSignal(list)
    
    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setMinimumHeight(200)
        self.default_text = "Drop files or folders here"
        self.sub_text = "or click Browse to select files"
        self.icon_text = "📁"
        self.setup_ui()
    
    def set_message(self, main_text, sub_text="", icon="📁"):
        """Update drop zone text"""
        self.default_text = main_text
        self.sub_text = sub_text
        self.icon_text = icon
        self.setup_ui()
    
    def setup_ui(self):
        self.setStyleSheet("""
            DropZone {
                background-color: #2a2520;
                border: 3px dashed #5a4a3a;
                border-radius: 10px;
            }
            DropZone:hover {
                border-color: #8a7a6a;
                background-color: #352f28;
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Icon
        icon_label = QLabel(self.icon_text)
        icon_label.setStyleSheet("font-size: 48px; color: #8a7a6a;")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Text
        # Text
        text_label = QLabel(self.default_text)
        text_label.setStyleSheet("""
            font-size: 18px;
            font-family: 'Courier New', monospace;
            color: #b0a090;
        """)
        text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        subtext = QLabel(self.sub_text)
        subtext.setStyleSheet("""
            font-size: 12px;
            color: #706050;
        """)
        subtext.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(icon_label)
        layout.addWidget(text_label)
        layout.addWidget(subtext)
    
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setStyleSheet("""
                DropZone {
                    background-color: #3a352e;
                    border: 3px dashed #aa9a8a;
                    border-radius: 10px;
                }
            """)
    
    def dragLeaveEvent(self, event):
        self.setup_ui()
    
    def dropEvent(self, event: QDropEvent):
        files = []
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if os.path.exists(path):
                files.append(path)
        
        self.files_dropped.emit(files)
        self.setup_ui()


class ThreatMeter(QFrame):
    """Visual threat level indicator"""
    
    def __init__(self):
        super().__init__()
        self.score = 0
        self.setup_ui()
    
    def setup_ui(self):
        self.setFixedHeight(80)
        layout = QVBoxLayout(self)
        
        # Label
        self.label = QLabel("THREAT LEVEL")
        self.label.setStyleSheet("""
            font-family: 'Courier New', monospace;
            font-size: 12px;
            color: #8a7a6a;
        """)
        
        # Score display
        self.score_label = QLabel("--")
        self.score_label.setStyleSheet("""
            font-family: 'Courier New', monospace;
            font-size: 32px;
            font-weight: bold;
            color: #4a8a4a;
        """)
        
        # Level label
        self.level_label = QLabel("SAFE")
        self.level_label.setStyleSheet("""
            font-family: 'Courier New', monospace;
            font-size: 14px;
            color: #4a8a4a;
        """)
        
        layout.addWidget(self.label, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.score_label, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.level_label, alignment=Qt.AlignmentFlag.AlignCenter)
    
    def set_score(self, score: float):
        self.score = score
        self.score_label.setText(f"{score:.0f}")
        
        if score >= 80:
            color = "#cc3333"
            level = "CRITICAL"
        elif score >= 60:
            color = "#cc6633"
            level = "HIGH"
        elif score >= 40:
            color = "#ccaa33"
            level = "MEDIUM"
        elif score >= 20:
            color = "#66aa66"
            level = "LOW"
        else:
            color = "#4a8a4a"
            level = "SAFE"
        
        self.score_label.setStyleSheet(f"""
            font-family: 'Courier New', monospace;
            font-size: 32px;
            font-weight: bold;
            color: {color};
        """)
        self.level_label.setStyleSheet(f"""
            font-family: 'Courier New', monospace;
            font-size: 14px;
            color: {color};
        """)
        self.level_label.setText(level)


class FileIntelApp(QMainWindow):
    """Main FILE-INTEL application window"""
    
    def __init__(self):
        super().__init__()
        self.scanner = None
        self.worker = None
        self.results = []
        
        self.setup_ui()
        self.setup_scanner()
    
    def setup_ui(self):
        """Setup the main UI"""
        self.setWindowTitle("FILE-INTEL • Military-Grade File Type Identifier")
        self.setMinimumSize(1200, 800)
        
        # Apply vintage theme
        self.apply_vintage_theme()
        
        # Set app icon
        if os.path.exists("assets/icon.ico"):
            self.setWindowIcon(QIcon("assets/icon.ico"))
        
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Header
        header = self.create_header()
        layout.addWidget(header)
        
        # Main content splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Input and controls
        left_panel = self.create_left_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Results
        right_panel = self.create_right_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([400, 800])
        layout.addWidget(splitter)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.status_bar.setStyleSheet("""
            QStatusBar {
                background-color: #1a1815;
                color: #8a7a6a;
                font-family: 'Courier New', monospace;
            }
        """)
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready • Drop files to analyze")
        
        # Menu bar
        self.create_menu_bar()
    
    def apply_vintage_theme(self):
        """Apply vintage aesthetic theme"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1a17;
            }
            QWidget {
                background-color: #1e1a17;
                color: #c0b0a0;
                font-family: 'Courier New', monospace;
            }
            QPushButton {
                background-color: #3a3530;
                color: #c0b0a0;
                border: 2px solid #5a4a3a;
                border-radius: 5px;
                padding: 8px 16px;
                font-family: 'Courier New', monospace;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #4a4540;
                border-color: #7a6a5a;
            }
            QPushButton:pressed {
                background-color: #2a2520;
            }
            QPushButton:disabled {
                background-color: #2a2520;
                color: #5a5040;
            }
            QGroupBox {
                border: 2px solid #3a3530;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
            }
            QTableWidget {
                background-color: #252220;
                gridline-color: #3a3530;
                border: 2px solid #3a3530;
                border-radius: 5px;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #4a4030;
            }
            QHeaderView::section {
                background-color: #2a2520;
                color: #a09080;
                padding: 8px;
                border: none;
                border-bottom: 2px solid #3a3530;
                font-weight: bold;
            }
            QTextEdit {
                background-color: #252220;
                border: 2px solid #3a3530;
                border-radius: 5px;
                color: #b0a090;
            }
            QProgressBar {
                background-color: #252220;
                border: 2px solid #3a3530;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #5a8a5a;
            }
            QCheckBox {
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: 2px solid #5a4a3a;
                border-radius: 3px;
                background-color: #252220;
            }
            QCheckBox::indicator:checked {
                background-color: #5a8a5a;
            }
            QScrollBar:vertical {
                background-color: #252220;
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background-color: #4a4540;
                border-radius: 6px;
                min-height: 30px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0;
            }
            QTabWidget::pane {
                border: 2px solid #3a3530;
                border-radius: 5px;
            }
            QTabBar::tab {
                background-color: #2a2520;
                color: #8a7a6a;
                padding: 10px 20px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background-color: #3a3530;
                color: #c0b0a0;
            }
        """)
    
    def create_header(self) -> QWidget:
        """Create header section"""
        header = QFrame()
        header.setFixedHeight(80)
        header.setStyleSheet("""
            QFrame {
                background-color: #252220;
                border-radius: 10px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Logo and title
        title = QLabel("FILE-INTEL")
        title.setStyleSheet("""
            font-size: 28px;
            font-weight: bold;
            font-family: 'Courier New', monospace;
            color: #d0c0b0;
            letter-spacing: 4px;
        """)
        
        subtitle = QLabel("Military-Grade File Type Identifier")
        subtitle.setStyleSheet("""
            font-size: 12px;
            color: #706050;
            font-family: 'Courier New', monospace;
        """)
        
        title_layout = QVBoxLayout()
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # Version info
        version = QLabel("v1.0.0")
        version.setStyleSheet("""
            font-size: 11px;
            color: #504030;
        """)
        layout.addWidget(version)
        
        return header
    
    def create_left_panel(self) -> QWidget:
        """Create left control panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 10, 0)
        
        # Drop zone
        self.drop_zone = DropZone()
        self.drop_zone.files_dropped.connect(self.handle_files_dropped)
        layout.addWidget(self.drop_zone)
        
        # Browse button
        browse_layout = QHBoxLayout()
        
        browse_btn = QPushButton("📂 Browse Files")
        browse_btn.clicked.connect(self.browse_files)
        
        browse_dir_btn = QPushButton("📁 Browse Folder")
        browse_dir_btn.clicked.connect(self.browse_directory)
        
        browse_layout.addWidget(browse_btn)
        browse_layout.addWidget(browse_dir_btn)
        layout.addLayout(browse_layout)
        
        # Scan options
        options_group = QGroupBox("Scan Options")
        options_layout = QVBoxLayout(options_group)
        
        self.deep_scan_cb = QCheckBox("Deep Scan (thorough analysis)")
        self.deep_scan_cb.setChecked(True)
        
        self.yara_cb = QCheckBox("YARA Rules (malware signatures)")
        self.yara_cb.setChecked(True)
        
        self.online_cb = QCheckBox("Online Lookup (VirusTotal)")
        self.online_cb.setChecked(False)
        
        options_layout.addWidget(self.deep_scan_cb)
        options_layout.addWidget(self.yara_cb)
        options_layout.addWidget(self.online_cb)
        
        layout.addWidget(options_group)
        
        # Threat meter
        self.threat_meter = ThreatMeter()
        layout.addWidget(self.threat_meter)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Scan button
        self.scan_btn = QPushButton("🔍 ANALYZE FILES")
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #4a6a4a;
                font-size: 16px;
                padding: 15px;
            }
            QPushButton:hover {
                background-color: #5a7a5a;
            }
        """)
        self.scan_btn.clicked.connect(self.start_scan)
        self.scan_btn.setEnabled(False)
        self.scan_btn.setEnabled(False)
        layout.addWidget(self.scan_btn)
        
        # Stop button
        self.stop_btn = QPushButton("STOP SCAN")
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #8a3a3a;
                font-size: 14px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #9a4a4a;
            }
            QPushButton:disabled {
                background-color: #3a2a2a;
                color: #5a4a4a;
            }
        """)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        layout.addWidget(self.stop_btn)
        
        layout.addStretch()
        
        return panel
    
    def create_right_panel(self) -> QWidget:
        """Create right results panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(10, 0, 0, 0)
        
        # Tabs for different views
        tabs = QTabWidget()
        
        # Results table tab
        results_widget = QWidget()
        results_layout = QVBoxLayout(results_widget)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels([
            "File", "Type", "Threat", "Score", "Status"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.results_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.results_table.itemSelectionChanged.connect(self.on_result_selected)
        
        results_layout.addWidget(self.results_table)
        tabs.addTab(results_widget, "📋 Results")
        
        # Details tab
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setStyleSheet("""
            font-family: 'Courier New', monospace;
            font-size: 12px;
        """)
        details_layout.addWidget(self.details_text)
        tabs.addTab(details_widget, "📄 Details")
        
        # Log tab
        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("""
            font-family: 'Courier New', monospace;
            font-size: 11px;
            color: #809070;
        """)
        log_layout.addWidget(self.log_text)
        tabs.addTab(log_widget, "📜 Log")
        
        layout.addWidget(tabs)
        
        # Export buttons
        export_layout = QHBoxLayout()
        
        export_json = QPushButton("Export JSON")
        export_json.clicked.connect(lambda: self.export_results('json'))
        
        export_html = QPushButton("Export HTML")
        export_html.clicked.connect(lambda: self.export_results('html'))
        
        export_csv = QPushButton("Export CSV")
        export_csv.clicked.connect(lambda: self.export_results('csv'))
        
        export_layout.addWidget(export_json)
        export_layout.addWidget(export_html)
        export_layout.addWidget(export_csv)
        export_layout.addStretch()
        
        layout.addLayout(export_layout)
        
        return panel
    
    def create_menu_bar(self):
        """Create menu bar"""
        menu_bar = self.menuBar()
        menu_bar.setStyleSheet("""
            QMenuBar {
                background-color: #252220;
                color: #a09080;
            }
            QMenuBar::item:selected {
                background-color: #3a3530;
            }
            QMenu {
                background-color: #2a2520;
                color: #a09080;
                border: 2px solid #3a3530;
            }
            QMenu::item:selected {
                background-color: #3a3530;
            }
        """)
        
        # File menu
        file_menu = menu_bar.addMenu("File")
        
        open_file = QAction("Open File...", self)
        open_file.triggered.connect(self.browse_files)
        file_menu.addAction(open_file)
        
        open_dir = QAction("Open Folder...", self)
        open_dir.triggered.connect(self.browse_directory)
        file_menu.addAction(open_dir)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Help menu
        help_menu = menu_bar.addMenu("Help")
        
        about = QAction("About FILE-INTEL", self)
        about.triggered.connect(self.show_about)
        help_menu.addAction(about)
    
    def setup_scanner(self):
        """Initialize the file scanner"""
        try:
            from ..config import Config
            from ..core.file_scanner import FileScanner
            
            config = Config()
            self.scanner = FileScanner(config)
            self.log("Scanner initialized successfully")
            
        except Exception as e:
            self.log(f"Error initializing scanner: {e}")
    
    def log(self, message: str):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
    
    def handle_files_dropped(self, files: List[str]):
        """Handle files dropped on drop zone"""
        self.pending_files = []
        
        for path in files:
            if os.path.isfile(path):
                self.pending_files.append(path)
            elif os.path.isdir(path):
                # Collect all files in directory
                for root, dirs, filenames in os.walk(path):
                    for filename in filenames:
                        self.pending_files.append(os.path.join(root, filename))
        
        self.log(f"Queued {len(self.pending_files)} files for analysis")
        self.scan_btn.setEnabled(len(self.pending_files) > 0)
        
        # Update DropZone feedback
        if self.pending_files:
            first_file = os.path.basename(self.pending_files[0])
            count = len(self.pending_files)
            if count == 1:
                msg = f"Ready: {first_file}"
            else:
                msg = f"Ready: {first_file} +{count-1} others"
            
            self.drop_zone.set_message(msg, "Click ANALYZE FILES to start", "✅")
            
        self.status_bar.showMessage(f"{len(self.pending_files)} files ready to analyze")
    
    def browse_files(self):
        """Browse for files"""
        files, _ = QFileDialog.getOpenFileNames(
            self, "Select Files to Analyze", "",
            "All Files (*.*)"
        )
        if files:
            self.handle_files_dropped(files)
    
    def browse_directory(self):
        """Browse for directory"""
        directory = QFileDialog.getExistingDirectory(
            self, "Select Folder to Analyze"
        )
        if directory:
            self.handle_files_dropped([directory])
    
    def start_scan(self):
        """Start scanning queued files"""
        if not self.scanner:
            self.log("Scanner not initialized!")
            return
        
        if not hasattr(self, 'pending_files') or not self.pending_files:
            return
        
        # Setup progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.drop_zone.setEnabled(False)
        self.results_table.setRowCount(0)
        self.results = []
        
        # Create worker
        options = {
            'deep_scan': self.deep_scan_cb.isChecked(),
            'enable_yara': self.yara_cb.isChecked(),
            'online_lookup': self.online_cb.isChecked()
        }
        
        self.worker = ScanWorker(self.scanner, self.pending_files, options)
        self.worker.progress.connect(self.on_progress)
        self.worker.result.connect(self.on_result)
        self.worker.finished_all.connect(self.on_scan_complete)
        self.worker.error.connect(self.log)
        self.worker.start()
        
        self.log(f"Started scanning {len(self.pending_files)} files...")
        
    def stop_scan(self):
        """Stop the ongoing scan"""
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.log("Stopping scan... please wait for current file.", "warning")
            self.stop_btn.setEnabled(False)
            self.status_bar.showMessage("Stopping scan...")
    
    def on_progress(self, message: str, percentage: float):
        """Handle progress update"""
        self.progress_bar.setValue(int(percentage))
        self.status_bar.showMessage(message)
    
    def on_result(self, result):
        """Handle single scan result"""
        self.results.append(result)
        
        # Add to table
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        # Filename
        self.results_table.setItem(row, 0, QTableWidgetItem(result.file_name))
        
        # Type
        type_text = result.magic_result.detected_type if result.magic_result else "Unknown"
        self.results_table.setItem(row, 1, QTableWidgetItem(type_text[:20]))
        
        # Threat level
        threat_item = QTableWidgetItem(result.threat_level.value.upper())
        threat_colors = {
            'safe': QColor(70, 140, 70),
            'low': QColor(100, 170, 100),
            'medium': QColor(200, 170, 50),
            'high': QColor(200, 100, 50),
            'critical': QColor(200, 50, 50)
        }
        threat_item.setForeground(threat_colors.get(result.threat_level.value.lower(), QColor(150, 140, 130)))
        self.results_table.setItem(row, 2, threat_item)
        
        # Score
        self.results_table.setItem(row, 3, QTableWidgetItem(f"{result.threat_score:.0f}"))
        
        # Status
        status = "⚠ ALERT" if result.threat_score >= 60 else "✓ OK"
        self.results_table.setItem(row, 4, QTableWidgetItem(status))
        
        # Update threat meter with highest score
        if result.threat_score > self.threat_meter.score:
            self.threat_meter.set_score(result.threat_score)
    
    def on_scan_complete(self, results: List):
        """Handle scan completion"""
        self.progress_bar.setVisible(False)
        self.progress_bar.setVisible(False)
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.drop_zone.setEnabled(True)
        
        high_threats = [r for r in results if r.threat_score >= 60]
        
        if high_threats:
            self.status_bar.showMessage(f"⚠ ALERT: {len(high_threats)} high-threat files detected!")
            self.log(f"Scan complete: {len(high_threats)} threats found in {len(results)} files")
        else:
            self.status_bar.showMessage(f"✓ Scan complete: {len(results)} files analyzed")
            self.log(f"Scan complete: No significant threats in {len(results)} files")
    
    def on_result_selected(self):
        """Handle result selection in table"""
        rows = self.results_table.selectionModel().selectedRows()
        if rows and self.results:
            row = rows[0].row()
            if row < len(self.results):
                result = self.results[row]
                self.show_result_details(result)
    
    def show_result_details(self, result):
        """Show detailed result in details panel"""
        details = []
        details.append(f"{'='*60}")
        details.append(f"FILE: {result.file_name}")
        details.append(f"Path: {result.file_path}")
        details.append(f"Size: {result.file_size:,} bytes")
        details.append(f"Scan Time: {result.scan_duration_ms:.0f}ms")
        details.append(f"{'='*60}")
        
        if result.magic_result:
            details.append(f"\n[DETECTED TYPE]")
            details.append(f"  Type: {result.magic_result.detected_type}")
            details.append(f"  Category: {result.magic_result.category.value}")
            details.append(f"  MIME: {result.magic_result.mime_type}")
            details.append(f"  Confidence: {result.magic_result.confidence:.0%}")
        
        if result.extension_mismatch:
            details.append(f"\n[⚠ EXTENSION MISMATCH]")
            details.append(f"  {result.extension_mismatch.get('message', '')}")
        
        if result.entropy_result:
            details.append(f"\n[ENTROPY ANALYSIS]")
            details.append(f"  Overall: {result.entropy_result.overall_entropy:.2f}")
            details.append(f"  Category: {result.entropy_result.category.value}")
            if result.entropy_result.is_suspicious:
                details.append(f"  ⚠ {result.entropy_result.suspicion_reason}")
        
        if result.hash_result:
            details.append(f"\n[FILE HASHES]")
            details.append(f"  MD5:    {result.hash_result.md5}")
            details.append(f"  SHA1:   {result.hash_result.sha1}")
            details.append(f"  SHA256: {result.hash_result.sha256}")
        
        if result.yara_matches:
            details.append(f"\n[YARA MATCHES] ({len(result.yara_matches)} rules)")
            for match in result.yara_matches[:10]:
                details.append(f"  [{match.get('severity')}] {match.get('rule')}")
        
        details.append(f"\n[THREAT ASSESSMENT]")
        details.append(f"  Score: {result.threat_score:.0f}/100")
        details.append(f"  Level: {result.threat_level.value.upper()}")
        
        if result.threat_indicators:
            details.append(f"\n[INDICATORS]")
            for ind in result.threat_indicators:
                details.append(f"  • {ind}")
        
        if result.recommendations:
            details.append(f"\n[RECOMMENDATIONS]")
            for rec in result.recommendations:
                details.append(f"  → {rec}")
        
        self.details_text.setText('\n'.join(details))
    
    def export_results(self, format_type: str):
        """Export results to file"""
        if not self.results:
            QMessageBox.warning(self, "Export", "No results to export")
            return
        
        # Get save path
        extensions = {'json': 'JSON (*.json)', 'html': 'HTML (*.html)', 'csv': 'CSV (*.csv)'}
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Results", f"file_intel_report.{format_type}",
            extensions.get(format_type, '*.*')
        )
        
        if not path:
            return
        
        try:
            if format_type == 'json':
                import json
                with open(path, 'w') as f:
                    json.dump([r.to_dict() for r in self.results], f, indent=2)
            
            elif format_type == 'csv':
                import csv
                with open(path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['File', 'Path', 'Type', 'Threat', 'Score', 'Indicators'])
                    for r in self.results:
                        type_name = r.magic_result.detected_type if r.magic_result else 'Unknown'
                        writer.writerow([
                            r.file_name, r.file_path, type_name,
                            r.threat_level.value, r.threat_score,
                            '; '.join(r.threat_indicators)
                        ])
            
            elif format_type == 'html':
                # Simple HTML report
                html = self.generate_html_report()
                with open(path, 'w') as f:
                    f.write(html)
            
            self.log(f"Exported results to {path}")
            QMessageBox.information(self, "Export", f"Results exported to:\n{path}")
            
        except Exception as e:
            self.log(f"Export error: {e}")
            QMessageBox.critical(self, "Export Error", str(e))
    
    def generate_html_report(self) -> str:
        """Generate HTML report"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>FILE-INTEL Analysis Report</title>
    <style>
        body { font-family: 'Courier New', monospace; background: #1e1a17; color: #c0b0a0; padding: 20px; }
        h1 { color: #d0c0b0; border-bottom: 2px solid #3a3530; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; text-align: left; border: 1px solid #3a3530; }
        th { background: #2a2520; }
        .critical { color: #cc3333; font-weight: bold; }
        .high { color: #cc6633; }
        .medium { color: #ccaa33; }
        .low { color: #66aa66; }
        .safe { color: #4a8a4a; }
    </style>
</head>
<body>
    <h1>FILE-INTEL Analysis Report</h1>
    <p>Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
    <table>
        <tr><th>File</th><th>Type</th><th>Threat</th><th>Score</th><th>Indicators</th></tr>
"""
        for r in self.results:
            type_name = r.magic_result.detected_type if r.magic_result else 'Unknown'
            threat_class = r.threat_level.value.lower()
            indicators = '<br>'.join(r.threat_indicators[:3])
            html += f"""        <tr>
            <td>{r.file_name}</td>
            <td>{type_name}</td>
            <td class="{threat_class}">{r.threat_level.value.upper()}</td>
            <td>{r.threat_score:.0f}</td>
            <td>{indicators}</td>
        </tr>
"""
        html += """    </table>
</body>
</html>"""
        return html
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, "About FILE-INTEL",
            "<h2>FILE-INTEL</h2>"
            "<p>Military-Grade File Type Identifier</p>"
            "<p>Version 1.0.0</p>"
            "<hr>"
            "<p>Advanced file analysis tool for red team operations, "
            "malware analysis, and threat hunting.</p>"
            "<p>Features:</p>"
            "<ul>"
            "<li>Magic number detection (80+ signatures)</li>"
            "<li>Entropy analysis for packed/encrypted content</li>"
            "<li>YARA rule scanning (1000+ rules)</li>"
            "<li>Extension mismatch detection</li>"
            "<li>VirusTotal integration</li>"
            "<li>URLhaus threat database</li>"
            "</ul>"
        )


def main():
    """Launch GUI application"""
    app = QApplication(sys.argv)
    window = FileIntelApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
