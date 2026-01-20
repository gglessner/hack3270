"""
Hack3270 GUI Module

PySide6-based graphical user interface for the hack3270 toolkit.
"""
__author__ = 'Garland Glessner'
__license__ = "GPL-3.0"

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QTabWidget, QLabel, QPushButton, QCheckBox, QComboBox, QGroupBox,
    QTreeWidget, QTreeWidgetItem, QTextEdit, QFileDialog, QHeaderView,
    QSplitter, QFrame, QScrollArea, QSizePolicy, QLineEdit
)

class NumericTreeWidgetItem(QTreeWidgetItem):
    """Custom QTreeWidgetItem that sorts numerically for ID (col 0), Delta (col 2), and Length (col 4)"""
    def __lt__(self, other):
        column = self.treeWidget().sortColumn()
        if column == 0:  # ID column - integer
            try:
                return int(self.text(column)) < int(other.text(column))
            except ValueError:
                pass
        elif column == 2:  # Delta column - float, "-" should sort first
            try:
                self_val = float(self.text(column)) if self.text(column) != "-" else -1
                other_val = float(other.text(column)) if other.text(column) != "-" else -1
                return self_val < other_val
            except ValueError:
                pass
        elif column == 4:  # Length column - integer
            try:
                return int(self.text(column)) < int(other.text(column))
            except ValueError:
                pass
        return self.text(column) < other.text(column)

class FuzzingTreeWidgetItem(QTreeWidgetItem):
    """Custom QTreeWidgetItem for Fuzzing tabs - sorts # (col 0) and Response Length (col 4) numerically"""
    def __lt__(self, other):
        column = self.treeWidget().sortColumn()
        if column in (0, 4):  # # and Response Length columns - integer
            try:
                return int(self.text(column)) < int(other.text(column))
            except ValueError:
                pass
        return self.text(column) < other.text(column)

class AnalysisTreeWidgetItem(QTreeWidgetItem):
    """Custom QTreeWidgetItem for Analysis tab - sorts Req(1), Resp(2), Len(4) numerically"""
    def __lt__(self, other):
        column = self.treeWidget().sortColumn()
        if column in (1, 2, 4):  # Req, Resp, Len columns - integer
            try:
                return int(self.text(column)) < int(other.text(column))
            except ValueError:
                pass
        return self.text(column) < other.text(column)
from PySide6.QtCore import Qt, QTimer, Signal, Slot, qInstallMessageHandler, QtMsgType
from PySide6.QtGui import QFont, QColor, QPalette, QAction
import libhack3270
import sys
import signal
import platform
import logging
import datetime
import re
import csv

# Suppress Qt geometry warnings (common on high-DPI/multi-monitor setups)
def qt_message_handler(mode, context, message):
    if "Unable to set geometry" in message:
        return  # Suppress geometry warnings
    # Print other messages normally
    if mode == QtMsgType.QtWarningMsg:
        print(f"Qt Warning: {message}")
    elif mode == QtMsgType.QtCriticalMsg:
        print(f"Qt Critical: {message}")
    elif mode == QtMsgType.QtFatalMsg:
        print(f"Qt Fatal: {message}")

qInstallMessageHandler(qt_message_handler)

# Dark theme stylesheet
DARK_STYLE = """
QMainWindow, QWidget {
    background-color: #1e1e1e;
    color: #d4d4d4;
    font-family: 'Segoe UI', sans-serif;
    font-size: 13px;
}
QTabWidget::pane {
    border: 1px solid #3c3c3c;
    background-color: #252526;
    border-radius: 4px;
}
QTabBar::tab {
    background-color: #2d2d2d;
    color: #808080;
    padding: 8px 16px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}
QTabBar::tab:selected {
    background-color: #1e1e1e;
    color: #ffffff;
    border-bottom: 2px solid #0078d4;
}
QTabBar::tab:hover:!selected {
    background-color: #383838;
}
QPushButton {
    background-color: #0078d4;
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 4px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #1084d8;
}
QPushButton:pressed {
    background-color: #006cbd;
}
QPushButton:disabled {
    background-color: #3c3c3c;
    color: #808080;
}
QPushButton[class="danger"] {
    background-color: #d32f2f;
}
QPushButton[class="danger"]:hover {
    background-color: #e53935;
}
QPushButton[class="success"] {
    background-color: #388e3c;
}
QPushButton[class="success"]:hover {
    background-color: #43a047;
}
QCheckBox {
    spacing: 8px;
    color: #d4d4d4;
}
QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border-radius: 3px;
    border: 2px solid #5c5c5c;
    background-color: #2d2d2d;
}
QCheckBox::indicator:checked {
    background-color: #0078d4;
    border-color: #0078d4;
}
QCheckBox::indicator:hover {
    border-color: #0078d4;
}
QComboBox {
    background-color: #3c3c3c;
    border: 1px solid #5c5c5c;
    border-radius: 4px;
    padding: 6px 12px;
    min-width: 100px;
}
QComboBox:hover {
    border-color: #0078d4;
}
QComboBox::drop-down {
    border: none;
    width: 20px;
}
QComboBox QAbstractItemView {
    background-color: #2d2d2d;
    border: 1px solid #5c5c5c;
    selection-background-color: #0078d4;
}
QTreeWidget {
    background-color: #1e1e1e;
    border: 1px solid #3c3c3c;
    border-radius: 4px;
    alternate-background-color: #252526;
}
QTreeWidget::item {
    padding: 4px;
}
QTreeWidget::item:selected {
    background-color: #0078d4;
}
QTreeWidget::item:hover:!selected {
    background-color: #2a2d2e;
}
QHeaderView::section {
    background-color: #2d2d2d;
    color: #d4d4d4;
    padding: 8px;
    border: none;
    border-right: 1px solid #3c3c3c;
    font-weight: bold;
}
QTextEdit {
    background-color: #1e1e1e;
    color: #d4d4d4;
    border: 1px solid #3c3c3c;
    border-radius: 4px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
}
QGroupBox {
    font-weight: bold;
    border: 1px solid #3c3c3c;
    border-radius: 4px;
    margin-top: 12px;
    padding-top: 12px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
    color: #0078d4;
}
QScrollBar:vertical {
    background-color: #1e1e1e;
    width: 12px;
    border-radius: 6px;
}
QScrollBar::handle:vertical {
    background-color: #5c5c5c;
    border-radius: 6px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover {
    background-color: #808080;
}
QLabel[class="status-ready"] { color: #4caf50; }
QLabel[class="status-warning"] { color: #ff9800; }
QLabel[class="status-error"] { color: #f44336; }
QLabel[class="status-info"] { color: #2196f3; }
QLabel[class="header"] { 
    font-size: 14px; 
    font-weight: bold; 
    color: #0078d4; 
}
"""


class Hack3270GUI(QMainWindow):
    def __init__(self, hack3270, logfile=None, loglevel=logging.WARNING):
        super().__init__()
        
        self.hack3270 = hack3270
        self.last_db_id = 0
        self.last_log_timestamp = None  # For calculating delta between log entries
        self.log_follow_mode = False  # Auto-scroll to latest log entry
        self.inject_filename = ""
        self.last_inject_config_set = False  # Track inject config state changes
        self.inject_stop_flag = False  # Flag to stop injection loop
        self.inject_pause_flag = False  # Flag to pause injection loop
        self.inject_lines = []  # Lines loaded from injection file
        self.inject_index = 0   # Current position in injection file
        self.send_keys_stop_flag = False  # Flag to stop send keys loop
        self.logs_initial_scroll_done = False  # Flag to scroll to last log on first Logs tab visit

        # Logger setup
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        if logfile is not None:
            logger_formatter = logging.Formatter(
                '%(levelname)s :: {} :: %(funcName)s :: %(message)s'.format(logfile))
        else:
            logger_formatter = logging.Formatter(
                '%(module)s :: %(levelname)s :: %(funcName)s :: %(lineno)d :: %(message)s')
        ch = logging.StreamHandler()
        ch.setFormatter(logger_formatter)
        ch.setLevel(loglevel)
        if not self.logger.hasHandlers():
            self.logger.addHandler(ch)

        self.init_ui()
        self.setup_timer()
        
        # Handle Ctrl+C gracefully
        signal.signal(signal.SIGINT, self.sigint_handler)
        
    def sigint_handler(self, signum, frame):
        """Handle Ctrl+C for graceful shutdown"""
        self.logger.debug("SIGINT received, shutting down")
        self.close()
        
    def init_ui(self):
        self.setWindowTitle(f"{libhack3270.__name__} v{libhack3270.__version__}")
        self.setStyleSheet(DARK_STYLE)
        
        # Get screen size
        screen = QApplication.primaryScreen().geometry()
        self.screen_width = screen.width()
        self.screen_height = screen.height()
        
        # Window sizing configuration - TWEAK THESE VALUES
        self.tab0_height = 200   # Tab 0: Hack Field Attributes
        self.tab1_height = 180   # Tab 1: Inject Into Fields
        self.tab2_height = 250   # Tab 2: Inject Key Presses
        self.tab3_height = 180   # Tab 3: AID Spoofing
        self.tab4_height = 700   # Tab 4: Field Fuzzing
        self.tab5_height = 700   # Tab 5: Order Fuzzing (same as Field Fuzzing)
        self.tall_height = 525   # Tabs 6, 7, 9: Logs, Analysis, Help (Statistics uses tall_height + 100)
        self.user_tall_height = self.tall_height  # Remember user's preferred tall height
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        # Offline mode banner
        if self.hack3270.is_offline():
            banner = QLabel("OFFLINE LOG ANALYSIS MODE")
            banner.setProperty("class", "status-warning")
            banner.setAlignment(Qt.AlignCenter)
            banner.setFont(QFont("Segoe UI", 14, QFont.Bold))
            main_layout.addWidget(banner)
        
        # Tab widget
        self.tabs = QTabWidget()
        self.last_tab_index = 0  # Initialize before connecting signal
        self.tabs.currentChanged.connect(self.on_tab_changed)
        main_layout.addWidget(self.tabs)
        
        # Create tabs
        self.create_hack_fields_tab()
        self.create_inject_fields_tab()
        self.create_inject_keys_tab()
        self.create_aid_spoofing_tab()
        self.create_field_fuzzing_tab()
        self.create_order_fuzzing_tab()
        self.create_logs_tab()
        self.create_analysis_tab()
        self.create_statistics_tab()
        self.create_help_tab()
        
        # Disable tabs in offline mode
        if self.hack3270.is_offline():
            for i in range(6):  # Disable first 6 tabs (including AID Spoofing, Field Fuzzing, Order Fuzzing)
                self.tabs.setTabEnabled(i, False)
        
        # Full horizontal width, start with tab 0 height
        self.resize(self.screen_width, self.tab0_height)
        self.setMinimumWidth(self.screen_width)  # Prevent making it narrower
        self.setMinimumHeight(100)  # Safety net for minimum height
        self.move(0, 0)  # Start at top of screen
        
        # Apply sizing to the initial tab
        self.on_tab_changed(self.tabs.currentIndex())
        
    def on_tab_changed(self, index):
        """Resize window height based on tab - each tab has its own height"""
        # Tab indices: 0=Hack Fields, 1=Inject Fields, 2=Inject Keys, 3=AID Spoofing, 
        #              4=Field Fuzzing, 5=Order Fuzzing, 6=Logs, 7=Analysis, 8=Statistics, 9=Help
        
        # Save tall height when leaving Help tab (only Help uses user-resizable height)
        if self.last_tab_index == 9:
            self.user_tall_height = self.height()
        
        # Handle height - each tab has its own height
        if index == 0:  # Hack Field Attributes
            self.resize(self.screen_width, self.tab0_height)
        elif index == 1:  # Inject Into Fields
            self.resize(self.screen_width, self.tab1_height)
        elif index == 2:  # Inject Key Presses
            self.resize(self.screen_width, self.tab2_height)
        elif index == 3:  # AID Spoofing
            self.resize(self.screen_width, self.tab3_height)
        elif index == 4:  # Field Fuzzing
            self.resize(self.screen_width, self.tab4_height)
        elif index == 5:  # Order Fuzzing
            self.resize(self.screen_width, self.tab5_height)
        elif index in [6, 7, 8]:  # Logs, Analysis, Statistics - same fixed height
            if index == 6:  # Logs
                self.update_logs_tab()
                # Scroll to last item on first visit to Logs tab
                if not self.logs_initial_scroll_done and self.log_tree.topLevelItemCount() > 0:
                    self.logs_initial_scroll_done = True
                    QApplication.processEvents()  # Ensure UI is ready
                    last_item = self.log_tree.topLevelItem(self.log_tree.topLevelItemCount() - 1)
                    self.log_tree.setCurrentItem(last_item)
                    self.log_tree.scrollToItem(last_item, QTreeWidget.PositionAtBottom)
            self.resize(self.screen_width, self.tall_height + 100)
        elif index == 9:  # Help - use user's preferred tall height
            target_height = max(self.user_tall_height, self.tall_height)
            self.resize(self.screen_width, target_height)
        
        self.last_tab_index = index
        
    def setup_timer(self):
        self.timer = QTimer()
        self.timer.timeout.connect(self.run_loop)
        self.timer.start(10)
        
    def run_loop(self):
        if self.hack3270.is_offline():
            return
        try:
            # Run AID fuzzer iteration if active
            if self.hack3270.aid_fuzzer_running:
                self.hack3270.run_aid_fuzzer(None)
            else:
                self.hack3270.daemon()
            
            if self.tabs.currentIndex() == 2:  # Inject Keys tab
                self.aid_refresh()
            
            # Update logs tab if we're on it, or if Follow mode is active
            if self.tabs.currentIndex() == 4 or self.log_follow_mode:  # Logs tab or Follow mode
                self.update_logs_tab()
            
            # Check if inject config was just set (mask captured)
            current_config = self.hack3270.get_inject_config_set()
            if current_config and not self.last_inject_config_set:
                mask_len = self.hack3270.get_inject_mask_len()
                self.inject_status.setText(f"Mask set! Field length: {mask_len}. Ready for injection.")
                self.inject_status.setProperty("class", "status-ready")
                self.inject_status.style().unpolish(self.inject_status)
                self.inject_status.style().polish(self.inject_status)
            self.last_inject_config_set = current_config
        except (ValueError, OSError, KeyboardInterrupt):
            # Socket closed or Ctrl+C, stop the timer and close
            self.timer.stop()
            self.close()
            
    def create_hack_fields_tab(self):
        tab = QWidget()
        layout = QHBoxLayout(tab)
        layout.setSpacing(20)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Hack button section
        btn_group = QGroupBox("Hack Fields")
        btn_layout = QVBoxLayout(btn_group)
        self.hack_button = QPushButton("OFF")
        self.hack_button.setProperty("class", "danger")
        self.hack_button.setMinimumWidth(100)
        self.hack_button.clicked.connect(self.hack_button_pressed)
        btn_layout.addWidget(self.hack_button)
        btn_layout.addStretch()
        layout.addWidget(btn_group)
        
        # Field options
        opts_group = QGroupBox("Field Options")
        opts_layout = QVBoxLayout(opts_group)
        self.hack_prot_cb = QCheckBox("Disable Field Protection")
        self.hack_prot_cb.setChecked(True)
        self.hack_hf_cb = QCheckBox("Enable Hidden Fields")
        self.hack_hf_cb.setChecked(True)
        self.hack_rnr_cb = QCheckBox("Remove Numeric Only Restrictions")
        self.hack_rnr_cb.setChecked(True)
        for cb in [self.hack_prot_cb, self.hack_hf_cb, self.hack_rnr_cb]:
            cb.stateChanged.connect(self.hack_toggle)
            opts_layout.addWidget(cb)
        opts_layout.addStretch()
        layout.addWidget(opts_group)
        
        # Field types
        types_group = QGroupBox("Field Types")
        types_layout = QVBoxLayout(types_group)
        self.hack_sf_cb = QCheckBox("Start Field")
        self.hack_sf_cb.setChecked(True)
        self.hack_sfe_cb = QCheckBox("Start Field Extended")
        self.hack_sfe_cb.setChecked(True)
        self.hack_mf_cb = QCheckBox("Modify Field")
        self.hack_mf_cb.setChecked(True)
        for cb in [self.hack_sf_cb, self.hack_sfe_cb, self.hack_mf_cb]:
            cb.stateChanged.connect(self.hack_toggle)
            types_layout.addWidget(cb)
        types_layout.addStretch()
        layout.addWidget(types_group)
        
        # Highlighting
        hl_group = QGroupBox("Hidden Field Highlighting")
        hl_layout = QVBoxLayout(hl_group)
        self.hack_ei_cb = QCheckBox("Enable Intensity")
        self.hack_ei_cb.setChecked(True)
        self.hack_hv_cb = QCheckBox("High Visibility")
        self.hack_hv_cb.setChecked(True)
        for cb in [self.hack_ei_cb, self.hack_hv_cb]:
            cb.stateChanged.connect(self.hack_toggle)
            hl_layout.addWidget(cb)
        hl_layout.addStretch()
        layout.addWidget(hl_group)
        
        # Hack color button
        color_btn_group = QGroupBox("Hack Color")
        color_btn_layout = QVBoxLayout(color_btn_group)
        self.hack_color_button = QPushButton("OFF")
        self.hack_color_button.setProperty("class", "danger")
        self.hack_color_button.setMinimumWidth(100)
        self.hack_color_button.clicked.connect(self.hack_color_button_pressed)
        color_btn_layout.addWidget(self.hack_color_button)
        color_btn_layout.addStretch()
        layout.addWidget(color_btn_group)
        
        # Color options
        color_opts_group = QGroupBox("Color Options")
        color_opts_layout = QVBoxLayout(color_opts_group)
        self.hack_color_sfe_cb = QCheckBox("Start Field Extended")
        self.hack_color_sfe_cb.setChecked(True)
        self.hack_color_mf_cb = QCheckBox("Modify Field")
        self.hack_color_mf_cb.setChecked(True)
        self.hack_color_sa_cb = QCheckBox("Set Attribute")
        self.hack_color_sa_cb.setChecked(True)
        self.hack_color_hv_cb = QCheckBox("High Visibility")
        self.hack_color_hv_cb.setChecked(True)
        for cb in [self.hack_color_sfe_cb, self.hack_color_mf_cb, self.hack_color_sa_cb, self.hack_color_hv_cb]:
            cb.stateChanged.connect(self.hack_color_toggle)
            color_opts_layout.addWidget(cb)
        color_opts_layout.addStretch()
        layout.addWidget(color_opts_group)
        
        self.tabs.addTab(tab, "Hack Field Attributes")
        
    def create_inject_fields_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Top controls
        top_layout = QHBoxLayout()
        
        status_label = QLabel("Status:")
        status_label.setProperty("class", "header")
        top_layout.addWidget(status_label)
        
        self.inject_status = QLabel("Not Ready.")
        self.inject_status.setProperty("class", "status-warning")
        top_layout.addWidget(self.inject_status)
        top_layout.addStretch()
        
        file_btn = QPushButton("FILE")
        file_btn.clicked.connect(self.browse_files)
        top_layout.addWidget(file_btn)
        
        setup_btn = QPushButton("SETUP")
        setup_btn.clicked.connect(self.inject_setup)
        top_layout.addWidget(setup_btn)
        
        inject_btn = QPushButton("INJECT")
        inject_btn.setProperty("class", "success")
        inject_btn.clicked.connect(self.inject_go)
        top_layout.addWidget(inject_btn)
        
        step_btn = QPushButton("STEP")
        step_btn.clicked.connect(self.inject_step)
        top_layout.addWidget(step_btn)
        
        pause_btn = QPushButton("PAUSE")
        pause_btn.clicked.connect(self.inject_pause)
        top_layout.addWidget(pause_btn)
        
        resume_btn = QPushButton("RESUME")
        resume_btn.clicked.connect(self.inject_resume)
        top_layout.addWidget(resume_btn)
        
        stop_btn = QPushButton("STOP")
        stop_btn.setProperty("class", "danger")
        stop_btn.clicked.connect(self.inject_stop)
        top_layout.addWidget(stop_btn)
        
        reset_btn = QPushButton("RESET")
        reset_btn.clicked.connect(self.inject_reset)
        top_layout.addWidget(reset_btn)
        
        layout.addLayout(top_layout)
        
        # Options row
        opts_layout = QHBoxLayout()
        
        opts_layout.addWidget(QLabel("Mask:"))
        self.mask_combo = QComboBox()
        self.mask_combo.addItems(["@", "#", "$", "%", "^", "&", "*"])
        self.mask_combo.setCurrentText("*")
        opts_layout.addWidget(self.mask_combo)
        
        opts_layout.addSpacing(20)
        opts_layout.addWidget(QLabel("Mode:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["SKIP", "TRUNC", "OVERFLOW"])
        opts_layout.addWidget(self.mode_combo)
        
        opts_layout.addSpacing(20)
        opts_layout.addWidget(QLabel("Keys:"))
        self.keys_combo = QComboBox()
        self.keys_combo.addItems(["ENTER", "ENTER+CLEAR", "ENTER+PF3", "ENTER+PF3+CLEAR"])
        opts_layout.addWidget(self.keys_combo)
        
        opts_layout.addStretch()
        layout.addLayout(opts_layout)
        
        layout.addSpacing(20)
        self.tabs.addTab(tab, "Inject Into Fields")
        
    def create_inject_keys_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Top controls
        top_layout = QHBoxLayout()
        send_btn = QPushButton("Send Keys")
        send_btn.setProperty("class", "success")
        send_btn.clicked.connect(self.send_keys)
        top_layout.addWidget(send_btn)
        
        send_stop_btn = QPushButton("STOP")
        send_stop_btn.setProperty("class", "danger")
        send_stop_btn.clicked.connect(self.send_keys_stop)
        top_layout.addWidget(send_stop_btn)
        
        clear_all_btn = QPushButton("CLEAR ALL")
        clear_all_btn.clicked.connect(self.aid_clear_all)
        top_layout.addWidget(clear_all_btn)
        
        defaults_btn = QPushButton("DEFAULTS")
        defaults_btn.clicked.connect(self.aid_setdef)
        top_layout.addWidget(defaults_btn)
        
        self.send_label = QLabel("Ready.")
        self.send_label.setProperty("class", "status-ready")
        top_layout.addWidget(self.send_label)
        top_layout.addStretch()
        layout.addLayout(top_layout)
        
        # AID checkboxes in grid layout (no scroll area - keeps them clickable)
        aid_layout = QGridLayout()
        aid_layout.setSpacing(10)
        
        # Define all AIDs
        self.aid_checkboxes = {}
        aids = [
            ('NO', True), ('QREPLY', True), ('ENTER', False),
            ('PF1', True), ('PF2', True), ('PF3', True), ('PF4', True),
            ('PF5', True), ('PF6', True), ('PF7', True), ('PF8', True),
            ('PF9', True), ('PF10', True), ('PF11', True), ('PF12', True),
            ('PF13', True), ('PF14', True), ('PF15', True), ('PF16', True),
            ('PF17', True), ('PF18', True), ('PF19', True), ('PF20', True),
            ('PF21', True), ('PF22', True), ('PF23', True), ('PF24', True),
            ('OICR', True), ('MSR_MHS', True), ('SELECT', True),
            ('PA1', True), ('PA2', True), ('PA3', True),
            ('CLEAR', False), ('SYSREQ', True)
        ]
        
        cols = 12
        for i, (name, default) in enumerate(aids):
            cb = QCheckBox(name)
            cb.setChecked(default)
            self.aid_checkboxes[name] = cb
            aid_layout.addWidget(cb, i // cols, i % cols)
        
        layout.addLayout(aid_layout)
        
        layout.addSpacing(20)
        self.tabs.addTab(tab, "Inject Key Presses")
    
    def create_aid_spoofing_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Controls row
        controls_layout = QHBoxLayout()
        
        # Toggle
        self.aid_spoof_toggle = QCheckBox("Spoof AID")
        self.aid_spoof_toggle.toggled.connect(self.on_aid_spoof_toggle)
        controls_layout.addWidget(self.aid_spoof_toggle)
        
        controls_layout.addSpacing(20)
        
        # Mode selection
        controls_layout.addWidget(QLabel("Mode:"))
        self.aid_mode_combo = QComboBox()
        self.aid_mode_combo.addItems(["MANUAL", "FUZZER"])
        self.aid_mode_combo.setEnabled(False)
        self.aid_mode_combo.currentTextChanged.connect(self.on_aid_mode_changed)
        controls_layout.addWidget(self.aid_mode_combo)
        
        controls_layout.addSpacing(20)
        
        # AID selection (for MANUAL mode)
        self.aid_select_label = QLabel("AID:")
        self.aid_select_label.setEnabled(False)
        controls_layout.addWidget(self.aid_select_label)
        self.aid_select_combo = QComboBox()
        self.aid_select_combo.addItems(list(libhack3270.hack3270.AIDS.keys()))
        self.aid_select_combo.setCurrentText("ENTER")
        self.aid_select_combo.setEnabled(False)
        self.aid_select_combo.currentTextChanged.connect(self.on_aid_select_changed)
        controls_layout.addWidget(self.aid_select_combo)
        
        # ARM button (for FUZZER mode)
        self.aid_arm_btn = QPushButton("ARM")
        self.aid_arm_btn.setProperty("class", "warning")
        self.aid_arm_btn.setEnabled(False)
        self.aid_arm_btn.setVisible(False)
        self.aid_arm_btn.clicked.connect(self.on_aid_arm_clicked)
        controls_layout.addWidget(self.aid_arm_btn)
        
        # STOP button (for FUZZER mode)
        self.aid_stop_btn = QPushButton("STOP")
        self.aid_stop_btn.setProperty("class", "danger")
        self.aid_stop_btn.setEnabled(False)
        self.aid_stop_btn.setVisible(False)
        self.aid_stop_btn.clicked.connect(self.on_aid_stop_clicked)
        controls_layout.addWidget(self.aid_stop_btn)
        
        # RESUME button (for FUZZER mode)
        self.aid_resume_btn = QPushButton("RESUME")
        self.aid_resume_btn.setProperty("class", "success")
        self.aid_resume_btn.setEnabled(False)
        self.aid_resume_btn.setVisible(False)
        self.aid_resume_btn.clicked.connect(self.on_aid_resume_clicked)
        controls_layout.addWidget(self.aid_resume_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Status row
        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel("Status:"))
        self.aid_status_label = QLabel("Disabled")
        self.aid_status_label.setProperty("class", "status-warning")
        status_layout.addWidget(self.aid_status_label)
        status_layout.addStretch()
        layout.addLayout(status_layout)
        
        layout.addStretch()
        self.tabs.addTab(tab, "AID Spoofing")
    
    def create_field_fuzzing_tab(self):
        """Create the Field Fuzzing tab for fuzzing discovered screen fields."""
        tab = QWidget()
        main_layout = QHBoxLayout(tab)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # ===== LEFT COLUMN: Target Fields (1/3 width, full height) =====
        self.fuzz_target_group = QGroupBox("Target Fields")
        target_layout = QVBoxLayout()
        target_layout.setSpacing(5)
        
        # Field type checkboxes
        field_type_layout = QHBoxLayout()
        self.fuzz_input_fields = QCheckBox("Input")
        self.fuzz_input_fields.setChecked(True)
        self.fuzz_protected_fields = QCheckBox("Protected")
        self.fuzz_hidden_fields = QCheckBox("Hidden")
        field_type_layout.addWidget(self.fuzz_input_fields)
        field_type_layout.addWidget(self.fuzz_protected_fields)
        field_type_layout.addWidget(self.fuzz_hidden_fields)
        target_layout.addLayout(field_type_layout)
        
        # Discover button
        discover_layout = QHBoxLayout()
        self.fuzz_discover_btn = QPushButton("Discover Fields")
        self.fuzz_discover_btn.clicked.connect(self.on_fuzz_discover_fields)
        discover_layout.addWidget(self.fuzz_discover_btn)
        self.fuzz_field_count_label = QLabel("0 fields")
        discover_layout.addWidget(self.fuzz_field_count_label)
        discover_layout.addStretch()
        target_layout.addLayout(discover_layout)
        
        # Field list (takes remaining space)
        self.fuzz_field_list = QTreeWidget()
        self.fuzz_field_list.setHeaderLabels(["#", "Type", "Addr", "Len", "Value"])
        self.fuzz_field_list.setSelectionMode(QTreeWidget.SelectionMode.MultiSelection)
        self.fuzz_field_list.header().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        target_layout.addWidget(self.fuzz_field_list, 1)  # Stretch factor 1
        
        # All/None buttons for field selection
        field_select_layout = QHBoxLayout()
        field_all_btn = QPushButton("All")
        field_all_btn.setMaximumWidth(60)
        field_all_btn.clicked.connect(self.fuzz_select_all_fields)
        field_none_btn = QPushButton("None")
        field_none_btn.setMaximumWidth(80)
        field_none_btn.clicked.connect(self.fuzz_deselect_all_fields)
        field_select_layout.addWidget(field_all_btn)
        field_select_layout.addWidget(field_none_btn)
        field_select_layout.addStretch()
        target_layout.addLayout(field_select_layout)
        
        self.fuzz_target_group.setLayout(target_layout)
        main_layout.addWidget(self.fuzz_target_group, 1)  # 1/3 weight
        
        # ===== RIGHT SIDE (2/3 width) =====
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)
        
        # ----- TOP ROW: Payload Categories | Options | Controls -----
        top_row = QHBoxLayout()
        top_row.setSpacing(10)
        
        # Payload Categories
        payload_group = QGroupBox("Payload Categories")
        payload_layout = QGridLayout()
        payload_layout.setSpacing(2)
        self.fuzz_payloads = {}
        payload_defs = [
            ('overflow', 'Buffer Overflow'),
            ('packed_decimal', 'Packed Decimal'),
            ('zoned_decimal', 'Zoned Decimal'),
            ('dates', 'Date/Time'),
            ('ebcdic_control', 'EBCDIC Control'),
            ('cics_injection', 'CICS Injection'),
            ('sql_injection', 'SQL Injection'),
            ('cobol_special', 'COBOL Special'),
            ('random_binary', 'Random Binary'),
            ('boundary', 'Boundary Test'),
        ]
        for i, (key, label) in enumerate(payload_defs):
            cb = QCheckBox(label)
            cb.setChecked(False)  # Default to unchecked
            self.fuzz_payloads[key] = cb
            payload_layout.addWidget(cb, i // 2, i % 2)
        select_layout = QHBoxLayout()
        select_all_btn = QPushButton("All")
        select_all_btn.setMaximumWidth(60)
        select_all_btn.clicked.connect(lambda: self.fuzz_set_all_payloads(True))
        deselect_all_btn = QPushButton("None")
        deselect_all_btn.setMaximumWidth(80)
        deselect_all_btn.clicked.connect(lambda: self.fuzz_set_all_payloads(False))
        select_layout.addWidget(select_all_btn)
        select_layout.addWidget(deselect_all_btn)
        select_layout.addStretch()
        payload_layout.addLayout(select_layout, (len(payload_defs) + 1) // 2, 0, 1, 2)
        payload_group.setLayout(payload_layout)
        payload_group.setMaximumWidth(200)  # Smaller width
        top_row.addWidget(payload_group)
        
        # Options
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout()
        options_layout.setSpacing(2)
        delay_layout = QHBoxLayout()
        delay_layout.addWidget(QLabel("Delay (ms):"))
        self.fuzz_delay_input = QLineEdit("300")
        self.fuzz_delay_input.setMaximumWidth(50)
        delay_layout.addWidget(self.fuzz_delay_input)
        delay_layout.addStretch()
        options_layout.addLayout(delay_layout)
        self.fuzz_stop_on_abend = QCheckBox("Stop on ABEND")
        self.fuzz_stop_on_abend.setChecked(True)
        options_layout.addWidget(self.fuzz_stop_on_abend)
        self.fuzz_stop_on_disconnect = QCheckBox("Stop on disconnect")
        self.fuzz_stop_on_disconnect.setChecked(True)
        options_layout.addWidget(self.fuzz_stop_on_disconnect)
        options_layout.addStretch()
        options_group.setLayout(options_layout)
        options_group.setMinimumWidth(250)  # Larger width
        top_row.addWidget(options_group)
        
        # Controls
        controls_group = QGroupBox("Controls")
        controls_layout = QVBoxLayout()
        controls_layout.setSpacing(3)
        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel("Status:"))
        self.fuzz_status_label = QLabel("Ready")
        self.fuzz_status_label.setProperty("class", "status-warning")
        status_layout.addWidget(self.fuzz_status_label)
        status_layout.addStretch()
        controls_layout.addLayout(status_layout)
        progress_layout = QHBoxLayout()
        progress_layout.addWidget(QLabel("Progress:"))
        self.fuzz_progress_label = QLabel("0 / 0")
        progress_layout.addWidget(self.fuzz_progress_label)
        progress_layout.addStretch()
        controls_layout.addLayout(progress_layout)
        button_layout = QGridLayout()
        self.fuzz_start_btn = QPushButton("Start")
        self.fuzz_start_btn.setProperty("class", "warning")
        self.fuzz_start_btn.clicked.connect(self.on_fuzz_start)
        button_layout.addWidget(self.fuzz_start_btn, 0, 0)
        self.fuzz_stop_btn = QPushButton("Stop")
        self.fuzz_stop_btn.setProperty("class", "danger")
        self.fuzz_stop_btn.setEnabled(False)
        self.fuzz_stop_btn.clicked.connect(self.on_fuzz_stop)
        button_layout.addWidget(self.fuzz_stop_btn, 0, 1)
        self.fuzz_pause_btn = QPushButton("Pause")
        self.fuzz_pause_btn.setEnabled(False)
        self.fuzz_pause_btn.clicked.connect(self.on_fuzz_pause)
        button_layout.addWidget(self.fuzz_pause_btn, 1, 0)
        self.fuzz_resume_btn = QPushButton("Resume")
        self.fuzz_resume_btn.setProperty("class", "success")
        self.fuzz_resume_btn.setEnabled(False)
        self.fuzz_resume_btn.clicked.connect(self.on_fuzz_resume)
        button_layout.addWidget(self.fuzz_resume_btn, 1, 1)
        controls_layout.addLayout(button_layout)
        controls_layout.addStretch()
        controls_group.setLayout(controls_layout)
        top_row.addWidget(controls_group)
        
        right_layout.addLayout(top_row)
        
        # ----- BOTTOM: Findings -----
        findings_group = QGroupBox("Findings")
        findings_layout = QVBoxLayout()
        self.fuzz_findings_tree = QTreeWidget()
        self.fuzz_findings_tree.setHeaderLabels(["#", "Field", "Payload", "Result", "Response Length"])
        self.fuzz_findings_tree.setAlternatingRowColors(True)
        self.fuzz_findings_tree.setSortingEnabled(True)
        header = self.fuzz_findings_tree.header()
        header.setMinimumSectionSize(50)  # Ensure # column is wide enough
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.fuzz_findings_tree.setColumnWidth(0, 60)  # Fixed width for # column
        findings_layout.addWidget(self.fuzz_findings_tree)
        export_layout = QHBoxLayout()
        export_layout.addStretch()
        self.fuzz_clear_btn = QPushButton("Clear Findings")
        self.fuzz_clear_btn.clicked.connect(self.on_fuzz_clear_findings)
        export_layout.addWidget(self.fuzz_clear_btn)
        self.fuzz_export_btn = QPushButton("Export CSV")
        self.fuzz_export_btn.clicked.connect(self.on_fuzz_export)
        export_layout.addWidget(self.fuzz_export_btn)
        findings_layout.addLayout(export_layout)
        findings_group.setLayout(findings_layout)
        right_layout.addWidget(findings_group, 1)  # Stretch factor 1
        
        main_layout.addWidget(right_widget, 2)  # 2/3 weight
        
        self.tabs.addTab(tab, "Field Fuzzing")
        
        # Initialize field fuzzing state
        self.fuzz_running = False
        self.fuzz_paused = False
        self.fuzz_discovered_fields = []
        self.fuzz_current_payloads = []
        self.fuzz_current_index = 0
        self.fuzz_finding_count = 0
        self.fuzz_timer = None
        self.fuzz_mode = 'field'  # Track which fuzzer is active
    
    def create_order_fuzzing_tab(self):
        """Create the Order Fuzzing tab for TN3270 protocol order injection."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # ===== TOP SECTION: Controls in Grid =====
        top_widget = QWidget()
        top_grid = QGridLayout(top_widget)
        top_grid.setContentsMargins(0, 0, 0, 0)
        top_grid.setSpacing(10)
        
        # ----- Column 0: Order Injection Types -----
        orders_group = QGroupBox("Order Injection Types")
        orders_layout = QVBoxLayout()
        orders_layout.setSpacing(2)
        self.order_payloads = {}
        order_defs = [
            ('sba', 'SBA (Set Buffer Address)'),
            ('sf', 'SF (Start Field)'),
            ('sfe', 'SFE (Start Field Extended)'),
            ('sa', 'SA (Set Attribute)'),
            ('mf', 'MF (Modify Field)'),
            ('ra', 'RA (Repeat to Address)'),
            ('eua', 'EUA (Erase Unprotected)'),
            ('ic', 'IC (Insert Cursor)'),
            ('pt', 'PT (Program Tab)'),
            ('ge', 'GE (Graphic Escape)'),
        ]
        for key, label in order_defs:
            cb = QCheckBox(label)
            cb.setChecked(True)
            self.order_payloads[key] = cb
            orders_layout.addWidget(cb)
        select_layout = QHBoxLayout()
        select_all_btn = QPushButton("All")
        select_all_btn.setMaximumWidth(60)
        select_all_btn.clicked.connect(lambda: self.order_set_all_payloads(True))
        deselect_all_btn = QPushButton("None")
        deselect_all_btn.setMaximumWidth(80)
        deselect_all_btn.clicked.connect(lambda: self.order_set_all_payloads(False))
        select_layout.addWidget(select_all_btn)
        select_layout.addWidget(deselect_all_btn)
        select_layout.addStretch()
        orders_layout.addLayout(select_layout)
        orders_group.setLayout(orders_layout)
        top_grid.addWidget(orders_group, 0, 0)
        
        # ----- Column 1: Additional Payloads -----
        extra_group = QGroupBox("Additional Payloads")
        extra_layout = QVBoxLayout()
        extra_layout.setSpacing(2)
        extra_defs = [
            ('telnet_iac', 'Telnet IAC Sequences'),
            ('attr_bytes', 'Field Attribute Bytes'),
            ('ext_attrs', 'Extended Attributes'),
            ('random_orders', 'Random Order Sequences'),
        ]
        for key, label in extra_defs:
            cb = QCheckBox(label)
            cb.setChecked(True)
            self.order_payloads[key] = cb
            extra_layout.addWidget(cb)
        extra_layout.addStretch()
        extra_group.setLayout(extra_layout)
        top_grid.addWidget(extra_group, 0, 1)
        
        # ----- Column 2: Options + Controls -----
        col2_widget = QWidget()
        col2_layout = QVBoxLayout(col2_widget)
        col2_layout.setContentsMargins(0, 0, 0, 0)
        col2_layout.setSpacing(5)
        
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout()
        options_layout.setSpacing(2)
        delay_layout = QHBoxLayout()
        delay_layout.addWidget(QLabel("Delay (ms):"))
        self.order_delay_input = QLineEdit("300")
        self.order_delay_input.setMaximumWidth(50)
        delay_layout.addWidget(self.order_delay_input)
        delay_layout.addStretch()
        options_layout.addLayout(delay_layout)
        self.order_stop_on_abend = QCheckBox("Stop on ABEND")
        self.order_stop_on_abend.setChecked(True)
        options_layout.addWidget(self.order_stop_on_abend)
        self.order_stop_on_disconnect = QCheckBox("Stop on disconnect")
        self.order_stop_on_disconnect.setChecked(True)
        options_layout.addWidget(self.order_stop_on_disconnect)
        options_group.setLayout(options_layout)
        col2_layout.addWidget(options_group)
        
        controls_group = QGroupBox("Controls")
        controls_layout = QVBoxLayout()
        controls_layout.setSpacing(3)
        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel("Status:"))
        self.order_status_label = QLabel("Ready")
        self.order_status_label.setProperty("class", "status-warning")
        status_layout.addWidget(self.order_status_label)
        status_layout.addStretch()
        controls_layout.addLayout(status_layout)
        progress_layout = QHBoxLayout()
        progress_layout.addWidget(QLabel("Progress:"))
        self.order_progress_label = QLabel("0 / 0")
        progress_layout.addWidget(self.order_progress_label)
        progress_layout.addStretch()
        controls_layout.addLayout(progress_layout)
        button_layout = QGridLayout()
        self.order_start_btn = QPushButton("Start")
        self.order_start_btn.setProperty("class", "warning")
        self.order_start_btn.clicked.connect(self.on_order_fuzz_start)
        button_layout.addWidget(self.order_start_btn, 0, 0)
        self.order_stop_btn = QPushButton("Stop")
        self.order_stop_btn.setProperty("class", "danger")
        self.order_stop_btn.setEnabled(False)
        self.order_stop_btn.clicked.connect(self.on_order_fuzz_stop)
        button_layout.addWidget(self.order_stop_btn, 0, 1)
        self.order_pause_btn = QPushButton("Pause")
        self.order_pause_btn.setEnabled(False)
        self.order_pause_btn.clicked.connect(self.on_order_fuzz_pause)
        button_layout.addWidget(self.order_pause_btn, 1, 0)
        self.order_resume_btn = QPushButton("Resume")
        self.order_resume_btn.setProperty("class", "success")
        self.order_resume_btn.setEnabled(False)
        self.order_resume_btn.clicked.connect(self.on_order_fuzz_resume)
        button_layout.addWidget(self.order_resume_btn, 1, 1)
        controls_layout.addLayout(button_layout)
        controls_group.setLayout(controls_layout)
        col2_layout.addWidget(controls_group)
        col2_layout.addStretch()
        
        top_grid.addWidget(col2_widget, 0, 2)
        top_grid.setColumnStretch(0, 1)
        top_grid.setColumnStretch(1, 1)
        top_grid.setColumnStretch(2, 1)
        layout.addWidget(top_widget)
        
        # ===== BOTTOM: Findings =====
        findings_group = QGroupBox("Findings")
        findings_layout = QVBoxLayout()
        self.order_findings_tree = QTreeWidget()
        self.order_findings_tree.setHeaderLabels(["#", "Order", "Payload", "Result", "Response Length"])
        self.order_findings_tree.setAlternatingRowColors(True)
        self.order_findings_tree.setSortingEnabled(True)
        header = self.order_findings_tree.header()
        header.setMinimumSectionSize(50)  # Ensure # column is wide enough
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.order_findings_tree.setColumnWidth(0, 60)  # Fixed width for # column
        findings_layout.addWidget(self.order_findings_tree)
        export_layout = QHBoxLayout()
        export_layout.addStretch()
        self.order_clear_btn = QPushButton("Clear Findings")
        self.order_clear_btn.clicked.connect(self.on_order_clear_findings)
        export_layout.addWidget(self.order_clear_btn)
        self.order_export_btn = QPushButton("Export CSV")
        self.order_export_btn.clicked.connect(self.on_order_export)
        export_layout.addWidget(self.order_export_btn)
        findings_layout.addLayout(export_layout)
        findings_group.setLayout(findings_layout)
        layout.addWidget(findings_group, 1)
        
        self.tabs.addTab(tab, "Order Fuzzing")
        
        # Initialize order fuzzing state
        self.order_running = False
        self.order_paused = False
        self.order_current_payloads = []
        self.order_current_index = 0
        self.order_finding_count = 0
        self.order_timer = None
        
    def create_logs_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Tree widget
        self.log_tree = QTreeWidget()
        self.log_tree.setHeaderLabels(["ID", "Timestamp", "Delta (ms)", "Sender", "Length", "Notes"])
        self.log_tree.setAlternatingRowColors(True)
        self.log_tree.header().setSectionResizeMode(5, QHeaderView.Stretch)  # Notes column stretches
        self.log_tree.itemSelectionChanged.connect(self.fetch_item)
        layout.addWidget(self.log_tree, 1)

        # Detail text (must be defined before update_logs_tab since fetch_item uses it)
        self.log_detail = QTextEdit()
        self.log_detail.setReadOnly(True)
        self.log_detail.setMaximumHeight(200)
        layout.addWidget(self.log_detail)

        self.update_logs_tab()
        
        # Enable sorting AFTER data is loaded, sort by ID ascending (1 at top, newest at bottom)
        self.log_tree.setSortingEnabled(True)
        self.log_tree.sortByColumn(0, Qt.AscendingOrder)
        # Note: Initial scroll to last item is done in on_tab_changed when Logs tab is first shown
        
        # Bottom controls
        bottom_layout = QHBoxLayout()
        self.auto_server_cb = QCheckBox("Auto Send Server")
        self.auto_server_cb.setChecked(True)
        bottom_layout.addWidget(self.auto_server_cb)
        
        self.auto_client_cb = QCheckBox("Auto Send Client")
        bottom_layout.addWidget(self.auto_client_cb)
        
        bottom_layout.addSpacing(30)
        
        # Search field - converts ASCII to EBCDIC and filters logs
        bottom_layout.addWidget(QLabel("Search:"))
        self.log_search_field = QLineEdit()
        self.log_search_field.setPlaceholderText("ASCII → EBCDIC filter")
        self.log_search_field.setMinimumWidth(200)
        self.log_search_field.returnPressed.connect(self.filter_logs)  # Enter key triggers search
        bottom_layout.addWidget(self.log_search_field)
        
        search_btn = QPushButton("Search")
        search_btn.clicked.connect(self.filter_logs)
        bottom_layout.addWidget(search_btn)
        
        clear_search_btn = QPushButton("Clear")
        clear_search_btn.clicked.connect(self.clear_log_search)
        bottom_layout.addWidget(clear_search_btn)
        
        bottom_layout.addSpacing(20)
        
        export_btn = QPushButton("Export All")
        export_btn.clicked.connect(self.export_csv)
        bottom_layout.addWidget(export_btn)
        
        export_visible_btn = QPushButton("Export Visible")
        export_visible_btn.clicked.connect(self.export_visible_csv)
        bottom_layout.addWidget(export_visible_btn)
        
        self.export_label = QLabel("Ready.")
        self.export_label.setProperty("class", "status-ready")
        bottom_layout.addWidget(self.export_label)
        
        bottom_layout.addStretch()
        
        # Follow button - auto-scroll to latest log entry
        self.log_follow_btn = QPushButton("Follow: OFF")
        self.log_follow_btn.setCheckable(True)
        self.log_follow_btn.setProperty("class", "")
        self.log_follow_btn.clicked.connect(self.toggle_log_follow)
        bottom_layout.addWidget(self.log_follow_btn)
        
        layout.addLayout(bottom_layout)
        
        self.tabs.addTab(tab, "Logs")
        
    def create_statistics_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Refresh button at top
        top_layout = QHBoxLayout()
        refresh_btn = QPushButton("Refresh Statistics")
        refresh_btn.setProperty("class", "success")
        refresh_btn.clicked.connect(self.refresh_statistics)
        top_layout.addWidget(refresh_btn)
        self.stats_status_label = QLabel("Ready")
        top_layout.addWidget(self.stats_status_label)
        top_layout.addStretch()
        layout.addLayout(top_layout)
        
        # Scroll area for all stats
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        scroll_layout.setSpacing(10)
        
        # Main grid for stats groups (3x3)
        main_grid = QGridLayout()
        main_grid.setSpacing(10)
        
        # Store labels for refresh
        self.stats_labels = {}
        
        # === Row 0: Connection | Traffic | Hack Operations ===
        conn_group = QGroupBox("Connection")
        conn_layout = QGridLayout(conn_group)
        conn_layout.setSpacing(5)
        self._add_stat_row(conn_layout, 0, "Server:", "stats_server", "---")
        self._add_stat_row(conn_layout, 1, "TLS:", "stats_tls", "---")
        self._add_stat_row(conn_layout, 2, "Protocol:", "stats_protocol", "---")
        self._add_stat_row(conn_layout, 3, "TCP Sessions:", "stats_sessions", "0")
        self._add_stat_row(conn_layout, 4, "Session Time:", "stats_time", "00:00:00")
        main_grid.addWidget(conn_group, 0, 0)
        
        traffic_group = QGroupBox("Traffic")
        traffic_layout = QGridLayout(traffic_group)
        traffic_layout.setSpacing(5)
        self._add_stat_row(traffic_layout, 0, "Server Messages:", "stats_server_msgs", "0")
        self._add_stat_row(traffic_layout, 1, "Server Bytes:", "stats_server_bytes", "0")
        self._add_stat_row(traffic_layout, 2, "Client Messages:", "stats_client_msgs", "0")
        self._add_stat_row(traffic_layout, 3, "Client Bytes:", "stats_client_bytes", "0")
        self._add_stat_row(traffic_layout, 4, "Avg Resp/Req:", "stats_avg_size", "0B / 0B")
        main_grid.addWidget(traffic_group, 0, 1)
        
        hack_group = QGroupBox("Hack Operations")
        hack_layout = QGridLayout(hack_group)
        hack_layout.setSpacing(5)
        self._add_stat_row(hack_layout, 0, "Field Hacks:", "stats_field_hacks", "0")
        self._add_stat_row(hack_layout, 1, "Color Hacks:", "stats_color_hacks", "0")
        self._add_stat_row(hack_layout, 2, "Toggle Events:", "stats_hack_toggles", "0")
        self._add_stat_row(hack_layout, 3, "TN3270 Negotiations:", "stats_negotiations", "0")
        main_grid.addWidget(hack_group, 0, 2)
        
        # === Row 1: Hidden Fields | AID Injection | Field Injection ===
        hidden_group = QGroupBox("Hidden Field Analysis")
        hidden_layout = QGridLayout(hidden_group)
        hidden_layout.setSpacing(5)
        self._add_stat_row(hidden_layout, 0, "Fields Detected:", "stats_hidden_detected", "0")
        self._add_stat_row(hidden_layout, 1, "Fields with Data:", "stats_hidden_with_data", "0")
        self._add_stat_row(hidden_layout, 2, "Screens w/ Hidden:", "stats_screens_hidden", "0")
        main_grid.addWidget(hidden_group, 1, 0)
        
        aid_group = QGroupBox("AID Injection")
        aid_layout = QGridLayout(aid_group)
        aid_layout.setSpacing(5)
        self._add_stat_row(aid_layout, 0, "Inject Keys Tab:", "stats_inject_keys", "0")
        self._add_stat_row(aid_layout, 1, "AID Spoofing:", "stats_aid_spoof", "0")
        self._add_stat_row(aid_layout, 2, "AID Fuzzer:", "stats_aid_fuzz", "0")
        self._add_stat_row(aid_layout, 3, "API: Send AID:", "stats_api_aid", "0")
        self._add_stat_row(aid_layout, 4, "Total:", "stats_total_aid", "0")
        main_grid.addWidget(aid_group, 1, 1)
        
        field_group = QGroupBox("Field Injection")
        field_layout = QGridLayout(field_group)
        field_layout.setSpacing(5)
        self._add_stat_row(field_layout, 0, "API: Send Field:", "stats_api_field", "0")
        self._add_stat_row(field_layout, 1, "API: Send Cmd:", "stats_api_command", "0")
        self._add_stat_row(field_layout, 2, "API: Replay:", "stats_api_replay", "0")
        self._add_stat_row(field_layout, 3, "Mask Captures:", "stats_mask_captures", "0")
        self._add_stat_row(field_layout, 4, "Total:", "stats_total_field", "0")
        main_grid.addWidget(field_group, 1, 2)
        
        # === Row 2: Fuzzing Activity | Fuzzing Results | Top ABEND Causes ===
        fuzz_act_group = QGroupBox("Fuzzing Activity")
        fuzz_act_layout = QGridLayout(fuzz_act_group)
        fuzz_act_layout.setSpacing(5)
        self._add_stat_row(fuzz_act_layout, 0, "Field Fuzzing:", "stats_fuzz_field", "0")
        self._add_stat_row(fuzz_act_layout, 1, "Order Fuzzing:", "stats_fuzz_order", "0")
        self._add_stat_row(fuzz_act_layout, 2, "Brute Force:", "stats_brute", "0")
        self._add_stat_row(fuzz_act_layout, 3, "GUI Fuzz:", "stats_gui_fuzz", "0")
        self._add_stat_row(fuzz_act_layout, 4, "Total:", "stats_total_fuzz", "0")
        main_grid.addWidget(fuzz_act_group, 2, 0)
        
        fuzz_res_group = QGroupBox("Fuzzing Results")
        fuzz_res_layout = QGridLayout(fuzz_res_group)
        fuzz_res_layout.setSpacing(5)
        self._add_stat_row(fuzz_res_layout, 0, "ABENDs:", "stats_abends", "0")
        self._add_stat_row(fuzz_res_layout, 1, "Errors:", "stats_errors", "0")
        self._add_stat_row(fuzz_res_layout, 2, "Unique Crashes:", "stats_unique_crashes", "0")
        self._add_stat_row(fuzz_res_layout, 3, "ABEND Rate:", "stats_abend_rate", "0.0%")
        main_grid.addWidget(fuzz_res_group, 2, 1)
        
        abend_group = QGroupBox("Top ABEND Causes")
        abend_layout = QVBoxLayout(abend_group)
        self.stats_abend_list = QLabel("Click Refresh")
        self.stats_abend_list.setWordWrap(True)
        abend_layout.addWidget(self.stats_abend_list)
        main_grid.addWidget(abend_group, 2, 2)
        
        # Set column stretches for even distribution
        main_grid.setColumnStretch(0, 1)
        main_grid.setColumnStretch(1, 1)
        main_grid.setColumnStretch(2, 1)
        
        scroll_layout.addLayout(main_grid)
        
        scroll_layout.addStretch()
        scroll.setWidget(scroll_widget)
        layout.addWidget(scroll, 1)
        
        self.tabs.addTab(tab, "Statistics")
    
    def _add_stat_row(self, layout, row, label_text, key, default_value):
        """Helper to add a statistics row with label and value."""
        lbl = QLabel(label_text)
        lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        layout.addWidget(lbl, row, 0)
        
        val = QLabel(default_value)
        val.setProperty("class", "status-info")
        layout.addWidget(val, row, 1)
        self.stats_labels[key] = val
    
    def refresh_statistics(self):
        """Recalculate all statistics from the database."""
        import re
        from collections import defaultdict
        
        self.stats_status_label.setText("Calculating...")
        QApplication.processEvents()
        
        # Initialize counters
        server_messages = 0
        server_bytes = 0
        client_messages = 0
        client_bytes = 0
        negotiations = 0
        sessions = 0
        total_time = 0.0
        last_timestamp = 0.0
        start_timestamp = 0.0
        
        # Hack operations
        field_hacks_enabled = 0
        color_hacks_enabled = 0
        hack_toggles = 0
        
        # Hidden fields
        hidden_detected = 0
        hidden_with_data = 0
        screens_with_hidden = set()
        
        # AID injection
        inject_keys = 0
        aid_spoof = 0
        aid_fuzz = 0
        api_aid = 0
        
        # Field injection
        api_field = 0
        api_command = 0
        api_replay = 0
        mask_captures = 0
        
        # Fuzzing
        fuzz_field = 0
        fuzz_order = 0
        brute_force = 0
        gui_fuzz = 0
        
        # Results
        abends = 0
        errors = 0
        abend_causes = defaultdict(int)
        
        # ABEND patterns (in EBCDIC)
        ABEND_PATTERNS = ['APCT', 'SOC7', 'ASRA', 'AICA', 'ASRB', 'SOC4', 'AEY9']
        ERROR_PATTERNS = ['NOT FOUND', 'UNDEFINED', 'UNKNOWN', 'INVALID', 'ERROR']
        
        # Process all logs
        all_logs = list(self.hack3270.all_logs())
        
        for i, record in enumerate(all_logs):
            try:
                record_id = record[0]
                timestamp = float(record[1])
                direction = record[2]
                notes = record[3] if record[3] else ""
                data_len = record[4]
                raw_data = record[5] if len(record) > 5 else b''
                
                # Traffic stats
                if direction == 'S':
                    server_messages += 1
                    server_bytes += data_len
                else:
                    client_messages += 1
                    client_bytes += data_len
                
                # TN3270 negotiation
                if 'tn3270 negotiation' in notes.lower():
                    negotiations += 1
                
                # Session detection (small server response typically = new connection)
                if direction == 'S' and data_len == 3:
                    sessions += 1
                    start_timestamp = timestamp
                    if last_timestamp > 0:
                        total_time += start_timestamp - last_timestamp
                else:
                    last_timestamp = timestamp
                
                # Hack operations
                if 'Hack Field Attributes: ENABLED' in notes or 'Hack Field Attributes: TOGGLED ON' in notes:
                    field_hacks_enabled += 1
                if 'Hack Text Color: ENABLED' in notes or 'Hack Text Color: TOGGLED ON' in notes:
                    color_hacks_enabled += 1
                if 'TOGGLED' in notes:
                    hack_toggles += 1
                
                # Hidden field detection - parse 3270 data stream for hidden fields
                if direction == 'S' and raw_data and len(raw_data) > 10:
                    try:
                        # Parse for SF (0x1D) and SFE (0x29) orders with hidden attribute
                        j = 0
                        screen_has_hidden = False
                        while j < len(raw_data) - 1:
                            byte = raw_data[j]
                            if byte == 0x1D:  # SF - Start Field
                                attr = raw_data[j + 1] if j + 1 < len(raw_data) else 0
                                if (attr & 0x0C) == 0x0C:  # Hidden bits set
                                    hidden_detected += 1
                                    screen_has_hidden = True
                                    # Check if there's data after this field
                                    data_start = j + 2
                                    data_end = data_start
                                    while data_end < len(raw_data) and raw_data[data_end] not in [0x1D, 0x29, 0x11]:
                                        data_end += 1
                                    if data_end > data_start:
                                        field_data = raw_data[data_start:data_end]
                                        # Check if it has non-null data
                                        if any(b != 0x00 and b != 0x40 for b in field_data):
                                            hidden_with_data += 1
                                j += 2
                            elif byte == 0x29:  # SFE - Start Field Extended
                                if j + 1 < len(raw_data):
                                    count = raw_data[j + 1]
                                    if j + 2 + count * 2 <= len(raw_data):
                                        for k in range(count):
                                            attr_type = raw_data[j + 2 + k * 2]
                                            attr_value = raw_data[j + 3 + k * 2]
                                            if attr_type == 0xC0 and (attr_value & 0x0C) == 0x0C:
                                                hidden_detected += 1
                                                screen_has_hidden = True
                                        j += 2 + count * 2
                                    else:
                                        j += 1
                                else:
                                    j += 1
                            else:
                                j += 1
                        if screen_has_hidden:
                            screens_with_hidden.add(record_id)
                    except:
                        pass
                
                # AID injection
                if 'Sending key:' in notes:
                    inject_keys += 1
                if 'AID Spoofed:' in notes:
                    aid_spoof += 1
                if 'AID Fuzz:' in notes:
                    aid_fuzz += 1
                if 'API: Send AID' in notes:
                    api_aid += 1
                
                # Field injection
                if 'API: Send field' in notes:
                    api_field += 1
                if 'API: Send command' in notes:
                    api_command += 1
                if 'API: Replay' in notes:
                    api_replay += 1
                if 'Inject setup - Mask:' in notes and 'Length:' in notes:
                    mask_captures += 1
                
                # Fuzzing activity
                if notes.startswith('Fuzz:'):
                    if '/Order' in notes or 'Order/' in notes:
                        fuzz_order += 1
                    else:
                        fuzz_field += 1
                if notes.startswith('Brute:'):
                    brute_force += 1
                if notes.startswith('GUI: Fuzz'):
                    gui_fuzz += 1
                
                # ABEND detection in server responses
                if direction == 'S' and raw_data:
                    for pattern in ABEND_PATTERNS:
                        try:
                            ebcdic_pattern = pattern.encode('cp500')
                            if ebcdic_pattern in raw_data:
                                abends += 1
                                # Find causing payload
                                if i > 0:
                                    prev_notes = all_logs[i-1][3] if all_logs[i-1][3] else ""
                                    if prev_notes.startswith('Fuzz:'):
                                        # Extract category
                                        if 'OVF' in prev_notes:
                                            abend_causes['Buffer Overflow'] += 1
                                        elif 'Order/' in prev_notes:
                                            abend_causes['Order Injection'] += 1
                                        elif 'RANDOM' in prev_notes:
                                            abend_causes['Random Binary'] += 1
                                        elif 'BOUND' in prev_notes:
                                            abend_causes['Boundary Test'] += 1
                                        elif 'CICS' in prev_notes:
                                            abend_causes['CICS Injection'] += 1
                                        elif 'COMP3' in prev_notes:
                                            abend_causes['Packed Decimal'] += 1
                                        else:
                                            abend_causes['Other'] += 1
                                    else:
                                        abend_causes['Unknown'] += 1
                                break
                        except:
                            pass
                    
                    # Error detection
                    for pattern in ERROR_PATTERNS:
                        try:
                            ebcdic_pattern = pattern.encode('cp500')
                            if ebcdic_pattern in raw_data:
                                errors += 1
                                break
                        except:
                            pass
                            
            except Exception as e:
                continue
        
        total_time += start_timestamp - last_timestamp if last_timestamp > 0 else 0
        
        # Update UI
        ip, port = self.hack3270.get_ip_port()
        self.stats_labels['stats_server'].setText(f"{ip}:{port}")
        self.stats_labels['stats_tls'].setText("Yes" if self.hack3270.get_tls() else "No")
        self.stats_labels['stats_protocol'].setText("TN3270E" if self.hack3270.check_inject_3270e() else "TN3270")
        self.stats_labels['stats_sessions'].setText(str(sessions))
        self.stats_labels['stats_time'].setText(self.get_elapsed_time(abs(total_time)))
        
        self.stats_labels['stats_server_msgs'].setText(f"{server_messages:,}")
        self.stats_labels['stats_server_bytes'].setText(f"{server_bytes:,}")
        self.stats_labels['stats_client_msgs'].setText(f"{client_messages:,}")
        self.stats_labels['stats_client_bytes'].setText(f"{client_bytes:,}")
        self.stats_labels['stats_negotiations'].setText(str(negotiations))
        avg_resp = server_bytes // server_messages if server_messages > 0 else 0
        avg_req = client_bytes // client_messages if client_messages > 0 else 0
        self.stats_labels['stats_avg_size'].setText(f"{avg_resp}B / {avg_req}B")
        
        self.stats_labels['stats_field_hacks'].setText(str(field_hacks_enabled))
        self.stats_labels['stats_color_hacks'].setText(str(color_hacks_enabled))
        self.stats_labels['stats_hack_toggles'].setText(str(hack_toggles))
        
        self.stats_labels['stats_hidden_detected'].setText(str(hidden_detected))
        self.stats_labels['stats_hidden_with_data'].setText(str(hidden_with_data))
        self.stats_labels['stats_screens_hidden'].setText(str(len(screens_with_hidden)))
        
        self.stats_labels['stats_inject_keys'].setText(str(inject_keys))
        self.stats_labels['stats_aid_spoof'].setText(str(aid_spoof))
        self.stats_labels['stats_aid_fuzz'].setText(str(aid_fuzz))
        self.stats_labels['stats_api_aid'].setText(str(api_aid))
        total_aid = inject_keys + aid_spoof + aid_fuzz + api_aid
        self.stats_labels['stats_total_aid'].setText(str(total_aid))
        
        self.stats_labels['stats_api_field'].setText(str(api_field))
        self.stats_labels['stats_api_command'].setText(str(api_command))
        self.stats_labels['stats_api_replay'].setText(str(api_replay))
        self.stats_labels['stats_mask_captures'].setText(str(mask_captures))
        total_field = api_field + api_command + api_replay
        self.stats_labels['stats_total_field'].setText(str(total_field))
        
        self.stats_labels['stats_fuzz_field'].setText(str(fuzz_field))
        self.stats_labels['stats_fuzz_order'].setText(str(fuzz_order))
        self.stats_labels['stats_brute'].setText(str(brute_force))
        self.stats_labels['stats_gui_fuzz'].setText(str(gui_fuzz))
        total_fuzz = fuzz_field + fuzz_order + brute_force + gui_fuzz
        self.stats_labels['stats_total_fuzz'].setText(str(total_fuzz))
        
        self.stats_labels['stats_abends'].setText(str(abends))
        self.stats_labels['stats_errors'].setText(str(errors))
        self.stats_labels['stats_unique_crashes'].setText(str(len(abend_causes)))
        abend_rate = (abends * 100 / total_fuzz) if total_fuzz > 0 else 0
        self.stats_labels['stats_abend_rate'].setText(f"{abend_rate:.1f}%")
        
        # Top ABEND causes
        if abend_causes:
            sorted_causes = sorted(abend_causes.items(), key=lambda x: -x[1])
            cause_lines = []
            for i, (cause, count) in enumerate(sorted_causes[:5], 1):
                pct = count * 100 / abends if abends > 0 else 0
                cause_lines.append(f"{i}. {cause}: {count} ({pct:.1f}%)")
            self.stats_abend_list.setText("\n".join(cause_lines))
        else:
            self.stats_abend_list.setText("No ABENDs detected in this session.")
        
        self.stats_status_label.setText(f"Updated - {len(all_logs)} log entries analyzed")
    
    def create_analysis_tab(self):
        """Create the Analysis tab for detecting injection anomalies."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Controls row
        controls_layout = QHBoxLayout()
        
        # Analyze button
        analyze_btn = QPushButton("Analyze Logs")
        analyze_btn.setProperty("class", "success")
        analyze_btn.clicked.connect(self.run_analysis)
        controls_layout.addWidget(analyze_btn)
        
        controls_layout.addSpacing(10)
        
        self.analysis_status = QLabel("Ready")
        controls_layout.addWidget(self.analysis_status)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Results tree
        self.analysis_tree = QTreeWidget()
        self.analysis_tree.setHeaderLabels([
            "Type", "Req", "Resp", "Value/Key", "Len", "Finding"
        ])
        self.analysis_tree.setAlternatingRowColors(True)
        self.analysis_tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.analysis_tree.header().setSectionResizeMode(5, QHeaderView.Stretch)
        # Center align Req and Resp header labels
        self.analysis_tree.headerItem().setTextAlignment(1, Qt.AlignCenter)
        self.analysis_tree.headerItem().setTextAlignment(2, Qt.AlignCenter)
        self.analysis_tree.itemSelectionChanged.connect(self.analysis_item_selected)
        layout.addWidget(self.analysis_tree, 1)
        
        # Detail view
        self.analysis_detail = QTextEdit()
        self.analysis_detail.setReadOnly(True)
        self.analysis_detail.setMaximumHeight(200)
        layout.addWidget(self.analysis_detail)
        
        # Bottom controls (like Logs tab)
        bottom_layout = QHBoxLayout()
        self.analysis_auto_server_cb = QCheckBox("Auto Send Server")
        self.analysis_auto_server_cb.setChecked(True)
        bottom_layout.addWidget(self.analysis_auto_server_cb)
        
        self.analysis_auto_client_cb = QCheckBox("Auto Send Client")
        bottom_layout.addWidget(self.analysis_auto_client_cb)
        
        bottom_layout.addSpacing(20)
        
        analysis_export_btn = QPushButton("Export CSV")
        analysis_export_btn.clicked.connect(self.export_analysis_csv)
        bottom_layout.addWidget(analysis_export_btn)
        
        self.analysis_export_label = QLabel("")
        bottom_layout.addWidget(self.analysis_export_label)
        
        bottom_layout.addStretch()
        layout.addLayout(bottom_layout)
        
        self.tabs.addTab(tab, "Analysis")
    
    def run_analysis(self):
        """Scan logs for hidden fields and injection transitions."""
        self.analysis_tree.clear()
        self.analysis_status.setText("Analyzing...")
        QApplication.processEvents()
        
        # Get all logs
        all_logs = self.hack3270.all_logs()
        if not all_logs:
            self.analysis_status.setText("No logs to analyze.")
            return
        
        from collections import Counter
        
        # Patterns for detection
        HIDDEN_FIELD_PATTERN = r'\[Highlighting - Default\]\[Highlighting - Reverse\]\[Color - Yellow\]([^\[\]]+)'
        HACK_FIELDS_ENABLED = r'Hack Field Attributes.*Show Hidden:\s*1'
        # Match: "Sending key: PA3", "AID Fuzz: 107/255 (0x6B - PA3)", "AID Spoofed: ENTER -> PA3"
        KEY_INJECTION_PATTERN = r'Sending key:\s*(.+)'
        AID_FUZZ_PATTERN = r'AID Fuzz:\s*\d+/\d+\s*\([^-]+-\s*([^)]+)\)'
        AID_SPOOF_PATTERN = r'AID Spoofed:\s*\w+\s*->\s*(\w+)'
        FIELD_INJECTION_PATTERN = r'Sending:\s*(.+)'
        # Match: "Fuzz: target/payload" or "Brute: value"
        FUZZ_PATTERN = r'^Fuzz:\s*(.+)/(.+)$'
        BRUTE_PATTERN = r'^Brute:\s*(.+)$'
        # Abend patterns
        ABEND_PATTERNS = [
            (r'DFHAC2\d{3}', 'CICS Abend'),
            (r'ABEND\s+\w+', 'Abend'),
            (r'\bASRA\b', 'ASRA'),
            (r'\bAICA\b', 'AICA'),
            (r'\bAEY7\b', 'AEY7'),
            (r'\bAEY9\b', 'AEY9'),
            (r'\bAPCT\b', 'APCT'),
            (r'\bSOC7\b', 'SOC7'),
            (r'\bSOC4\b', 'SOC4'),
            (r'\bSOC1\b', 'SOC1'),
        ]
        # Error patterns
        ERROR_PATTERNS = [
            (r'NOT\s+FOUND', 'NOT FOUND'),
            (r'UNDEFINED', 'UNDEFINED'),
            (r'UNKNOWN\s+TRANSACTION', 'UNKNOWN TRANSACTION'),
        ]
        
        hidden_values = 0
        hidden_labels = 0
        key_transitions = 0
        field_transitions = 0
        fuzz_abends = 0
        fuzz_errors = 0
        
        # ===== HIDDEN FIELD ANALYSIS =====
        for record in all_logs:
            record_id = record[0]
            sender = record[2]
            notes = record[3]
            data = self.hack3270.parse_3270(self.hack3270.get_ascii(record[5])) if record[5] else ""
            
            # Only check server responses with Hack Fields enabled
            if sender == 'S' and re.search(HACK_FIELDS_ENABLED, notes):
                matches = re.findall(HIDDEN_FIELD_PATTERN, data)
                for match in matches:
                    content = match.strip()
                    if not content:
                        continue
                    
                    # Determine if label or value
                    if content.endswith(':'):
                        hidden_labels += 1
                        item = AnalysisTreeWidgetItem([
                            "Hidden",
                            str(record_id),
                            str(record_id),
                            content.rstrip(':')[:15],
                            str(record[4]),
                            f"Label: {content.rstrip(':')}"
                        ])
                        item.setForeground(5, QColor("#ffd93d"))  # Yellow
                    else:
                        hidden_values += 1
                        item = AnalysisTreeWidgetItem([
                            "Hidden",
                            str(record_id),
                            str(record_id),
                            content[:15],
                            str(record[4]),
                            f"VALUE: {content}"
                        ])
                        item.setForeground(0, QColor("#ff6b6b"))  # Red
                        item.setForeground(5, QColor("#ff6b6b"))
                    
                    # Center align Req and Resp columns
                    item.setTextAlignment(1, Qt.AlignCenter)
                    item.setTextAlignment(2, Qt.AlignCenter)
                    self.analysis_tree.addTopLevelItem(item)
        
        # ===== KEY INJECTION (AID) ANALYSIS =====
        # Detect: Sending key, AID Fuzz, AID Spoof
        key_injections = []
        for i, record in enumerate(all_logs):
            if record[2] == 'C':  # Client
                key_name = None
                
                # Try each pattern
                match = re.search(KEY_INJECTION_PATTERN, record[3])
                if match:
                    key_name = match.group(1).strip()
                else:
                    match = re.search(AID_FUZZ_PATTERN, record[3])
                    if match:
                        key_name = match.group(1).strip()
                    else:
                        match = re.search(AID_SPOOF_PATTERN, record[3])
                        if match:
                            key_name = match.group(1).strip()
                
                if key_name:
                    # Find next server response
                    for j in range(i + 1, min(i + 5, len(all_logs))):
                        if all_logs[j][2] == 'S':
                            key_injections.append({
                                'request_id': record[0],
                                'timestamp': float(record[1]),
                                'response_id': all_logs[j][0],
                                'key': key_name,
                                'length': all_logs[j][4]
                            })
                            break
        
        # Group key injections by timing (< 2 seconds apart = same sequence)
        key_sequences = []
        if key_injections:
            current_seq = [key_injections[0]]
            for i in range(1, len(key_injections)):
                if key_injections[i]['timestamp'] - key_injections[i-1]['timestamp'] < 2.0:
                    current_seq.append(key_injections[i])
                else:
                    if len(current_seq) >= 2:
                        key_sequences.append(current_seq)
                    current_seq = [key_injections[i]]
            if len(current_seq) >= 2:
                key_sequences.append(current_seq)
        
        # Analyze each key sequence for length transitions
        for sequence in key_sequences:
            lengths = [e['length'] for e in sequence]
            mode_length = Counter(lengths).most_common(1)[0][0]
            
            prev_entry = None
            prev_was_normal = True
            
            for entry in sequence:
                is_anomaly = entry['length'] != mode_length
                
                if prev_entry and prev_was_normal and is_anomaly:
                    key_transitions += 1
                    diff = entry['length'] - mode_length
                    diff_str = f"+{diff}" if diff > 0 else str(diff)
                    
                    # Single combined entry showing the transition
                    item = AnalysisTreeWidgetItem([
                        "AID",
                        str(entry['request_id']),
                        str(entry['response_id']),
                        entry['key'],
                        str(entry['length']),
                        f"{prev_entry['key']}({mode_length}) -> {entry['key']}({entry['length']}) [{diff_str}]"
                    ])
                    item.setForeground(0, QColor("#6bcb77"))  # Green
                    item.setForeground(5, QColor("#6bcb77"))
                    # Center align Req and Resp columns
                    item.setTextAlignment(1, Qt.AlignCenter)
                    item.setTextAlignment(2, Qt.AlignCenter)
                    self.analysis_tree.addTopLevelItem(item)
                
                prev_entry = entry
                prev_was_normal = not is_anomaly
        
        # ===== FIELD INJECTION ANALYSIS =====
        field_injections = []
        for i, record in enumerate(all_logs):
            if record[2] == 'C':  # Client
                match = re.search(FIELD_INJECTION_PATTERN, record[3])
                if match:
                    value = match.group(1).strip()
                    # Find next server response
                    for j in range(i + 1, min(i + 5, len(all_logs))):
                        if all_logs[j][2] == 'S':
                            # Get parsed response for content comparison
                            resp_data = self.hack3270.parse_3270(
                                self.hack3270.get_ascii(all_logs[j][5])
                            ) if all_logs[j][5] else ""
                            field_injections.append({
                                'request_id': record[0],
                                'timestamp': float(record[1]),
                                'response_id': all_logs[j][0],
                                'value': value,
                                'length': all_logs[j][4],
                                'data': resp_data
                            })
                            break
        
        # Group field injections by timing
        field_sequences = []
        if field_injections:
            current_seq = [field_injections[0]]
            for i in range(1, len(field_injections)):
                if field_injections[i]['timestamp'] - field_injections[i-1]['timestamp'] < 2.0:
                    current_seq.append(field_injections[i])
                else:
                    if len(current_seq) >= 2:
                        field_sequences.append(current_seq)
                    current_seq = [field_injections[i]]
            if len(current_seq) >= 2:
                field_sequences.append(current_seq)
        
        # Analyze each field sequence for content transitions
        for sequence in field_sequences:
            # Normalize responses by removing echoed injected value
            for entry in sequence:
                entry['normalized'] = entry['data'].replace(entry['value'], '<<INJ>>')
            
            # Find mode (most common normalized response)
            response_counts = Counter(e['normalized'] for e in sequence)
            baseline = response_counts.most_common(1)[0][0]
            mode_count = response_counts.most_common(1)[0][1]
            
            prev_entry = None
            prev_was_normal = True
            
            for entry in sequence:
                is_anomaly = entry['normalized'] != baseline
                
                if prev_entry and prev_was_normal and is_anomaly:
                    field_transitions += 1
                    
                    # Single combined entry showing the transition
                    item = AnalysisTreeWidgetItem([
                        "Field",
                        str(entry['request_id']),
                        str(entry['response_id']),
                        entry['value'],
                        str(entry['length']),
                        f"{prev_entry['value']} -> {entry['value']} (content changed)"
                    ])
                    item.setForeground(0, QColor("#ff6b6b"))  # Red
                    item.setForeground(5, QColor("#ff6b6b"))
                    # Center align Req and Resp columns
                    item.setTextAlignment(1, Qt.AlignCenter)
                    item.setTextAlignment(2, Qt.AlignCenter)
                    self.analysis_tree.addTopLevelItem(item)
                
                prev_entry = entry
                prev_was_normal = not is_anomaly
        
        # ===== FUZZING ANALYSIS (API) =====
        # Detect: "Fuzz: target/payload" or "Brute: value" patterns
        fuzz_entries = []
        for i, record in enumerate(all_logs):
            if record[2] == 'C':  # Client
                target = None
                payload = None
                fuzz_type = None
                
                # Check for Fuzz: pattern
                match = re.match(FUZZ_PATTERN, record[3])
                if match:
                    target = match.group(1).strip()
                    payload = match.group(2).strip()
                    fuzz_type = 'Fuzz'
                else:
                    # Check for Brute: pattern
                    match = re.match(BRUTE_PATTERN, record[3])
                    if match:
                        payload = match.group(1).strip()
                        target = 'Code'
                        fuzz_type = 'Brute'
                
                if fuzz_type:
                    # Find next server response
                    for j in range(i + 1, min(i + 5, len(all_logs))):
                        if all_logs[j][2] == 'S':
                            resp_data = self.hack3270.parse_3270(
                                self.hack3270.get_ascii(all_logs[j][5])
                            ) if all_logs[j][5] else ""
                            fuzz_entries.append({
                                'request_id': record[0],
                                'timestamp': float(record[1]),
                                'response_id': all_logs[j][0],
                                'fuzz_type': fuzz_type,
                                'target': target,
                                'payload': payload,
                                'length': all_logs[j][4],
                                'data': resp_data
                            })
                            break
        
        # Analyze fuzz entries for abends and errors
        for entry in fuzz_entries:
            abend_found = None
            error_found = None
            
            # Check for abends
            for pattern, name in ABEND_PATTERNS:
                if re.search(pattern, entry['data'], re.IGNORECASE):
                    abend_found = name
                    break
            
            # Check for errors (only if no abend)
            if not abend_found:
                for pattern, name in ERROR_PATTERNS:
                    if re.search(pattern, entry['data'], re.IGNORECASE):
                        error_found = name
                        break
            
            if abend_found:
                fuzz_abends += 1
                item = AnalysisTreeWidgetItem([
                    "Fuzz",
                    str(entry['request_id']),
                    str(entry['response_id']),
                    f"{entry['target']}/{entry['payload'][:12]}",
                    str(entry['length']),
                    f"ABEND: {abend_found}"
                ])
                item.setForeground(0, QColor("#ff6b6b"))  # Red
                item.setForeground(5, QColor("#ff6b6b"))
                item.setTextAlignment(1, Qt.AlignCenter)
                item.setTextAlignment(2, Qt.AlignCenter)
                self.analysis_tree.addTopLevelItem(item)
            
            elif error_found:
                fuzz_errors += 1
                item = AnalysisTreeWidgetItem([
                    "Fuzz",
                    str(entry['request_id']),
                    str(entry['response_id']),
                    f"{entry['target']}/{entry['payload'][:12]}",
                    str(entry['length']),
                    f"ERROR: {error_found}"
                ])
                item.setForeground(0, QColor("#ffd93d"))  # Yellow
                item.setForeground(5, QColor("#ffd93d"))
                item.setTextAlignment(1, Qt.AlignCenter)
                item.setTextAlignment(2, Qt.AlignCenter)
                self.analysis_tree.addTopLevelItem(item)
        
        # Sort results by Request ID (column 1) numerically
        self.analysis_tree.sortItems(1, Qt.AscendingOrder)
        
        # Update status
        parts = []
        if hidden_values > 0:
            parts.append(f"{hidden_values} hidden values")
        if hidden_labels > 0:
            parts.append(f"{hidden_labels} hidden labels")
        if key_transitions > 0:
            parts.append(f"{key_transitions} AID transitions")
        if field_transitions > 0:
            parts.append(f"{field_transitions} field transitions")
        if fuzz_abends > 0:
            parts.append(f"{fuzz_abends} fuzz abends")
        if fuzz_errors > 0:
            parts.append(f"{fuzz_errors} fuzz errors")
        
        if parts:
            self.analysis_status.setText("Found: " + ", ".join(parts))
        else:
            self.analysis_status.setText("No findings.")
    
    def analysis_item_selected(self):
        """Handle selection of an analysis result - show detail and optionally replay."""
        items = self.analysis_tree.selectedItems()
        if not items:
            return
        
        item = items[0]
        request_id = int(item.text(1))
        response_id = int(item.text(2))
        
        # Get and display the response record
        detail_text = f"=== REQUEST (ID: {request_id}) ===\n"
        for row in self.hack3270.get_log(request_id):
            ebcdic_data = self.hack3270.get_ascii(row[5])
            if re.search("^tn3270 ", row[3]):
                detail_text += self.hack3270.parse_telnet(ebcdic_data)
            else:
                detail_text += self.hack3270.parse_3270(ebcdic_data)
            
            # Auto-send client data if enabled
            if self.analysis_auto_client_cb.isChecked():
                self.hack3270.send_server(row[5])
        
        detail_text += f"\n\n=== RESPONSE (ID: {response_id}) ===\n"
        for row in self.hack3270.get_log(response_id):
            ebcdic_data = self.hack3270.get_ascii(row[5])
            if re.search("^tn3270 ", row[3]):
                detail_text += self.hack3270.parse_telnet(ebcdic_data)
            else:
                detail_text += self.hack3270.parse_3270(ebcdic_data)
            
            # Auto-send server data if enabled
            if self.analysis_auto_server_cb.isChecked():
                self.hack3270.send_client(row[5])
        
        self.analysis_detail.setPlainText(detail_text)
    
    def export_analysis_csv(self):
        """Export analysis results to a CSV file."""
        item_count = self.analysis_tree.topLevelItemCount()
        
        if item_count == 0:
            self.analysis_export_label.setText("No results to export.")
            return
        
        # Prompt for filename
        default_name = f"{self.hack3270.project_name}_analysis.csv"
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Analysis", default_name, "CSV Files (*.csv);;All Files (*)"
        )
        
        if not filename:
            return  # User cancelled
        
        self.analysis_export_label.setText(f"Exporting {item_count} entries...")
        QApplication.processEvents()
        
        try:
            import csv
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                # Write header matching tree columns
                writer.writerow(["Type", "Request ID", "Response ID", "Value/Key", "Length", "Finding"])
                
                # Export all items
                for i in range(item_count):
                    item = self.analysis_tree.topLevelItem(i)
                    writer.writerow([
                        item.text(0),  # Type
                        item.text(1),  # Req
                        item.text(2),  # Resp
                        item.text(3),  # Value/Key
                        item.text(4),  # Len
                        item.text(5)   # Finding
                    ])
            
            self.analysis_export_label.setText(f"Exported {item_count} entries")
        except Exception as e:
            self.analysis_export_label.setText(f"Export failed: {str(e)}")
        
    def create_help_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        help_text = QTextEdit()
        help_text.setReadOnly(True)
        
        # Custom stylesheet for widget
        help_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3c3c3c;
                border-radius: 4px;
                font-family: 'Segoe UI', sans-serif;
                font-size: 13px;
                padding: 10px;
            }
        """)
        
        try:
            with open("README.md", "r", encoding="utf-8") as f:
                help_text.setMarkdown(f.read())
        except FileNotFoundError:
            help_text.setPlainText("README.md not found")
        
        layout.addWidget(help_text)
        self.tabs.addTab(tab, "Help")
        
    def update_logs_tab(self):
        new_items_added = False
        for row in self.hack3270.all_logs(self.last_db_id):
            current_timestamp = float(row[1])
            
            # Calculate delta from previous entry
            if self.last_log_timestamp is not None:
                delta_ms = (current_timestamp - self.last_log_timestamp) * 1000
                delta_str = f"{delta_ms:.1f}"
            else:
                delta_str = "-"
            
            item = NumericTreeWidgetItem([
                str(row[0]),
                str(datetime.datetime.fromtimestamp(current_timestamp)),
                delta_str,
                self.hack3270.expand_CS(row[2]),
                str(row[4]),
                row[3]
            ])
            self.log_tree.addTopLevelItem(item)
            self.last_db_id = int(row[0])
            self.last_log_timestamp = current_timestamp
            new_items_added = True
        
        # Follow mode - scroll to and select latest entry
        if new_items_added and self.log_follow_mode:
            last_item = self.log_tree.topLevelItem(self.log_tree.topLevelItemCount() - 1)
            if last_item:
                self.log_tree.scrollToItem(last_item)
                self.log_tree.setCurrentItem(last_item)
            
    # Button handlers
    def hack_button_pressed(self):
        self.set_checkbox_values()
        if self.hack3270.get_hack_on():
            self.hack3270.set_hack_on(0)
            self.hack_button.setText("OFF")
            self.hack_button.setProperty("class", "danger")
            self.hack3270.set_hack_toggled()
        else:
            self.hack3270.set_hack_on(1)
            self.hack_button.setText("ON")
            self.hack_button.setProperty("class", "success")
            self.hack3270.set_hack_toggled()
        self.hack_button.style().unpolish(self.hack_button)
        self.hack_button.style().polish(self.hack_button)

    def hack_color_button_pressed(self):
        self.set_checkbox_values()
        if self.hack3270.get_hack_color_on():
            self.hack3270.set_hack_color_on(0)
            self.hack_color_button.setText("OFF")
            self.hack_color_button.setProperty("class", "danger")
            self.hack3270.set_hack_color_toggled()
        else:
            self.hack3270.set_hack_color_on(1)
            self.hack_color_button.setText("ON")
            self.hack_color_button.setProperty("class", "success")
            self.hack3270.set_hack_color_toggled()
        self.hack_color_button.style().unpolish(self.hack_color_button)
        self.hack_color_button.style().polish(self.hack_color_button)

    def hack_toggle(self):
        self.set_checkbox_values()
        self.hack3270.set_hack_toggled(1)
    
    def hack_color_toggle(self):
        self.set_checkbox_values()
        self.hack3270.set_hack_color_toggled(1)

    # AID Spoofing methods
    def on_aid_spoof_toggle(self, checked):
        """Handle AID spoof toggle."""
        self.hack3270.set_aid_spoof_enabled(checked)
        self.aid_mode_combo.setEnabled(checked)
        
        if checked:
            # Update controls based on current mode
            self.on_aid_mode_changed(self.aid_mode_combo.currentText())
            if self.aid_mode_combo.currentText() == 'MANUAL':
                self.aid_status_label.setText(f"Spoofing all AIDs to {self.aid_select_combo.currentText()}")
            else:
                self.aid_status_label.setText("Ready. Click ARM then send from terminal.")
            self.aid_status_label.setProperty("class", "status-ready")
        else:
            self.aid_select_label.setEnabled(False)
            self.aid_select_combo.setEnabled(False)
            self.aid_arm_btn.setEnabled(False)
            self.aid_arm_btn.setVisible(False)
            self.aid_status_label.setText("Disabled")
            self.aid_status_label.setProperty("class", "status-warning")
            self.hack3270.disarm_aid_fuzzer()
        
        self.aid_status_label.style().unpolish(self.aid_status_label)
        self.aid_status_label.style().polish(self.aid_status_label)

    def on_aid_mode_changed(self, mode):
        """Handle AID mode change between MANUAL and FUZZER."""
        self.hack3270.set_aid_spoof_mode(mode)
        
        if mode == 'MANUAL':
            self.aid_select_label.setVisible(True)
            self.aid_select_combo.setVisible(True)
            self.aid_select_label.setEnabled(True)
            self.aid_select_combo.setEnabled(True)
            self.aid_arm_btn.setVisible(False)
            self.aid_arm_btn.setEnabled(False)
            self.aid_stop_btn.setVisible(False)
            self.aid_stop_btn.setEnabled(False)
            self.aid_resume_btn.setVisible(False)
            self.aid_resume_btn.setEnabled(False)
            if self.aid_spoof_toggle.isChecked():
                self.aid_status_label.setText(f"Spoofing all AIDs to {self.aid_select_combo.currentText()}")
                self.aid_status_label.setProperty("class", "status-ready")
        else:  # FUZZER
            self.aid_select_label.setVisible(False)
            self.aid_select_combo.setVisible(False)
            self.aid_select_label.setEnabled(False)
            self.aid_select_combo.setEnabled(False)
            self.aid_arm_btn.setVisible(True)
            self.aid_arm_btn.setEnabled(True)
            self.aid_stop_btn.setVisible(True)
            self.aid_stop_btn.setEnabled(False)  # Enabled when fuzzing starts
            self.aid_resume_btn.setVisible(True)
            self.aid_resume_btn.setEnabled(False)  # Enabled when paused
            if self.aid_spoof_toggle.isChecked():
                self.aid_status_label.setText("Ready. Click ARM then send from terminal.")
                self.aid_status_label.setProperty("class", "status-ready")
        
        self.aid_status_label.style().unpolish(self.aid_status_label)
        self.aid_status_label.style().polish(self.aid_status_label)

    def on_aid_select_changed(self, aid_name):
        """Handle AID selection change in MANUAL mode."""
        self.hack3270.set_aid_spoof_value(aid_name)
        if self.aid_spoof_toggle.isChecked():
            self.aid_status_label.setText(f"Spoofing all AIDs to {aid_name}")
            self.aid_status_label.setProperty("class", "status-ready")
            self.aid_status_label.style().unpolish(self.aid_status_label)
            self.aid_status_label.style().polish(self.aid_status_label)

    def on_aid_arm_clicked(self):
        """Handle ARM button click for FUZZER mode."""
        self.hack3270.set_aid_fuzzer_callback(self.aid_fuzzer_callback)
        self.hack3270.arm_aid_fuzzer()
        self.aid_arm_btn.setEnabled(False)
        self.aid_status_label.setText("Armed. Waiting for transmission...")
        self.aid_status_label.setProperty("class", "status-warning")
        self.aid_status_label.style().unpolish(self.aid_status_label)
        self.aid_status_label.style().polish(self.aid_status_label)

    def aid_fuzzer_callback(self, state, progress, total, aid_name):
        """Callback from libhack3270 for fuzzer status updates."""
        if state == 'captured':
            self.aid_status_label.setText("Captured! Fuzzing... 0/256")
            self.aid_status_label.setProperty("class", "status-info")
            self.aid_stop_btn.setEnabled(True)
        elif state == 'progress':
            self.aid_status_label.setText(f"Fuzzing... {progress}/256 (0x{progress-1:02X} - {aid_name})")
            self.aid_status_label.setProperty("class", "status-info")
        elif state == 'complete':
            self.aid_status_label.setText("Complete! 256 AIDs tested. Check Logs tab.")
            self.aid_status_label.setProperty("class", "status-ready")
            self.aid_arm_btn.setEnabled(True)
            self.aid_stop_btn.setEnabled(False)
            self.aid_resume_btn.setEnabled(False)
        elif state == 'stopped':
            self.aid_status_label.setText(f"Stopped at {progress}/256. Click ARM to restart.")
            self.aid_status_label.setProperty("class", "status-warning")
            self.aid_arm_btn.setEnabled(True)
            self.aid_stop_btn.setEnabled(False)
            self.aid_resume_btn.setEnabled(False)
        elif state == 'paused':
            self.aid_status_label.setText(f"Paused at {progress}/256. Click RESUME to continue.")
            self.aid_status_label.setProperty("class", "status-warning")
            self.aid_stop_btn.setEnabled(True)
            self.aid_resume_btn.setEnabled(True)
        elif state == 'resumed':
            self.aid_status_label.setText(f"Resumed. Fuzzing... {progress}/256")
            self.aid_status_label.setProperty("class", "status-info")
            self.aid_resume_btn.setEnabled(False)
        
        self.aid_status_label.style().unpolish(self.aid_status_label)
        self.aid_status_label.style().polish(self.aid_status_label)
        QApplication.processEvents()

    def on_aid_stop_clicked(self):
        """Handle STOP button click for FUZZER mode - pauses the fuzzer."""
        self.hack3270.pause_aid_fuzzer()

    def on_aid_resume_clicked(self):
        """Handle RESUME button click for FUZZER mode."""
        self.hack3270.resume_aid_fuzzer()
    
    # =========================================================================
    # Fuzzing Tab Handlers
    # =========================================================================
    
    def on_fuzz_discover_fields(self):
        """Discover fields from the current screen."""
        try:
            # Get last server response
            raw_data = self.hack3270.get_last_server_raw()
            if not raw_data:
                self.fuzz_field_count_label.setText("No screen data available")
                return
            
            # Parse fields using the API-style parsing
            fields = self._parse_screen_fields(raw_data)
            
            # Filter based on checkboxes
            self.fuzz_discovered_fields = []
            for f in fields:
                if f['hidden'] and self.fuzz_hidden_fields.isChecked():
                    self.fuzz_discovered_fields.append(f)
                elif f['protected'] and not f['hidden'] and self.fuzz_protected_fields.isChecked():
                    self.fuzz_discovered_fields.append(f)
                elif not f['protected'] and not f['hidden'] and self.fuzz_input_fields.isChecked():
                    self.fuzz_discovered_fields.append(f)
            
            # Update the field list
            self.fuzz_field_list.clear()
            for i, f in enumerate(self.fuzz_discovered_fields):
                ftype = 'Hidden' if f['hidden'] else ('Protected' if f['protected'] else 'Input')
                addr_bytes = self._encode_buffer_address(f['address'])
                addr_str = f"{addr_bytes[0]:02X} {addr_bytes[1]:02X}"
                # Convert EBCDIC value to ASCII for display
                value_str = ""
                if f.get('value'):
                    try:
                        value_str = f['value'].decode('cp500').strip()
                        # Truncate long values for display
                        if len(value_str) > 30:
                            value_str = value_str[:27] + "..."
                    except:
                        value_str = f['value'].hex()[:20]
                item = QTreeWidgetItem([str(i+1), ftype, addr_str, str(f['length']), value_str])
                item.setSelected(True)  # Select all by default
                self.fuzz_field_list.addTopLevelItem(item)
            
            self.fuzz_field_count_label.setText(f"{len(self.fuzz_discovered_fields)} fields discovered")
            
        except Exception as e:
            self.fuzz_field_count_label.setText(f"Error: {str(e)}")
    
    def _parse_screen_fields(self, raw_data):
        """Parse 3270 data stream to find all fields (mirrors API logic)."""
        fields = []
        i = 0
        screen_size = 80 * 24
        
        SBA = 0x11
        SF = 0x1D
        SFE = 0x29
        
        # Skip command bytes at start
        if len(raw_data) > 0 and raw_data[0] in [0xF1, 0xF5, 0x7E, 0xF3]:
            i = 1
            if raw_data[0] in [0xF5, 0x7E]:  # EW or EWA - skip WCC
                i = 2
        
        current_field = None
        current_addr = 0
        addr_table = [
            0x40, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
            0xC8, 0xC9, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
            0x50, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
            0xD8, 0xD9, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
            0x60, 0x61, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
            0xE8, 0xE9, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
            0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
            0xF8, 0xF9, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        ]
        
        def decode_addr(b1, b2):
            if b1 & 0xC0 == 0x00:
                return ((b1 & 0x3F) << 8) | b2
            else:
                try:
                    high = addr_table.index(b1)
                    low = addr_table.index(b2)
                    return (high << 6) | low
                except ValueError:
                    return -1
        
        while i < len(raw_data):
            byte = raw_data[i]
            
            if byte == SBA:
                if i + 2 < len(raw_data):
                    current_addr = decode_addr(raw_data[i+1], raw_data[i+2])
                    i += 3
                else:
                    i += 1
            elif byte == SF:
                if i + 1 < len(raw_data):
                    attr = raw_data[i+1]
                    if current_field is not None:
                        current_field['length'] = current_addr - current_field['address']
                        if current_field['length'] < 0:
                            current_field['length'] += screen_size
                    
                    current_field = {
                        'address': current_addr + 1,
                        'protected': (attr & 0x20) != 0,
                        'numeric': (attr & 0x10) != 0,
                        'hidden': (attr & 0x0C) == 0x0C,
                        'length': 0,
                        'value': b''
                    }
                    fields.append(current_field)
                    current_addr += 1
                    i += 2
                else:
                    i += 1
            elif byte == SFE:
                if i + 1 < len(raw_data):
                    count = raw_data[i+1]
                    if i + 2 + count * 2 <= len(raw_data):
                        if current_field is not None:
                            current_field['length'] = current_addr - current_field['address']
                            if current_field['length'] < 0:
                                current_field['length'] += screen_size
                        
                        protected = False
                        numeric = False
                        hidden = False
                        
                        for j in range(count):
                            attr_type = raw_data[i + 2 + j * 2]
                            attr_value = raw_data[i + 3 + j * 2]
                            if attr_type == 0xC0:
                                protected = (attr_value & 0x20) != 0
                                numeric = (attr_value & 0x10) != 0
                                hidden = (attr_value & 0x0C) == 0x0C
                        
                        current_field = {
                            'address': current_addr + 1,
                            'protected': protected,
                            'numeric': numeric,
                            'hidden': hidden,
                            'length': 0,
                            'value': b''
                        }
                        fields.append(current_field)
                        current_addr += 1
                        i += 2 + count * 2
                    else:
                        i += 1
                else:
                    i += 1
            elif byte in [0x28, 0x2C, 0x3C]:  # SA, MF, RA
                if byte == 0x28:
                    i += 3
                elif byte == 0x2C:
                    if i + 1 < len(raw_data):
                        count = raw_data[i+1]
                        i += 2 + count * 2
                    else:
                        i += 1
                elif byte == 0x3C:
                    i += 4
            elif byte == 0x13:  # IC
                i += 1
            elif byte == 0x05:  # PT
                i += 1
            elif byte == 0x08:  # GE
                i += 2
            elif byte == 0x12:  # EUA
                i += 4
            else:
                if current_field is not None:
                    current_field['value'] += bytes([byte])
                current_addr += 1
                i += 1
        
        if current_field is not None and current_field['length'] == 0:
            current_field['length'] = screen_size - current_field['address']
        
        return fields
    
    def _encode_buffer_address(self, addr):
        """Encode buffer position to 12-bit address bytes."""
        addr_table = [
            0x40, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
            0xC8, 0xC9, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
            0x50, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
            0xD8, 0xD9, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
            0x60, 0x61, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
            0xE8, 0xE9, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
            0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
            0xF8, 0xF9, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        ]
        high = (addr >> 6) & 0x3F
        low = addr & 0x3F
        return bytes([addr_table[high], addr_table[low]])
    
    def fuzz_set_all_payloads(self, checked):
        """Set all payload checkboxes to the given state."""
        for cb in self.fuzz_payloads.values():
            cb.setChecked(checked)
    
    def fuzz_select_all_fields(self):
        """Select all fields in the field list."""
        for i in range(self.fuzz_field_list.topLevelItemCount()):
            self.fuzz_field_list.topLevelItem(i).setSelected(True)
    
    def fuzz_deselect_all_fields(self):
        """Deselect all fields in the field list."""
        for i in range(self.fuzz_field_list.topLevelItemCount()):
            self.fuzz_field_list.topLevelItem(i).setSelected(False)
    
    def on_fuzz_start(self):
        """Handle Start Fuzzing button click - show warning and start if confirmed."""
        from PySide6.QtWidgets import QMessageBox
        
        # Show warning dialog
        warning = QMessageBox()
        warning.setIcon(QMessageBox.Icon.Warning)
        warning.setWindowTitle("⚠️ DANGER: Fuzzing Warning")
        warning.setText(
            "<b>WARNING: Fuzzing can crash or corrupt the target system!</b>"
        )
        warning.setInformativeText(
            "Fuzzing sends malformed data to discover vulnerabilities. This can cause:\n\n"
            "• Application crashes (ABENDs)\n"
            "• Data corruption\n"
            "• System instability\n"
            "• Service disruption\n\n"
            "ONLY run this on test/development systems!\n\n"
            "By clicking 'I Understand', you confirm that:\n"
            "1. This is NOT a production system\n"
            "2. You have PERMISSION to test this system\n"
            "3. You accept responsibility for any consequences"
        )
        
        understand_btn = warning.addButton("I understand and have permission!", QMessageBox.ButtonRole.AcceptRole)
        warning.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        
        warning.exec()
        
        if warning.clickedButton() != understand_btn:
            return
        
        # Validate that fields are discovered
        selected_items = self.fuzz_field_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Fields Selected", 
                "Please discover and select fields to fuzz first.")
            return
        
        # Validate at least one payload category is selected
        selected_payloads = [k for k, cb in self.fuzz_payloads.items() if cb.isChecked() and cb.isVisible()]
        if not selected_payloads:
            QMessageBox.warning(self, "No Payloads Selected", 
                "Please select at least one payload category.")
            return
        
        # Start fuzzing
        self._start_fuzzing(selected_payloads)
    
    def _start_fuzzing(self, payload_categories):
        """Initialize and start the fuzzing process."""
        self.fuzz_running = True
        self.fuzz_paused = False
        self.fuzz_finding_count = 0
        
        # Update UI state
        self.fuzz_start_btn.setEnabled(False)
        self.fuzz_stop_btn.setEnabled(True)
        self.fuzz_pause_btn.setEnabled(True)
        self.fuzz_resume_btn.setEnabled(False)
        self.fuzz_discover_btn.setEnabled(False)
        self.fuzz_status_label.setText("Initializing...")
        
        # Generate payloads
        self.fuzz_current_payloads = self._generate_payloads(payload_categories)
        self.fuzz_current_index = 0
        
        total = len(self.fuzz_current_payloads)
        self.fuzz_progress_label.setText(f"0 / {total}")
        self.fuzz_status_label.setText("Fuzzing...")
        self.fuzz_status_label.setProperty("class", "status-info")
        self.fuzz_status_label.style().unpolish(self.fuzz_status_label)
        self.fuzz_status_label.style().polish(self.fuzz_status_label)
        
        # Get delay
        try:
            delay_ms = int(self.fuzz_delay_input.text())
        except ValueError:
            delay_ms = 300
        
        # Start timer for fuzzing iterations
        self.fuzz_timer = QTimer()
        self.fuzz_timer.timeout.connect(self._fuzz_iteration)
        self.fuzz_timer.start(delay_ms)
    
    def _generate_payloads(self, categories):
        """Generate all payloads based on selected categories."""
        payloads = []
        
        # Get selected field indices
        selected_indices = []
        for i in range(self.fuzz_field_list.topLevelItemCount()):
            item = self.fuzz_field_list.topLevelItem(i)
            if item.isSelected():
                selected_indices.append(i)
        
        for field_idx in selected_indices:
            field = self.fuzz_discovered_fields[field_idx]
            field_len = field['length'] if field['length'] > 0 else 44
            
            for category in categories:
                category_payloads = self._get_category_payloads(category, field_len)
                for payload_data, payload_name, is_binary in category_payloads:
                    payloads.append({
                        'field_idx': field_idx,
                        'field': field,
                        'data': payload_data,
                        'name': payload_name,
                        'is_binary': is_binary,
                        'category': category
                    })
        
        return payloads
    
    def _get_category_payloads(self, category, field_length):
        """Get payloads for a specific category."""
        payloads = []
        
        if category == 'overflow':
            sizes = [field_length + 1, field_length + 4, field_length * 2, 50, 100, 256]
            sizes = sorted(set(s for s in sizes if s > field_length))[:6]
            for length in sizes:
                payloads.append(('A' * length, f"OVF-{length}", False))
            payloads.append(('9' * (field_length * 2), f"NUM-OVF-{field_length*2}", False))
            
        elif category == 'packed_decimal':
            payloads.extend([
                (bytes([0x12, 0x34, 0x5A]), "COMP3-SIGN-A", True),
                (bytes([0xAB, 0xCD, 0xEF]), "COMP3-HEX-DIGITS", True),
                (bytes([0xFF, 0xFF, 0xFF, 0xFF]), "COMP3-ALL-F", True),
                (bytes([0x00, 0x00, 0x00, 0x00]), "COMP3-ALL-0", True),
            ])
            
        elif category == 'zoned_decimal':
            payloads.extend([
                (bytes([0x00, 0x01, 0x02, 0x03]), "ZONED-NULL-ZONE", True),
                (bytes([0x30, 0x31, 0x32, 0x33]), "ZONED-ASCII", True),
                (bytes([0xC1, 0xC2, 0xC3, 0xC4]), "ZONED-ALPHA-ABCD", True),
            ])
            
        elif category == 'dates':
            for date_str, name in [
                ('00000000', 'DATE-NULL'), ('99999999', 'DATE-MAX'),
                ('20250230', 'DATE-FEB30'), ('20251301', 'DATE-MONTH13'),
                ('250000', 'TIME-HOUR25'), ('999999', 'TIME-MAX')
            ]:
                payloads.append((date_str, name, False))
                
        elif category == 'ebcdic_control':
            for code, name in [(0x00, 'NUL'), (0x0D, 'CR'), (0x15, 'NL'), (0x3F, 'SUB')]:
                payloads.append((bytes([code] * 4), f"CTRL-{name}", True))
            payloads.append((bytes([0x0E, 0x0F, 0x0E, 0x0F]), "SHIFT-IO", True))
            
        elif category == 'cics_injection':
            for trans in ['CEMT', 'CEDA', 'CEDF', 'CESF', 'CECI']:
                payloads.append((trans, f"CICS-{trans}", False))
            payloads.append(('CEMT SET PROG(*) NEW', 'CICS-CMD-NEWCOPY', False))
            
        elif category == 'sql_injection':
            for sql, name in [
                ("'", 'SQL-QUOTE'), ("' OR '1'='1", 'SQL-OR-TRUE'),
                ("'; --", 'SQL-SEMICOLON'), ("' UNION SELECT", 'SQL-UNION'),
            ]:
                payloads.append((sql, name, False))
                
        elif category == 'cobol_special':
            for size in [4, 16, 44]:
                payloads.append((bytes([0x00] * size), f"LOW-VALUES-{size}", True))
                payloads.append((bytes([0xFF] * size), f"HIGH-VALUES-{size}", True))
                
        elif category == 'tn3270_orders':
            for order_byte, name in [(0x11, 'SBA'), (0x1D, 'SF'), (0x29, 'SFE')]:
                payloads.append((bytes([order_byte] * 4), f"ORD-{name}-x4", True))
            payloads.append((bytes([0xFF, 0xEF]), "IAC-EOR", True))
            payloads.append((bytes([0xFF, 0xFF, 0xFF, 0xFF]), "IAC-FLOOD", True))
            
        elif category == 'random_binary':
            import random
            for i in range(5):
                length = random.randint(8, 64)
                data = bytes([random.randint(0, 255) for _ in range(length)])
                payloads.append((data, f"RANDOM-{length}B-{i+1}", True))
                
        elif category == 'boundary':
            if field_length > 1:
                payloads.append(('X' * (field_length - 1), f"BOUND-UNDER", False))
            payloads.append(('X' * field_length, f"BOUND-EXACT", False))
            payloads.append(('X' * (field_length + 1), f"BOUND-OVER", False))
        
        return payloads
    
    def _fuzz_iteration(self):
        """Execute one fuzzing iteration."""
        if not self.fuzz_running or self.fuzz_paused:
            return
        
        if self.fuzz_current_index >= len(self.fuzz_current_payloads):
            self._fuzz_complete()
            return
        
        payload = self.fuzz_current_payloads[self.fuzz_current_index]
        
        try:
            # Build and send the field fuzz packet
            self._send_field_fuzz(payload)
            
            # Check response
            import time
            time.sleep(0.1)
            response = self.hack3270.get_last_server()
            response_len = len(self.hack3270.get_last_server_raw() or b'')
            
            # Check for abend
            abend = None
            response_upper = response.upper() if response else ''
            abend_patterns = ['DFHAC2', 'ABEND', 'ASRA', 'AICA', 'AEY7', 'APCT',
                              'SOC7', 'SOC4', 'S0C7', 'S0C4', 'ASRB', 'AEXL']
            for pattern in abend_patterns:
                if pattern in response_upper:
                    abend = pattern
                    break
            
            # Record finding if abend detected
            if abend:
                self._add_finding(payload, 'ABEND: ' + abend, response_len)
                if self.fuzz_stop_on_abend.isChecked():
                    self._fuzz_complete(f"Stopped: ABEND {abend} detected")
                    return
            
        except Exception as e:
            error_str = str(e)
            if 'WinError 10053' in error_str or 'Connection' in error_str:
                self._add_finding(payload, 'CONNECTION LOST', 0)
                if self.fuzz_stop_on_disconnect.isChecked():
                    self._fuzz_complete("Stopped: Connection lost")
                    return
            else:
                self._add_finding(payload, f'ERROR: {error_str}', 0)
        
        # Update progress
        self.fuzz_current_index += 1
        total = len(self.fuzz_current_payloads)
        self.fuzz_progress_label.setText(f"{self.fuzz_current_index} / {total}")
    
    def _send_field_fuzz(self, payload):
        """Send a field fuzzing packet."""
        field = payload['field']
        data = payload['data']
        is_binary = payload['is_binary']
        name = payload['name']
        
        # Convert ASCII to EBCDIC if needed
        A2E = {
            ' ': 0x40, 'a': 0x81, 'b': 0x82, 'c': 0x83, 'd': 0x84, 'e': 0x85, 'f': 0x86, 'g': 0x87,
            'h': 0x88, 'i': 0x89, 'j': 0x91, 'k': 0x92, 'l': 0x93, 'm': 0x94, 'n': 0x95, 'o': 0x96,
            'p': 0x97, 'q': 0x98, 'r': 0x99, 's': 0xa2, 't': 0xa3, 'u': 0xa4, 'v': 0xa5, 'w': 0xa6,
            'x': 0xa7, 'y': 0xa8, 'z': 0xa9, 'A': 0xc1, 'B': 0xc2, 'C': 0xc3, 'D': 0xc4, 'E': 0xc5,
            'F': 0xc6, 'G': 0xc7, 'H': 0xc8, 'I': 0xc9, 'J': 0xd1, 'K': 0xd2, 'L': 0xd3, 'M': 0xd4,
            'N': 0xd5, 'O': 0xd6, 'P': 0xd7, 'Q': 0xd8, 'R': 0xd9, 'S': 0xe2, 'T': 0xe3, 'U': 0xe4,
            'V': 0xe5, 'W': 0xe6, 'X': 0xe7, 'Y': 0xe8, 'Z': 0xe9, '0': 0xf0, '1': 0xf1, '2': 0xf2,
            '3': 0xf3, '4': 0xf4, '5': 0xf5, '6': 0xf6, '7': 0xf7, '8': 0xf8, '9': 0xf9,
            '.': 0x4b, '<': 0x4c, '(': 0x4d, '+': 0x4e, '|': 0x4f, '&': 0x50, '!': 0x5a, '$': 0x5b,
            '*': 0x5c, ')': 0x5d, ';': 0x5e, '-': 0x60, '/': 0x61, ',': 0x6b, '%': 0x6c, '_': 0x6d,
            '>': 0x6e, '?': 0x6f, ':': 0x7a, '#': 0x7b, '@': 0x7c, "'": 0x7d, '=': 0x7e, '"': 0x7f,
        }
        
        if is_binary:
            ebcdic_data = data if isinstance(data, bytes) else data.encode('latin-1')
        else:
            ebcdic_data = bytes([A2E.get(c, 0x6F) for c in str(data)])
        
        # Build packet
        addr_bytes = self._encode_buffer_address(field['address'])
        AID_ENTER = 0x7D
        SBA = 0x11
        
        # Check for TN3270E mode
        header = b''
        if hasattr(self.hack3270, 'check_inject_3270e') and self.hack3270.check_inject_3270e():
            header = b'\x00\x00\x00\x00\x01'
        
        packet = header + bytes([AID_ENTER, SBA]) + addr_bytes + ebcdic_data
        
        # Send via proxy
        desc = f'Fuzz: Field_{payload["field_idx"]}/{name}'
        self.hack3270.api_send_raw(packet, desc)
    
    def _add_finding(self, payload, result, response_len):
        """Add a finding to the findings tree."""
        self.fuzz_finding_count += 1
        
        field_name = f"Field {payload['field_idx']}" if payload['field_idx'] >= 0 else "N/A"
        payload_name = payload['name']
        
        item = FuzzingTreeWidgetItem([
            str(self.fuzz_finding_count),
            field_name,
            payload_name,
            result,
            str(response_len)
        ])
        
        # Color-code based on result
        if 'ABEND' in result:
            for i in range(5):
                item.setBackground(i, QColor('#5c1a1a'))  # Dark red
        elif 'CONNECTION' in result:
            for i in range(5):
                item.setBackground(i, QColor('#5c3d1a'))  # Dark orange
        elif 'ERROR' in result:
            for i in range(5):
                item.setBackground(i, QColor('#5c5c1a'))  # Dark yellow
        
        self.fuzz_findings_tree.addTopLevelItem(item)
        self.fuzz_findings_tree.scrollToItem(item)
    
    def _fuzz_complete(self, message=None):
        """Complete the fuzzing process."""
        self.fuzz_running = False
        self.fuzz_paused = False
        
        if self.fuzz_timer:
            self.fuzz_timer.stop()
            self.fuzz_timer = None
        
        # Update UI state
        self.fuzz_start_btn.setEnabled(True)
        self.fuzz_stop_btn.setEnabled(False)
        self.fuzz_pause_btn.setEnabled(False)
        self.fuzz_resume_btn.setEnabled(False)
        self.fuzz_discover_btn.setEnabled(True)
        
        if message:
            self.fuzz_status_label.setText(message)
        else:
            self.fuzz_status_label.setText(f"Complete - {self.fuzz_finding_count} findings")
        
        self.fuzz_status_label.setProperty("class", "status-success" if self.fuzz_finding_count == 0 else "status-warning")
        self.fuzz_status_label.style().unpolish(self.fuzz_status_label)
        self.fuzz_status_label.style().polish(self.fuzz_status_label)
    
    def on_fuzz_stop(self):
        """Handle Stop button click."""
        self._fuzz_complete("Stopped by user")
    
    def on_fuzz_pause(self):
        """Handle Pause button click."""
        self.fuzz_paused = True
        self.fuzz_pause_btn.setEnabled(False)
        self.fuzz_resume_btn.setEnabled(True)
        self.fuzz_status_label.setText("Paused")
    
    def on_fuzz_resume(self):
        """Handle Resume button click."""
        self.fuzz_paused = False
        self.fuzz_pause_btn.setEnabled(True)
        self.fuzz_resume_btn.setEnabled(False)
        self.fuzz_status_label.setText("Fuzzing...")
    
    def on_fuzz_clear_findings(self):
        """Clear all findings."""
        self.fuzz_findings_tree.clear()
        self.fuzz_finding_count = 0
    
    def on_fuzz_export(self):
        """Export findings to CSV."""
        if self.fuzz_findings_tree.topLevelItemCount() == 0:
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.information(self, "No Findings", "No findings to export.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Findings", "fuzz_findings.csv", "CSV Files (*.csv)"
        )
        
        if filename:
            try:
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["#", "Field", "Payload", "Result", "Response Length"])
                    
                    for i in range(self.fuzz_findings_tree.topLevelItemCount()):
                        item = self.fuzz_findings_tree.topLevelItem(i)
                        writer.writerow([item.text(j) for j in range(5)])
                
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.information(self, "Export Complete", 
                    f"Exported {self.fuzz_findings_tree.topLevelItemCount()} findings to {filename}")
            except Exception as e:
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.critical(self, "Export Failed", f"Error: {str(e)}")
    
    # =========================================================================
    # Order Fuzzing Tab Handlers
    # =========================================================================
    
    def order_set_all_payloads(self, checked):
        """Set all order payload checkboxes to the given state."""
        for cb in self.order_payloads.values():
            cb.setChecked(checked)
    
    def on_order_fuzz_start(self):
        """Handle Start button click for Order Fuzzing tab."""
        from PySide6.QtWidgets import QMessageBox
        
        # Show warning dialog
        warning = QMessageBox()
        warning.setIcon(QMessageBox.Icon.Warning)
        warning.setWindowTitle("⚠️ DANGER: Order Fuzzing Warning")
        warning.setText(
            "<b>WARNING: Order Fuzzing can crash the target system!</b>"
        )
        warning.setInformativeText(
            "Order fuzzing injects malformed TN3270 protocol data. This can cause:\n\n"
            "• Protocol parser crashes\n"
            "• Terminal disconnection\n"
            "• System instability\n\n"
            "ONLY run this on test/development systems!\n\n"
            "By clicking 'I Understand', you confirm that:\n"
            "1. This is NOT a production system\n"
            "2. You have PERMISSION to test this system\n"
            "3. You accept responsibility for any consequences"
        )
        
        understand_btn = warning.addButton("I understand and have permission!", QMessageBox.ButtonRole.AcceptRole)
        warning.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        
        warning.exec()
        
        if warning.clickedButton() != understand_btn:
            return
        
        # Validate at least one order type is selected
        selected_orders = [k for k, cb in self.order_payloads.items() if cb.isChecked()]
        if not selected_orders:
            QMessageBox.warning(self, "No Orders Selected", 
                "Please select at least one order injection type.")
            return
        
        # Start order fuzzing
        self._start_order_fuzzing(selected_orders)
    
    def _start_order_fuzzing(self, order_types):
        """Initialize and start the order fuzzing process."""
        self.order_running = True
        self.order_paused = False
        self.order_finding_count = 0
        
        # Update UI state
        self.order_start_btn.setEnabled(False)
        self.order_stop_btn.setEnabled(True)
        self.order_pause_btn.setEnabled(True)
        self.order_resume_btn.setEnabled(False)
        self.order_status_label.setText("Initializing...")
        
        # Generate order payloads
        self.order_current_payloads = self._generate_order_payloads(order_types)
        self.order_current_index = 0
        
        total = len(self.order_current_payloads)
        self.order_progress_label.setText(f"0 / {total}")
        self.order_status_label.setText("Fuzzing...")
        self.order_status_label.setProperty("class", "status-info")
        self.order_status_label.style().unpolish(self.order_status_label)
        self.order_status_label.style().polish(self.order_status_label)
        
        # Get delay
        try:
            delay_ms = int(self.order_delay_input.text())
        except ValueError:
            delay_ms = 300
        
        # Start timer for fuzzing iterations
        self.order_timer = QTimer()
        self.order_timer.timeout.connect(self._order_fuzz_iteration)
        self.order_timer.start(delay_ms)
    
    def _generate_order_payloads(self, order_types):
        """Generate order injection payloads."""
        payloads = []
        
        order_bytes = {
            'sba': 0x11, 'sf': 0x1D, 'sfe': 0x29, 'sa': 0x28,
            'mf': 0x2C, 'ra': 0x3C, 'eua': 0x12, 'ic': 0x13,
            'pt': 0x05, 'ge': 0x08,
        }
        
        for order_type in order_types:
            if order_type in order_bytes:
                ob = order_bytes[order_type]
                # Repeated order bytes
                payloads.append({'type': order_type, 'data': bytes([ob] * 4), 'name': f'{order_type.upper()}-x4', 'is_binary': True})
                payloads.append({'type': order_type, 'data': bytes([ob] * 16), 'name': f'{order_type.upper()}-x16', 'is_binary': True})
            elif order_type == 'telnet_iac':
                payloads.append({'type': 'telnet', 'data': bytes([0xFF, 0xEF]), 'name': 'IAC-EOR', 'is_binary': True})
                payloads.append({'type': 'telnet', 'data': bytes([0xFF, 0xF0]), 'name': 'IAC-SE', 'is_binary': True})
                payloads.append({'type': 'telnet', 'data': bytes([0xFF, 0xFF, 0xFF, 0xFF]), 'name': 'IAC-FLOOD', 'is_binary': True})
            elif order_type == 'attr_bytes':
                for attr in [0x00, 0x20, 0x28, 0x2C, 0x0C, 0x30, 0x3C]:
                    payloads.append({'type': 'attr', 'data': bytes([0x1D, attr] * 4), 'name': f'SF-ATTR-{attr:02X}', 'is_binary': True})
            elif order_type == 'ext_attrs':
                payloads.append({'type': 'ext', 'data': bytes([0x29, 0x02, 0xC0, 0x00]), 'name': 'SFE-EXT-ATTR', 'is_binary': True})
                payloads.append({'type': 'ext', 'data': bytes([0x29, 0x03, 0x41, 0xF1, 0x42, 0xF4]), 'name': 'SFE-COLOR', 'is_binary': True})
            elif order_type == 'random_orders':
                import random
                for i in range(5):
                    data = bytes([random.choice([0x11, 0x1D, 0x29, 0x28, 0x2C, 0x3C]) for _ in range(8)])
                    payloads.append({'type': 'random', 'data': data, 'name': f'RANDOM-{i+1}', 'is_binary': True})
        
        return payloads
    
    def _order_fuzz_iteration(self):
        """Execute one order fuzzing iteration."""
        if not self.order_running or self.order_paused:
            return
        
        if self.order_current_index >= len(self.order_current_payloads):
            self._order_fuzz_complete()
            return
        
        payload = self.order_current_payloads[self.order_current_index]
        
        try:
            # Build and send the order fuzz packet
            self._send_order_fuzz_packet(payload)
            
            # Check response
            import time
            time.sleep(0.1)
            response = self.hack3270.get_last_server()
            response_len = len(self.hack3270.get_last_server_raw() or b'')
            
            # Check for abend
            abend = None
            response_upper = response.upper() if response else ''
            abend_patterns = ['DFHAC2', 'ABEND', 'ASRA', 'AICA', 'AEY7', 'APCT',
                              'SOC7', 'SOC4', 'S0C7', 'S0C4', 'ASRB', 'AEXL']
            for pattern in abend_patterns:
                if pattern in response_upper:
                    abend = pattern
                    break
            
            if abend:
                self._add_order_finding(payload, 'ABEND: ' + abend, response_len)
                if self.order_stop_on_abend.isChecked():
                    self._order_fuzz_complete(f"Stopped: ABEND {abend} detected")
                    return
            
        except Exception as e:
            error_str = str(e)
            if 'WinError 10053' in error_str or 'Connection' in error_str:
                self._add_order_finding(payload, 'CONNECTION LOST', 0)
                if self.order_stop_on_disconnect.isChecked():
                    self._order_fuzz_complete("Stopped: Connection lost")
                    return
            else:
                self._add_order_finding(payload, f'ERROR: {error_str}', 0)
        
        # Update progress
        self.order_current_index += 1
        total = len(self.order_current_payloads)
        self.order_progress_label.setText(f"{self.order_current_index} / {total}")
    
    def _send_order_fuzz_packet(self, payload):
        """Send an order fuzzing packet."""
        data = payload['data']
        name = payload['name']
        
        AID_ENTER = 0x7D
        SBA = 0x11
        
        # Check for TN3270E mode
        header = b''
        if hasattr(self.hack3270, 'check_inject_3270e') and self.hack3270.check_inject_3270e():
            header = b'\x00\x00\x00\x00\x01'
        
        cursor_addr = bytes([0x40, 0x40])  # Position 0
        packet = header + bytes([AID_ENTER, SBA]) + cursor_addr + data
        
        desc = f'Fuzz: Order/{name}'
        self.hack3270.api_send_raw(packet, desc)
    
    def _add_order_finding(self, payload, result, response_len):
        """Add a finding to the order findings tree."""
        self.order_finding_count += 1
        
        order_type = payload['type'].upper()
        payload_name = payload['name']
        
        item = FuzzingTreeWidgetItem([
            str(self.order_finding_count),
            order_type,
            payload_name,
            result,
            str(response_len)
        ])
        
        # Color-code based on result
        if 'ABEND' in result:
            for i in range(5):
                item.setBackground(i, QColor('#5c1a1a'))
        elif 'CONNECTION' in result:
            for i in range(5):
                item.setBackground(i, QColor('#5c3d1a'))
        elif 'ERROR' in result:
            for i in range(5):
                item.setBackground(i, QColor('#5c5c1a'))
        
        self.order_findings_tree.addTopLevelItem(item)
        self.order_findings_tree.scrollToItem(item)
    
    def _order_fuzz_complete(self, message=None):
        """Complete the order fuzzing process."""
        self.order_running = False
        self.order_paused = False
        
        if self.order_timer:
            self.order_timer.stop()
            self.order_timer = None
        
        self.order_start_btn.setEnabled(True)
        self.order_stop_btn.setEnabled(False)
        self.order_pause_btn.setEnabled(False)
        self.order_resume_btn.setEnabled(False)
        
        if message:
            self.order_status_label.setText(message)
        else:
            self.order_status_label.setText(f"Complete - {self.order_finding_count} findings")
        
        self.order_status_label.setProperty("class", "status-success" if self.order_finding_count == 0 else "status-warning")
        self.order_status_label.style().unpolish(self.order_status_label)
        self.order_status_label.style().polish(self.order_status_label)
    
    def on_order_fuzz_stop(self):
        """Handle Stop button click for Order Fuzzing."""
        self._order_fuzz_complete("Stopped by user")
    
    def on_order_fuzz_pause(self):
        """Handle Pause button click for Order Fuzzing."""
        self.order_paused = True
        self.order_pause_btn.setEnabled(False)
        self.order_resume_btn.setEnabled(True)
        self.order_status_label.setText("Paused")
    
    def on_order_fuzz_resume(self):
        """Handle Resume button click for Order Fuzzing."""
        self.order_paused = False
        self.order_pause_btn.setEnabled(True)
        self.order_resume_btn.setEnabled(False)
        self.order_status_label.setText("Fuzzing...")
    
    def on_order_clear_findings(self):
        """Clear all order findings."""
        self.order_findings_tree.clear()
        self.order_finding_count = 0
    
    def on_order_export(self):
        """Export order findings to CSV."""
        if self.order_findings_tree.topLevelItemCount() == 0:
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.information(self, "No Findings", "No findings to export.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Findings", "order_fuzz_findings.csv", "CSV Files (*.csv)"
        )
        
        if filename:
            try:
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["#", "Order", "Payload", "Result", "Response Length"])
                    
                    for i in range(self.order_findings_tree.topLevelItemCount()):
                        item = self.order_findings_tree.topLevelItem(i)
                        writer.writerow([item.text(j) for j in range(5)])
                
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.information(self, "Export Complete", 
                    f"Exported {self.order_findings_tree.topLevelItemCount()} findings to {filename}")
            except Exception as e:
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.critical(self, "Export Failed", f"Error: {str(e)}")

    def set_checkbox_values(self):
        self.hack3270.set_hack_prot(1 if self.hack_prot_cb.isChecked() else 0)
        self.hack3270.set_hack_hf(1 if self.hack_hf_cb.isChecked() else 0)
        self.hack3270.set_hack_rnr(1 if self.hack_rnr_cb.isChecked() else 0)
        self.hack3270.set_hack_sf(1 if self.hack_sf_cb.isChecked() else 0)
        self.hack3270.set_hack_sfe(1 if self.hack_sfe_cb.isChecked() else 0)
        self.hack3270.set_hack_mf(1 if self.hack_mf_cb.isChecked() else 0)
        self.hack3270.set_hack_ei(1 if self.hack_ei_cb.isChecked() else 0)
        self.hack3270.set_hack_hv(1 if self.hack_hv_cb.isChecked() else 0)
        self.hack3270.set_hack_color_sfe(1 if self.hack_color_sfe_cb.isChecked() else 0)
        self.hack3270.set_hack_color_mf(1 if self.hack_color_mf_cb.isChecked() else 0)
        self.hack3270.set_hack_color_sa(1 if self.hack_color_sa_cb.isChecked() else 0)
        self.hack3270.set_hack_color_hv(1 if self.hack_color_hv_cb.isChecked() else 0)
    
    def browse_files(self):
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select file for injections", "injections",
            "Text Files (*.txt);;All Files (*)")
        if filename:
            self.inject_filename = filename
            self.inject_status.setText(f"Filename set to: {filename}")
            self.inject_status.setProperty("class", "status-ready")
        else:
            self.inject_status.setText("Error: file not set.")
            self.inject_status.setProperty("class", "status-error")
        self.inject_status.style().unpolish(self.inject_status)
        self.inject_status.style().polish(self.inject_status)
    
    def inject_setup(self):
        mask = self.mask_combo.currentText()
        self.inject_status.setText(f"Submit data using mask character of '{mask}' to setup injection.")
        self.inject_status.setProperty("class", "status-warning")
        self.inject_status.style().unpolish(self.inject_status)
        self.inject_status.style().polish(self.inject_status)
        QApplication.processEvents()
        self.hack3270.set_inject_mask(mask)
        self.hack3270.set_inject_setup_capture()
    
    def _load_inject_file(self):
        """Load injection file into memory if not already loaded"""
        if not self.inject_lines and self.inject_filename:
            with open(self.inject_filename, 'r') as f:
                self.inject_lines = [line.rstrip() for line in f]
            self.inject_index = 0
    
    def _inject_one_line(self, line):
        """Inject a single line and handle key mode"""
        mode = self.mode_combo.currentText()
        mask_len = self.hack3270.get_inject_mask_len()
        
        if mode == 'TRUNC':
            line = line[:mask_len]
        
        # OVERFLOW mode bypasses length check, SKIP mode skips long entries
        should_inject = (mode == 'OVERFLOW' or len(line) <= mask_len)
        
        if should_inject:
            injection_ebcdic = self.hack3270.get_ebcdic(line)
            bytes_ebcdic = (self.hack3270.get_inject_preamble() + 
                           injection_ebcdic + 
                           self.hack3270.get_inject_postamble())
            self.hack3270.write_log('C', 'Sending: ' + line, bytes_ebcdic)
            self.hack3270.send_server(bytes_ebcdic)
            overflow_note = " [OVERFLOW]" if len(line) > mask_len else ""
            self.inject_status.setText(f"Sending: {line}{overflow_note}")
            self.inject_status.setProperty("class", "status-info")
            self.inject_status.style().unpolish(self.inject_status)
            self.inject_status.style().polish(self.inject_status)
            QApplication.processEvents()
            self.hack3270.tend_server()
            
        key_mode = self.keys_combo.currentText()
        if key_mode == 'ENTER+CLEAR':
            self.hack3270.send_key('CLEAR', b'\x6d')
        elif key_mode == 'ENTER+PF3':
            self.hack3270.send_key('PF3', b'\xf3')
        elif key_mode == 'ENTER+PF3+CLEAR':
            self.hack3270.send_key('PF3', b'\xf3')
            self.hack3270.send_key('CLEAR', b'\x6d')
    
    def _check_inject_ready(self):
        """Check if injection is ready, return True if ready"""
        if not self.inject_filename and not self.hack3270.get_inject_config_set():
            self.inject_status.setText("First select a file for injection, then click SETUP.")
            self.inject_status.setProperty("class", "status-error")
            self.inject_status.style().unpolish(self.inject_status)
            self.inject_status.style().polish(self.inject_status)
            return False
        
        if not self.inject_filename:
            self.inject_status.setText("Injection file not set. Click FILE.")
            self.inject_status.setProperty("class", "status-error")
            self.inject_status.style().unpolish(self.inject_status)
            self.inject_status.style().polish(self.inject_status)
            return False
        
        if not self.hack3270.get_inject_config_set():
            self.inject_status.setText("Field for injection hasn't been setup. Click SETUP.")
            self.inject_status.setProperty("class", "status-error")
            self.inject_status.style().unpolish(self.inject_status)
            self.inject_status.style().polish(self.inject_status)
            return False
        
        return True
    
    def inject_step(self):
        """Inject just ONE entry and stop"""
        if not self._check_inject_ready():
            return
        
        self._load_inject_file()
        
        if self.inject_index >= len(self.inject_lines):
            self.inject_status.setText("Injection complete. Click RESET to start over.")
            self.inject_status.setProperty("class", "status-ready")
            self.inject_status.style().unpolish(self.inject_status)
            self.inject_status.style().polish(self.inject_status)
            return
        
        line = self.inject_lines[self.inject_index]
        self._inject_one_line(line)
        self.inject_index += 1
        
        self.inject_status.setText(f"Stepped [{self.inject_index}/{len(self.inject_lines)}]: {line}")
        self.inject_status.setProperty("class", "status-warning")
        self.inject_status.style().unpolish(self.inject_status)
        self.inject_status.style().polish(self.inject_status)
    
    def inject_go(self):
        """Inject all remaining entries automatically"""
        if not self._check_inject_ready():
            return

        self._load_inject_file()
        self.inject_stop_flag = False
        self.inject_pause_flag = False
        
        while self.inject_index < len(self.inject_lines):
            # Check if stop was requested
            if self.inject_stop_flag:
                self.inject_status.setText(f"Stopped at [{self.inject_index}/{len(self.inject_lines)}]")
                self.inject_status.setProperty("class", "status-warning")
                self.inject_status.style().unpolish(self.inject_status)
                self.inject_status.style().polish(self.inject_status)
                return
            
            # Wait while paused
            while self.inject_pause_flag:
                if self.inject_stop_flag:
                    self.inject_status.setText(f"Stopped at [{self.inject_index}/{len(self.inject_lines)}]")
                    self.inject_status.setProperty("class", "status-warning")
                    self.inject_status.style().unpolish(self.inject_status)
                    self.inject_status.style().polish(self.inject_status)
                    return
                QApplication.processEvents()
            
            line = self.inject_lines[self.inject_index]
            self._inject_one_line(line)
            self.inject_index += 1
        
        self.inject_status.setText(f"Injection complete [{len(self.inject_lines)}/{len(self.inject_lines)}]")
        self.inject_status.setProperty("class", "status-ready")
        self.inject_status.style().unpolish(self.inject_status)
        self.inject_status.style().polish(self.inject_status)

    def inject_pause(self):
        self.inject_pause_flag = True
        self.inject_status.setText(f"Paused at [{self.inject_index}/{len(self.inject_lines)}]")
        self.inject_status.setProperty("class", "status-warning")
        self.inject_status.style().unpolish(self.inject_status)
        self.inject_status.style().polish(self.inject_status)
    
    def inject_resume(self):
        self.inject_pause_flag = False
        self.inject_status.setText("Injection resumed.")
        self.inject_status.setProperty("class", "status-info")
        self.inject_status.style().unpolish(self.inject_status)
        self.inject_status.style().polish(self.inject_status)
    
    def inject_stop(self):
        self.inject_stop_flag = True
        self.inject_pause_flag = False  # Clear pause flag so stop takes effect
    
    def inject_reset(self):
        self.hack3270.set_inject_config_set(0)
        self.last_inject_config_set = False
        self.inject_stop_flag = False
        self.inject_pause_flag = False
        self.inject_lines = []  # Clear loaded lines
        self.inject_index = 0   # Reset position
        self.inject_status.setText("Configuration cleared.")
        self.inject_status.setProperty("class", "status-warning")
        self.inject_status.style().unpolish(self.inject_status)
        self.inject_status.style().polish(self.inject_status)
    
    def send_keys(self):
        self.send_keys_stop_flag = False  # Reset stop flag
        for aid_name, byte_code in libhack3270.hack3270.AIDS.items():
            # Check if stop was requested
            if self.send_keys_stop_flag:
                self.send_label.setText("Stopped.")
                self.send_label.setProperty("class", "status-warning")
                self.send_label.style().unpolish(self.send_label)
                self.send_label.style().polish(self.send_label)
                return
            
            if aid_name in self.aid_checkboxes and self.aid_checkboxes[aid_name].isChecked():
                # Update status to show which key is being sent
                self.send_label.setText(f"Sending: {aid_name}")
                self.send_label.setProperty("class", "status-warning")
                self.send_label.style().unpolish(self.send_label)
                self.send_label.style().polish(self.send_label)
                QApplication.processEvents()
                
                self.hack3270.send_key(aid_name, byte_code)
        
        # Reset to Ready when done
        self.send_label.setText("Ready.")
        self.send_label.setProperty("class", "status-ready")
        self.send_label.style().unpolish(self.send_label)
        self.send_label.style().polish(self.send_label)
    
    def send_keys_stop(self):
        self.send_keys_stop_flag = True
        
    def fetch_item(self):
        items = self.log_tree.selectedItems()
        if not items:
            return
        item = items[0]
        record_id = int(item.text(0))
        record_cs = item.text(2)

        for row in self.hack3270.get_log(record_id):
            ebcdic_data = self.hack3270.get_ascii(row[5])
            if re.search("^tn3270 ", row[3]):
                parsed_3270 = self.hack3270.parse_telnet(ebcdic_data)
            else:
                parsed_3270 = self.hack3270.parse_3270(ebcdic_data)
            self.log_detail.setPlainText(parsed_3270)
            
            if record_cs == "Server" and self.auto_server_cb.isChecked():
                self.hack3270.send_client(row[5])
            if record_cs == "Client" and self.auto_client_cb.isChecked():
                self.hack3270.send_server(row[5])
    
    def export_csv(self):
        self.export_label.setText("Starting export...")
        self.export_label.setProperty("class", "status-warning")
        self.export_label.style().unpolish(self.export_label)
        self.export_label.style().polish(self.export_label)
        QApplication.processEvents()
        
        csv_filename = self.hack3270.export_csv()
        self.export_label.setText(f"Export finished: {csv_filename}")
        self.export_label.setProperty("class", "status-ready")
        self.export_label.style().unpolish(self.export_label)
        self.export_label.style().polish(self.export_label)
    
    def export_visible_csv(self):
        """Export only visible (filtered) log entries to a user-specified CSV file."""
        # Count visible items
        visible_count = 0
        for i in range(self.log_tree.topLevelItemCount()):
            if not self.log_tree.topLevelItem(i).isHidden():
                visible_count += 1
        
        if visible_count == 0:
            self.export_label.setText("No visible entries to export.")
            self.export_label.setProperty("class", "status-warning")
            self.export_label.style().unpolish(self.export_label)
            self.export_label.style().polish(self.export_label)
            return
        
        # Prompt for filename
        default_name = f"{self.hack3270.project_name}_filtered.csv"
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Visible Logs", default_name, "CSV Files (*.csv);;All Files (*)"
        )
        
        if not filename:
            return  # User cancelled
        
        self.export_label.setText(f"Exporting {visible_count} entries...")
        self.export_label.setProperty("class", "status-warning")
        self.export_label.style().unpolish(self.export_label)
        self.export_label.style().polish(self.export_label)
        QApplication.processEvents()
        
        try:
            with open(filename, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                # Write header
                writer.writerow(["ID", "Timestamp", "Sender", "Notes", "Length", "Data"])
                
                # Iterate visible items and export
                for i in range(self.log_tree.topLevelItemCount()):
                    item = self.log_tree.topLevelItem(i)
                    if not item.isHidden():
                        item_id = int(item.text(0))
                        # Get full record from database
                        records = self.hack3270.get_log(item_id)
                        if records and len(records) > 0:
                            row = records[0]
                            ebcdic_data = self.hack3270.get_ascii(row[5])
                            if re.search("^tn3270 ", row[3]):
                                parsed_3270 = self.hack3270.parse_telnet(ebcdic_data)
                            else:
                                parsed_3270 = self.hack3270.parse_3270(ebcdic_data)
                            data = parsed_3270.replace('\n', ' ')
                            writer.writerow([row[0], row[1], row[2], row[3], row[4], data])
            
            self.export_label.setText(f"Exported {visible_count} entries to {filename}")
            self.export_label.setProperty("class", "status-ready")
        except Exception as e:
            self.export_label.setText(f"Export failed: {str(e)}")
            self.export_label.setProperty("class", "status-warning")
        
        self.export_label.style().unpolish(self.export_label)
        self.export_label.style().polish(self.export_label)
    
    def toggle_log_follow(self):
        """Toggle log follow mode - auto-scroll to latest entry."""
        self.log_follow_mode = self.log_follow_btn.isChecked()
        if self.log_follow_mode:
            self.log_follow_btn.setText("Follow: ON")
            self.log_follow_btn.setProperty("class", "success")
            # Jump to latest entry immediately
            if self.log_tree.topLevelItemCount() > 0:
                last_item = self.log_tree.topLevelItem(self.log_tree.topLevelItemCount() - 1)
                self.log_tree.scrollToItem(last_item)
                self.log_tree.setCurrentItem(last_item)
        else:
            self.log_follow_btn.setText("Follow: OFF")
            self.log_follow_btn.setProperty("class", "")
        self.log_follow_btn.style().unpolish(self.log_follow_btn)
        self.log_follow_btn.style().polish(self.log_follow_btn)
    
    def filter_logs(self):
        """Filter log entries by EBCDIC-converted search string."""
        search_text = self.log_search_field.text()
        if not search_text:
            # Show all items when search is empty
            for i in range(self.log_tree.topLevelItemCount()):
                self.log_tree.topLevelItem(i).setHidden(False)
            return
        
        # Convert search text to EBCDIC bytes
        try:
            ebcdic_search = self.hack3270.get_ebcdic(search_text)
        except:
            return  # Invalid characters, skip filtering
        
        # Iterate through all tree items
        for i in range(self.log_tree.topLevelItemCount()):
            item = self.log_tree.topLevelItem(i)
            item_id = int(item.text(0))
            
            # Get the log record from database
            try:
                records = self.hack3270.get_log(item_id)
                if records and len(records) > 0:
                    record = records[0]  # get_log returns fetchall(), take first row
                    # record[5] is the RAW_DATA binary blob
                    binary_data = record[5] if len(record) > 5 else b''
                    # Check if EBCDIC search string is in the binary data
                    if ebcdic_search in binary_data:
                        item.setHidden(False)
                    else:
                        item.setHidden(True)
                else:
                    item.setHidden(True)
            except:
                item.setHidden(True)
    
    def clear_log_search(self):
        """Clear the log search field, show all entries, and scroll to the last one."""
        self.log_search_field.clear()
        self.filter_logs()  # Show all entries since search text is now empty
        # Scroll to and select the last entry
        if self.log_tree.topLevelItemCount() > 0:
            last_item = self.log_tree.topLevelItem(self.log_tree.topLevelItemCount() - 1)
            self.log_tree.setCurrentItem(last_item)
            self.log_tree.scrollToItem(last_item, QTreeWidget.PositionAtBottom)
    
    def get_elapsed_time(self, elapsed):
        if elapsed < 60:
            return f"{int(elapsed)} seconds"
        elif elapsed < 3600:
            minutes = int(elapsed // 60)
            seconds = int(elapsed % 60)
            return f"{minutes} minutes and {seconds} seconds"
        elif elapsed < 86400:
            hours = int(elapsed // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = int(elapsed % 60)
            return f"{hours} hours, {minutes} minutes and {seconds} seconds"
        else:
            days = int(elapsed // 86400)
            hours = int((elapsed % 86400) // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = int(elapsed % 60)
            return f"{days} days, {hours} hours, {minutes} minutes and {seconds} seconds"
    
    def aid_refresh(self):
        """Auto-disable PF keys that appear in screen text (user can still re-enable them)"""
        aids = self.hack3270.current_aids()
        # Only disable PF keys that are found on screen - don't reset all checkboxes
        # This preserves user's manual selections
        for i in range(1, 25):
            pf_name = f'PF{i}'
            if pf_name in aids and pf_name in self.aid_checkboxes:
                self.aid_checkboxes[pf_name].setChecked(False)
    
    def aid_clear_all(self):
        """Uncheck all AID checkboxes"""
        for cb in self.aid_checkboxes.values():
            cb.setChecked(False)
    
    def aid_setdef(self):
        """Reset all AID checkboxes to defaults"""
        defaults = {
            'NO': True, 'QREPLY': True, 'ENTER': False,
            'OICR': True, 'MSR_MHS': True, 'SELECT': True,
            'PA1': True, 'PA2': True, 'PA3': True,
            'CLEAR': False, 'SYSREQ': True
        }
        for name, checked in defaults.items():
            if name in self.aid_checkboxes:
                self.aid_checkboxes[name].setChecked(checked)
        for i in range(1, 25):
            pf_name = f'PF{i}'
            if pf_name in self.aid_checkboxes:
                self.aid_checkboxes[pf_name].setChecked(True)
                
    def closeEvent(self, event):
        # Stop the timer first to prevent run_loop from accessing closed sockets
        self.timer.stop()
        self.hack3270.on_closing()
        event.accept()


# Connection dialog for initial setup
class ConnectionDialog(QWidget):
    """Simple dialog shown during connection setup"""
    def __init__(self, message):
        super().__init__()
        self.setWindowTitle("Hack3270")
        self.setStyleSheet(DARK_STYLE)
        
        # Get screen size and set window to half width, at top of screen
        screen = QApplication.primaryScreen().geometry()
        dialog_width = screen.width() // 2
        dialog_height = 100
        self.setFixedSize(dialog_width, dialog_height)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        self.label = QLabel(message)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setWordWrap(True)
        self.label.setFont(QFont("Segoe UI", 12))
        layout.addWidget(self.label)
        
        self.button = QPushButton("Click to Continue")
        self.button.setVisible(False)
        self.button.clicked.connect(self.accept_click)
        layout.addWidget(self.button)
        
        self.clicked = False
        
        # Position at top of screen, centered horizontally
        self.move((screen.width() - dialog_width) // 2, 0)
        
    def set_message(self, message):
        self.label.setText(message)
        QApplication.processEvents()
        
    def show_button(self):
        self.button.setVisible(True)
        QApplication.processEvents()
        
    def accept_click(self):
        self.clicked = True
        
    def wait_for_click(self):
        while not self.clicked:
            QApplication.processEvents()


# Compatibility wrapper for existing code
class tkhack3270:
    """Wrapper class for compatibility with existing hack3270.py"""
    def __init__(self, root, style, hack3270, logfile=None, loglevel=logging.WARNING):
        # root parameter is ignored - we create our own QApplication
        self.app = QApplication.instance() or QApplication(sys.argv)
        
        # Handle initial connection flow - always wait for client first
        ip, port = hack3270.get_proxy_ip_port()
        
        # Show connection waiting dialog
        dialog = ConnectionDialog(f"Waiting for TN3270 connection on {ip}:{port}")
        dialog.show()
        QApplication.processEvents()
        
        # This blocks until a client connects
        hack3270.client_connect()
        
        # Update dialog and wait for user click
        dialog.set_message("Connection received.")
        dialog.show_button()
        dialog.wait_for_click()
        dialog.close()
        
        if not hack3270.is_offline():
            # Online mode - connect to the server
            hack3270.server_connect()
            hack3270.check_inject_3270e()
        else:
            # Offline mode - replay recorded data to client
            my_record_num = 1
            while hack3270.check_record(my_record_num):
                if hack3270.check_server(my_record_num):
                    hack3270.play_record(my_record_num)
                else:
                    hack3270.recv()
                my_record_num += 1
            while hack3270.check_server(my_record_num):
                hack3270.play_record(my_record_num)
                my_record_num += 1
        
        # Start the Web API listener (not in offline mode)
        if not hack3270.is_offline():
            hack3270.api_start()
        
        self.window = Hack3270GUI(hack3270, logfile, loglevel)
        self.window.show()
        self.app.exec()
