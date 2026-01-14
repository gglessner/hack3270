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
        self.tab3_height = 180   # Tab 3: AID Spoofing (same as Inject Into Fields)
        self.tab5_height = 425   # Tab 5: Statistics
        self.tall_height = 525   # Tabs 4 & 6: Logs and Help
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
        self.create_logs_tab()
        self.create_analysis_tab()
        self.create_statistics_tab()
        self.create_help_tab()
        
        # Disable tabs in offline mode
        if self.hack3270.is_offline():
            for i in range(4):  # Disable first 4 tabs (including AID Spoofing)
                self.tabs.setTabEnabled(i, False)
        
        # Full horizontal width, start with tab 0 height
        self.resize(self.screen_width, self.tab0_height)
        self.setMinimumWidth(self.screen_width)  # Prevent making it narrower
        self.setMinimumHeight(100)  # Safety net for minimum height
        self.move(0, 0)  # Start at top of screen
        
        # Apply sizing to the initial tab
        self.on_tab_changed(self.tabs.currentIndex())
        
    def on_tab_changed(self, index):
        """Keep full width, minimize height on compact tabs, restore tall on Logs/Analysis/Help"""
        # Tab indices: 0=Hack Fields, 1=Inject Fields, 2=Inject Keys, 3=AID Spoofing, 4=Logs, 5=Analysis, 6=Statistics, 7=Help
        
        # Save tall height when leaving tall tabs (Logs, Analysis, Help)
        if self.last_tab_index in [4, 5, 7]:
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
        elif index == 6:  # Statistics
            self.resize(self.screen_width, self.tab5_height)
        
        elif index in [4, 5, 7]:  # Logs, Analysis, or Help
            if index == 4:
                self.update_logs_tab()
                # Scroll to last item on first visit to Logs tab
                if not self.logs_initial_scroll_done and self.log_tree.topLevelItemCount() > 0:
                    self.logs_initial_scroll_done = True
                    QApplication.processEvents()  # Ensure UI is ready
                    last_item = self.log_tree.topLevelItem(self.log_tree.topLevelItemCount() - 1)
                    self.log_tree.setCurrentItem(last_item)
                    self.log_tree.scrollToItem(last_item, QTreeWidget.PositionAtBottom)
            target_height = max(self.user_tall_height, 500)
            if self.height() < target_height:
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
        
        # Stats group
        stats_group = QGroupBox("Session Statistics")
        stats_layout = QGridLayout(stats_group)
        stats_layout.setSpacing(10)
        
        ip, port = self.hack3270.get_ip_port()
        
        # Calculate statistics
        total_connections = 0
        total_time = 0.0
        last_timestamp = 0.0
        start_timestamp = 0.0
        total_injections = 0
        total_hacks = 0
        server_messages = 0
        server_bytes = 0
        client_messages = 0
        client_bytes = 0

        for record in self.hack3270.all_logs():
            curr_timestamp = float(record[1])
            if record[2] == 'C':
                client_messages += 1
                client_bytes += record[4]
            else:
                server_messages += 1
                server_bytes += record[4]
            if record[2] == 'C' and "Send" in record[3]:
                total_injections += 1
            if record[2] == 'S' and "ENABLED" in record[3]:
                total_hacks += 1
            if record[2] == 'S' and record[4] == 3:
                total_connections += 1
                start_timestamp = curr_timestamp
                if last_timestamp > 0:
                    total_time += start_timestamp - last_timestamp
            else:
                last_timestamp = curr_timestamp
        total_time += start_timestamp - last_timestamp

        stats = [
            ("Server IP Address:", str(ip)),
            ("Server TCP Port:", str(port)),
            ("TLS Enabled:", str(self.hack3270.get_tls())),
            ("Total TCP Connections:", str(total_connections)),
            ("Total Server Messages:", str(server_messages)),
            ("Total Client Messages:", str(client_messages)),
            ("Total Server Bytes:", str(server_bytes)),
            ("Total Client Bytes:", str(client_bytes)),
            ("Total Hacks:", str(total_hacks)),
            ("Total Injections:", str(total_injections)),
            ("Total Connect Time:", self.get_elapsed_time(total_time)),
        ]
        
        for i, (label, value) in enumerate(stats):
            lbl = QLabel(label)
            lbl.setProperty("class", "header")
            lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            stats_layout.addWidget(lbl, i, 0)
            
            val = QLabel(value)
            val.setProperty("class", "status-info")
            stats_layout.addWidget(val, i, 1)
        
        layout.addWidget(stats_group)
        layout.addSpacing(20)
        self.tabs.addTab(tab, "Statistics")
    
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
        
        hidden_values = 0
        hidden_labels = 0
        key_transitions = 0
        field_transitions = 0
        
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
        
        self.window = Hack3270GUI(hack3270, logfile, loglevel)
        self.window.show()
        self.app.exec()
