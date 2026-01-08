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
    QSplitter, QFrame, QScrollArea, QSizePolicy
)

class NumericTreeWidgetItem(QTreeWidgetItem):
    """Custom QTreeWidgetItem that sorts numerically for ID (col 0) and Length (col 3)"""
    def __lt__(self, other):
        column = self.treeWidget().sortColumn()
        if column in (0, 3):  # ID and Length columns
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
        self.inject_filename = ""
        self.last_inject_config_set = False  # Track inject config state changes
        self.inject_stop_flag = False  # Flag to stop injection loop
        self.inject_pause_flag = False  # Flag to pause injection loop
        self.inject_lines = []  # Lines loaded from injection file
        self.inject_index = 0   # Current position in injection file
        self.send_keys_stop_flag = False  # Flag to stop send keys loop

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
        self.tab4_height = 425   # Tab 4: Statistics
        self.tall_height = 525   # Tabs 3 & 5: Logs and Help
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
        self.create_logs_tab()
        self.create_statistics_tab()
        self.create_help_tab()
        
        # Disable tabs in offline mode
        if self.hack3270.is_offline():
            for i in range(3):
                self.tabs.setTabEnabled(i, False)
        
        # Full horizontal width, start with tab 0 height
        self.resize(self.screen_width, self.tab0_height)
        self.setMinimumWidth(self.screen_width)  # Prevent making it narrower
        self.setMinimumHeight(100)  # Safety net for minimum height
        self.move(0, 0)  # Start at top of screen
        
        # Apply sizing to the initial tab
        self.on_tab_changed(self.tabs.currentIndex())
        
    def on_tab_changed(self, index):
        """Keep full width, minimize height on compact tabs, restore tall on Logs/Help"""
        # Save tall height when leaving Logs or Help
        if self.last_tab_index in [3, 5]:
            self.user_tall_height = self.height()
        
        # Handle height - each tab has its own height
        if index == 0:  # Hack Field Attributes
            self.resize(self.screen_width, self.tab0_height)
        elif index == 1:  # Inject Into Fields
            self.resize(self.screen_width, self.tab1_height)
        elif index == 2:  # Inject Key Presses
            self.resize(self.screen_width, self.tab2_height)
        elif index == 4:  # Statistics
            self.resize(self.screen_width, self.tab4_height)
        
        elif index in [3, 5]:  # Logs or Help
            if index == 3:
                self.update_logs_tab()
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
            self.hack3270.daemon()
            if self.tabs.currentIndex() == 2:  # Inject Keys tab
                self.aid_refresh()
            
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
        self.mode_combo.addItems(["SKIP", "TRUNC"])
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
        
        self.send_label = QLabel("Ready.")
        self.send_label.setProperty("class", "status-ready")
        top_layout.addWidget(self.send_label)
        top_layout.addStretch()
        layout.addLayout(top_layout)
        
        # AID checkboxes in scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setMaximumHeight(200)
        
        aid_widget = QWidget()
        aid_layout = QGridLayout(aid_widget)
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
        
        scroll.setWidget(aid_widget)
        layout.addWidget(scroll)
        
        layout.addSpacing(20)
        self.tabs.addTab(tab, "Inject Key Presses")
        
    def create_logs_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Tree widget
        self.log_tree = QTreeWidget()
        self.log_tree.setHeaderLabels(["ID", "Timestamp", "Sender", "Length", "Notes"])
        self.log_tree.setAlternatingRowColors(True)
        self.log_tree.setSortingEnabled(True)
        self.log_tree.header().setSectionResizeMode(4, QHeaderView.Stretch)
        self.log_tree.itemSelectionChanged.connect(self.fetch_item)
        layout.addWidget(self.log_tree, 1)

        self.update_logs_tab()

        # Detail text
        self.log_detail = QTextEdit()
        self.log_detail.setReadOnly(True)
        self.log_detail.setMaximumHeight(200)
        layout.addWidget(self.log_detail)
        
        # Bottom controls
        bottom_layout = QHBoxLayout()
        self.auto_server_cb = QCheckBox("Auto Send Server")
        self.auto_server_cb.setChecked(True)
        bottom_layout.addWidget(self.auto_server_cb)
        
        self.auto_client_cb = QCheckBox("Auto Send Client")
        bottom_layout.addWidget(self.auto_client_cb)
        
        bottom_layout.addSpacing(30)
        
        export_btn = QPushButton("Export to CSV")
        export_btn.clicked.connect(self.export_csv)
        bottom_layout.addWidget(export_btn)
        
        self.export_label = QLabel("Ready.")
        self.export_label.setProperty("class", "status-ready")
        bottom_layout.addWidget(self.export_label)
        
        bottom_layout.addStretch()
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
        for row in self.hack3270.all_logs(self.last_db_id):
            item = NumericTreeWidgetItem([
                str(row[0]),
                str(datetime.datetime.fromtimestamp(float(row[1]))),
                self.hack3270.expand_CS(row[2]),
                str(row[4]),
                row[3]
            ])
            self.log_tree.addTopLevelItem(item)
            self.last_db_id = int(row[0])
            
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
        if self.mode_combo.currentText() == 'TRUNC':
            line = line[:self.hack3270.get_inject_mask_len()]
            
        if len(line) <= self.hack3270.get_inject_mask_len():
            injection_ebcdic = self.hack3270.get_ebcdic(line)
            bytes_ebcdic = (self.hack3270.get_inject_preamble() + 
                           injection_ebcdic + 
                           self.hack3270.get_inject_postamble())
            self.hack3270.write_log('C', 'Sending: ' + line, bytes_ebcdic)
            self.hack3270.send_server(bytes_ebcdic)
            self.inject_status.setText(f"Sending: {line}")
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
        aids = self.hack3270.current_aids()
        self.aid_setdef()
        for i in range(1, 25):
            pf_name = f'PF{i}'
            if pf_name in aids and pf_name in self.aid_checkboxes:
                self.aid_checkboxes[pf_name].setChecked(False)
    
    def aid_setdef(self):
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
