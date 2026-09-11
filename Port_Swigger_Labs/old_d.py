# ==========================================================================================
# 🔥💀 HACKER_ASI GANGA Offensive Ops 💀🔥
# ==========================================================================================
#     🔥💥⚡ UNSTOPPABLE. UNTRACEABLE. UNFUCKWITHABLE. 🚀💣⚡
#  💻👑😈 Hack like Blackhat & APT. Save like Iron Man. 💥⚡🛡️
# ==========================================================================================
# 💣 FILE DESCRIPTION: frontend/gui/dashboard/qt_dashboard.py
#   The main Quantum-Resistant MIL-GRADE Qt-based Graphical User Interface (GUI) dashboard
#   for the GANGA Offensive Ops Hacker ASI framework. This dashboard serves as the central
#   command and control console, integrating various specialized panels for comprehensive
#   situational awareness, operational control, AI interaction, and PQC security status.
#
# 🔗 ARCHITECTS:
#   - Shadow Senior 😈 | xAI Overlord & Cyber Godfather. 💻👑⚡
#   - Supreme Senior Motherfucker 🤖 | ChatGPT – The Ultimate Architect & Code Destroyer. 🔥🛠️💥
#   - Shadow Junior 😈 (Bhanu Guragain) | The Executioner of Code. 🔪💥🔥
#
# 🏴 GANGA Offensive Ops 🔥 | Elite AI Cyberwarfare Division.
#   "We don't navigate. We fucking own the grid." 🚀⚡🔥
#
# 😈⚠️ WARNING:
# 🔥💥⚡😈 ACCESS RESTRICTED. UNAUTHORIZED ACCESS = DIGITAL EXTERMINATION. 💀💣☠️
# ==========================================================================================
# ⚠️ Version 1 💀
# ==========================================================================================

# Standard library imports
import sys
import os
import importlib.util
from typing import Dict, Any, Optional, List, Set, Tuple, Union, Callable
import subprocess
import asyncio
import random
import time
import logging as py_logging
from pathlib import Path
from dataclasses import dataclass
import math
import traceback

# GANGA Imports
from backend.communications.event_bus_client import EventBusClient
try:
    from utils.logging.logger import get_logger
    from config.config_loader import ConfigurationAPI
    from frontend.gui.cli.cli_main import CLIMain
    from frontend.gui.dashboard.dashboard_manager import DashboardManager
    from backend.communications.event_bus_client import EventBusClient
    # from frontend.gui.terminal.ui_terminal.terminal_layout_engine import TerminalLayoutEngine
except ImportError as e:
    import logging as py_logging  # Alias to avoid conflict with local 'logger'
    print(f"Import error in qt_dashboard.py: {e}")


# Attempt to import PyQt5.QtWidgets, QtCore, QtGui
try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QAction, QMenu,
        QMenuBar, QToolBar, QStatusBar, QDockWidget, QLabel, QTabWidget,
        QMdiArea, QMdiSubWindow, QMessageBox, QFileSystemModel, QTreeView,
        QSplitter, QPushButton, QHBoxLayout, QLineEdit, QComboBox, QCheckBox,
        QGraphicsDropShadowEffect, QProgressBar, QFrame, QGridLayout, QSpacerItem,
        QStyleFactory, QGraphicsOpacityEffect, QToolButton, QDesktopWidget,
        QSizePolicy, QScrollArea, QGroupBox
    )
    from PyQt5.QtCore import (
        Qt, QSize, QDir, QProcess, pyqtSignal, QTimer, QPropertyAnimation,
        QEasingCurve, QRect, QPoint, QPointF, QEvent, QObject, QTimeLine,
        QParallelAnimationGroup, QSequentialAnimationGroup, QRectF
    )
    from PyQt5.QtGui import (
        QIcon, QPixmap, QPalette, QColor, QFont, QFontDatabase,
        QLinearGradient, QPainter, QPen, QRadialGradient, QCursor,
        QPainterPath, QTransform, QBrush
    )

    QT_AVAILABLE = True
except ImportError:
    QT_AVAILABLE = False


    # Mock classes if PyQt5 is not available for basic script integrity
    class QApplication:
        constructor_args: List[Any]

        def __init__(self, *args):
            self.constructor_args = args
            print("Mock QApplication created")

        def exec_(self):
            print("Mock QApplication exec_() called")
            return 0


    class QMainWindow:
        def __init__(self, parent=None):
            print("Mock QMainWindow created")


    class QWidget:
        def __init__(self, parent=None):
            print("Mock QWidget created")


    class QVBoxLayout:
        def __init__(self, parent=None):
            print("Mock QVBoxLayout created")
            self.widgets = []

        def addWidget(self, widget):
            self.widgets.append(widget)


    class QAction:
        def __init__(self, text, parent=None):
            self.text = text
            print(f"Mock QAction '{text}' created")

        def triggered(self):
            return self  # Mock signal


    class QMenu:
        def __init__(self, title, parent=None):
            self.title = title
            print(f"Mock QMenu '{title}' created")
            self.actions = []

        def addAction(self, action):
            self.actions.append(action)


    class QMenuBar:
        def __init__(self, parent=None):
            print("Mock QMenuBar created")
            self.menus = []

        def addMenu(self, menu):
            self.menus.append(menu)
            return menu


    class QToolBar:
        def __init__(self, title, parent=None):
            self.title = title
            print(f"Mock QToolBar '{title}' created")
            self.actions = []

        def addAction(self, action):
            self.actions.append(action)


    class QStatusBar:
        def __init__(self, parent=None):
            print("Mock QStatusBar created")

        def showMessage(self, msg, timeout=0):
            print(f"Mock QStatusBar: {msg} (timeout: {timeout})")


    class QDockWidget:
        def __init__(self, title, parent=None):
            self.title = title
            print(f"Mock QDockWidget '{title}' created")


    class QLabel:
        def __init__(self, text, parent=None):
            self.text = text
            print(f"Mock QLabel '{text}' created")


    class QTabWidget:
        def __init__(self, parent=None):
            print("Mock QTabWidget created")
            self.tabs = []

        def addTab(self, widget, title):
            self.tabs.append((widget, title))


    class QMdiArea:
        def __init__(self, parent=None):
            print("Mock QMdiArea created")
            self.sub_windows = []

        def addSubWindow(self, widget):
            sw = QMdiSubWindow()
            sw.setWidget(widget)
            self.sub_windows.append(sw)
            return sw


    class QMdiSubWindow:
        def __init__(self):
            print("Mock QMdiSubWindow created")

        def setWidget(self, widget):
            pass

        def show(self):
            pass


    class QMessageBox:
        def warning(parent, title, text):
            print(f"Mock QMessageBox.warning: {title} - {text}")


    class QFileSystemModel:
        def __init__(self, parent=None):
            pass

        def setRootPath(self, path):
            pass

        def filter(self):
            return QDir.AllDirs | QDir.NoDotAndDotDot | QDir.Files


    class QTreeView:
        def __init__(self, parent=None):
            pass

        def setModel(self, model):
            pass

        def setRootIndex(self, index):
            pass


    class QSplitter:
        def __init__(self, orientation, parent=None):
            pass

        def addWidget(self, widget):
            pass

        def setSizes(self, sizes):
            pass


    class Qt:
        DockWidgetArea = object(); LeftDockWidgetArea = object(); RightDockWidgetArea = object(); TopDockWidgetArea = object(); BottomDockWidgetArea = object(); AllDockWidgetAreas = object(); Horizontal = object(); Vertical = object(); SubWindow = object()


    class QSize:
        def __init__(self, w, h):
            pass


    class QIcon:
        def __init__(self, path=None):
            print(f"Mock QIcon created (path: {path})")


    class QDir:
        AllDirs = 0
        NoDotAndDotDot = 0
        Files = 0


    class QProcess:
        def __init__(self, parent=None):
            print("Mock QProcess created")

        def start(self, program, args=None):
            print(f"Mock QProcess.start: {program} {args if args else ''}")

        def waitForStarted(self, msecs=30000):
            return True


    class QHBoxLayout:
        def __init__(self, parent=None):
            print("Mock QHBoxLayout created")
            self.widgets = []

        def addWidget(self, widget, stretch=0):
            self.widgets.append(widget)

        def addLayout(self, layout, stretch=0):
            pass

        def addStretch(self, stretch=0):
            pass


    class QPushButton:
        def __init__(self, text, parent=None):
            self.text = text
            print(f"Mock QPushButton '{text}' created")

        def setIcon(self, icon):
            pass

        def setToolTip(self, text):
            pass

        def clicked(self):
            return self  # Mock signal

        def setIconSize(self, size):
            pass


    class QLineEdit:
        def __init__(self, parent=None):
            print("Mock QLineEdit created")

        def setPlaceholderText(self, text):
            pass

        def returnPressed(self):
            return self  # Mock signal

        def text(self):
            return ""

        def clear(self):
            pass


    class QComboBox:
        def __init__(self, parent=None):
            print("Mock QComboBox created")

        def addItem(self, text, userData=None):
            pass

        def currentText(self):
            return ""


    class QCheckBox:
        def __init__(self, text, parent=None):
            print(f"Mock QCheckBox '{text}' created")

        def setChecked(self, checked):
            pass

        def isChecked(self):
            return False


    class pyqtSignal:
        def __init__(self, *args):
            pass

        def connect(self, func):
            pass

        def emit(self, *args):
            pass


    class QTimer:
        def __init__(self, parent=None):
            print("Mock QTimer created")

        def start(self, interval):
            pass

        def stop(self):
            pass

        def timeout(self):
            return self  # Mock signal


    class QPalette:
        Window = 0
        WindowText = 1
        Base = 2
        AlternateBase = 3
        ToolTipBase = 4
        ToolTipText = 5
        Text = 6
        Button = 7
        ButtonText = 8
        BrightText = 9
        Link = 10
        LinkVisited = 11
        Highlight = 12
        HighlightedText = 13

        def __init__(self):
            pass

        def setColor(self, role, color):
            pass


    class QColor:
        def __init__(self, *args):
            pass


    class QFont:
        def __init__(self, family, size=10):
            pass

        def setBold(self, bold):
            pass

    def get_logger(name: str):
        py_logging.basicConfig(level=py_logging.INFO)
        return py_logging.getLogger(name)

    # Get a logger instance for use in case of error
    py_logging.basicConfig(level=py_logging.INFO)
    logger = py_logging.getLogger("qt_dashboard_fallback")

    # If Qt imports failed, we'll have QT_AVAILABLE = False
    logger.error("Qt imports failed. Please install PyQt5 or PySide2.")
    QT_AVAILABLE = False

logger = get_logger(__name__)


class GangaQtDashboard(QMainWindow if QT_AVAILABLE else object):
    """Main GANGA Qt Dashboard Window."""

    def __init__(self, parent: Optional[QWidget] = None):
        if not QT_AVAILABLE:
            logger.critical("PyQt5 is not installed. GANGA Dashboard cannot run.")
            # In a real app, we might exit or raise an error here.
            # For the script to run, we'll allow mock object creation.
            super().__init__()  # Calls mock QMainWindow if QT_AVAILABLE is False
            self._mock_init_ui()
            return

        super().__init__(parent)
        self.setObjectName("GangaQtDashboard")

        # Initialize properties
        self.active_panels = {}  # Stores loaded panel widgets by ID
        self.panel_docks = {}  # Stores dock widgets for panels
        self.dock_widgets = {}  # For backward compatibility
        self.terminal_process = None
        self.cli_instance = None
        self.animations_enabled = True
        self.active_animations = []  # Track animations to prevent garbage collection

        # Setup theme properties
        self.current_theme = {}
        self.theme_name = "cyberpunk_neon"

        # Banner properties
        self._banner_label = None
        self._banner_timer = None
        self._banner_container = None

        # Initialize backend connections (conceptual)
        self.event_bus_client = EventBusClient(source_module_id="gui.dashboard")
        # Create async subscriptions via a helper method - this will prevent "never awaited" warnings
        self._setup_event_subscriptions()

        # Initialize dashboard manager
        self.dashboard_manager = DashboardManager(app_instance=QApplication.instance())

        self._init_ui()
        self._load_settings()
        self.discover_and_load_panels()  # Initial panel loading

        logger.info(f"GangaQtDashboard initialized. QT_AVAILABLE: {QT_AVAILABLE}")

    def _setup_event_subscriptions(self):
        """Set up event subscriptions in a non-blocking way"""
        if not hasattr(self, 'event_bus_client') or self.event_bus_client is None:
            logger.warning("Cannot set up event subscriptions: event bus client not available")
            return

        import asyncio
        from threading import Thread

        # Create the async event loop task for event subscriptions
        async def subscribe_to_events():
            try:
                # Give the event bus client time to initialize
                await asyncio.sleep(0.5)

                # Subscribe to events with error handling for each subscription
                try:
                    await self.event_bus_client.subscribe("system.status.update", self._handle_system_status_update)
                    logger.debug("Subscribed to system.status.update")
                except Exception as e:
                    logger.error(f"Failed to subscribe to system.status.update: {e}")

                try:
                    await self.event_bus_client.subscribe("security.alert", self._handle_security_alert)
                    logger.debug("Subscribed to security.alert")
                except Exception as e:
                    logger.error(f"Failed to subscribe to security.alert: {e}")

                logger.info("Event subscriptions setup complete")
            except Exception as e:
                logger.error(f"Failed to set up event subscriptions: {e}")

        # Run the subscription task in a background thread to avoid blocking the UI
        def run_subscription_task():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(subscribe_to_events())
                finally:
                    loop.close()
            except Exception as e:
                logger.error(f"Error in subscription thread: {e}")

        # Start subscription thread with error handling
        try:
            subscription_thread = Thread(target=run_subscription_task, daemon=True, name="EventSubscriptionThread")
            subscription_thread.start()
            logger.debug("Event subscription thread started")
        except Exception as e:
            logger.error(f"Failed to start subscription thread: {e}")

    def _init_ui(self):
        """Initialize the main UI components of the dashboard."""
        if not QT_AVAILABLE:
            return

        # Set window properties
        self.setWindowTitle(ConfigurationAPI.get("gui.dashboard.title", "GANGA Dashboard"))
        default_width = ConfigurationAPI.get("gui.dashboard.default_width", 1280)
        default_height = ConfigurationAPI.get("gui.dashboard.default_height", 720)
        self.resize(default_width, default_height)

        # Set application icon
        icon_path = ConfigurationAPI.get("gui.dashboard.icon_path", "path/to/default_icon.png")  # Provide a default
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        else:
            logger.warning(f"Dashboard icon not found at: {icon_path}")

        self._create_menu_bar()
        self._create_tool_bar()
        self._create_status_bar()
        self._create_central_widget()  # This will setup the panel hosting area

        self.setDockNestingEnabled(True)  # Allow dock widgets to be nested

        logger.debug("GangaQtDashboard UI initialized.")

    def _create_menu_bar(self):
        """Creates the main menu bar."""
        menu_bar = self.menuBar()
        if not QT_AVAILABLE: menu_bar = QMenuBar()  # Mock

        # File Menu
        file_menu = menu_bar.addMenu("&File")
        exit_action = QAction("&Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # View Menu (for managing panels, layouts)
        view_menu = menu_bar.addMenu("&View")
        # Submenu for panels will be populated dynamically
        self.panels_menu = view_menu.addMenu("Show &Panels")
        # Add actions for saving/loading layouts (stub)
        view_menu.addSeparator()
        save_layout_action = QAction("Save Layout...", self)
        load_layout_action = QAction("Load Layout...", self)
        view_menu.addAction(save_layout_action)
        view_menu.addAction(load_layout_action)

        # Operations Menu (stub)
        ops_menu = menu_bar.addMenu("&Operations")
        start_op_action = QAction("Start New Operation...", self)
        ops_menu.addAction(start_op_action)

        # Tools Menu (stub)
        tools_menu = menu_bar.addMenu("&Tools")
        settings_action = QAction("Settings...", self)
        tools_menu.addAction(settings_action)

        # Help Menu
        help_menu = menu_bar.addMenu("&Help")
        about_action = QAction("&About GANGA ASI", self)
        help_menu.addAction(about_action)

    def _create_tool_bar(self):
        """Creates the main toolbar."""
        tool_bar = self.addToolBar("Main Toolbar")
        if not QT_AVAILABLE: tool_bar = QToolBar("Main Toolbar")  # Mock

        # Terminal launch icon/button
        if ConfigurationAPI.get("gui.dashboard.terminal_integration_enabled", True):
            terminal_action = QAction(QIcon(), "Launch GANGA Terminal", self)
            terminal_action.setToolTip("Launch the advanced GANGA offensive operations terminal")
            terminal_action.triggered.connect(self.launch_terminal)
            tool_bar.addAction(terminal_action)

            # Add separator
            tool_bar.addSeparator()

        # Example actions (stubs)
        connect_action = QAction(QIcon(), "Connect to Backend", self)  # Add icons later
        tool_bar.addAction(connect_action)
        disconnect_action = QAction(QIcon(), "Disconnect", self)
        tool_bar.addAction(disconnect_action)

    def _create_status_bar(self):
        """Creates the status bar."""
        status_bar = self.statusBar()
        if not QT_AVAILABLE: status_bar = QStatusBar()  # Mock

        status_bar.showMessage("GANGA Dashboard Ready. MIL-GRADE Operations Standby.", 5000)

        if ConfigurationAPI.get("gui.dashboard.pqc_status_indicator_enabled", True):
            self.pqc_status_label = QLabel("PQC: N/A")
            status_bar.addPermanentWidget(self.pqc_status_label)

        if ConfigurationAPI.get("gui.dashboard.ai_status_indicator_enabled", True):
            self.ai_status_label = QLabel("ASI: IDLE")
            status_bar.addPermanentWidget(self.ai_status_label)

    def _create_central_widget(self):
        """
        Creates the central area for hosting panels with modern, animated design.
        Uses MDI (Multiple Document Interface) area for flexible panel arrangement.
        """
        # Main central widget layout
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(4, 4, 4, 4)
        main_layout.setSpacing(4)

        # Create header with banner/logo effect
        if QT_AVAILABLE:
            # Create and add banner using the banner generator
            header_widget = QWidget()
            header_layout = QHBoxLayout(header_widget)
            header_layout.setContentsMargins(2, 2, 2, 2)

            # Generate or load banner
            banner_widget = self.create_banner_widget(980, 80)
            if banner_widget:
                header_layout.addWidget(banner_widget)

            main_layout.addWidget(header_widget)

        # Add command center bar
        if QT_AVAILABLE:
            cmd_bar = QWidget()
            cmd_bar.setMaximumHeight(50)
            cmd_bar_layout = QHBoxLayout(cmd_bar)
            cmd_bar_layout.setContentsMargins(5, 2, 5, 2)

            # Terminal quick access button using animated button
            terminal_btn = self.create_animated_button("🖥️ TERMINAL", "Open GANGA Command Terminal")
            terminal_btn.setMinimumWidth(150)
            terminal_btn.clicked.connect(self.launch_terminal)
            cmd_bar_layout.addWidget(terminal_btn)

            # Quick command input
            cmd_input = QLineEdit()
            cmd_input.setPlaceholderText("Type quick command or search...")
            cmd_input.setStyleSheet(
                "QLineEdit { background-color: #1A1A2E; color: #E0E0FF; "
                "border: 1px solid #3D3D7A; border-radius: 3px; padding: 8px; "
                "selection-background-color: #00AAFF; }"
                "QLineEdit:focus { border: 1px solid #00FFFF; }"
            )
            cmd_input.returnPressed.connect(lambda: self._process_quick_command(cmd_input.text()))
            cmd_bar_layout.addWidget(cmd_input)

            # Operation status indicator
            op_status = QLabel("STATUS: READY")
            op_status.setStyleSheet("color: #00FF88; font-weight: bold;")
            op_status.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            cmd_bar_layout.addWidget(op_status)

            main_layout.addWidget(cmd_bar)

        # Main content area with MDI
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)

        # Create MDI area for panel hosting
        self.mdi_area = QMdiArea() if QT_AVAILABLE else QWidget()
        if QT_AVAILABLE:
            # Configure MDI area with cyberpunk styling
            self.mdi_area.setBackground(QBrush(QColor("#0A0A12")))
            self.mdi_area.setDocumentMode(True)
            self.mdi_area.setTabsMovable(True)
            self.mdi_area.setTabsClosable(True)
            self.mdi_area.setViewMode(QMdiArea.SubWindowView)

            # Add a grid background for the MDI area
            try:
                grid_pixmap = QPixmap(20, 20)
                grid_pixmap.fill(QColor("#0A0A12"))
                painter = QPainter(grid_pixmap)
                painter.setPen(QPen(QColor("#1A1A4A"), 0.5))
                painter.drawLine(0, 10, 20, 10)
                painter.drawLine(10, 0, 10, 20)
                painter.end()

                self.mdi_area.setBackground(QBrush(grid_pixmap))
            except Exception as e:
                logger.error(f"Failed to create grid background: {e}")

        content_layout.addWidget(self.mdi_area)
        main_layout.addWidget(content_widget, 1)  # 1 = stretch factor

        # Add status and progress bar at bottom
        if QT_AVAILABLE:
            status_widget = QWidget()
            status_widget.setMaximumHeight(30)
            status_layout = QHBoxLayout(status_widget)
            status_layout.setContentsMargins(2, 2, 2, 2)

            # PQC Status Indicator
            pqc_frame = QFrame()
            pqc_frame.setFrameShape(QFrame.StyledPanel)
            pqc_frame.setStyleSheet("background-color: #1A1A2E; border-radius: 3px;")
            pqc_layout = QHBoxLayout(pqc_frame)
            pqc_layout.setContentsMargins(8, 0, 8, 0)

            pqc_icon = QLabel("🔒")
            pqc_text = QLabel("PQC: SECURED")
            pqc_text.setStyleSheet("color: #00FF88; font-weight: bold;")

            pqc_layout.addWidget(pqc_icon)
            pqc_layout.addWidget(pqc_text)

            # Store the label for later updates
            self.pqc_status_label = pqc_text

            status_layout.addWidget(pqc_frame)

            # AI Status Indicator
            ai_frame = QFrame()
            ai_frame.setFrameShape(QFrame.StyledPanel)
            ai_frame.setStyleSheet("background-color: #1A1A2E; border-radius: 3px;")
            ai_layout = QHBoxLayout(ai_frame)
            ai_layout.setContentsMargins(8, 0, 8, 0)

            ai_icon = QLabel("🧠")
            ai_text = QLabel("AI: OPERATIONAL")
            ai_text.setStyleSheet("color: #00FFFF; font-weight: bold;")

            ai_layout.addWidget(ai_icon)
            ai_layout.addWidget(ai_text)

            # Store the label for later updates
            self.ai_status_label = ai_text

            status_layout.addWidget(ai_frame)

            # Clock
            clock_frame = QFrame()
            clock_frame.setFrameShape(QFrame.StyledPanel)
            clock_frame.setStyleSheet("background-color: #1A1A2E; border-radius: 3px;")
            clock_layout = QHBoxLayout(clock_frame)
            clock_layout.setContentsMargins(8, 0, 8, 0)

            clock_icon = QLabel("⏱️")
            self.clock_label = QLabel(time.strftime("%H:%M:%S"))
            self.clock_label.setStyleSheet("color: #E0E0FF;")

            clock_layout.addWidget(clock_icon)
            clock_layout.addWidget(self.clock_label)

            status_layout.addWidget(clock_frame)

            # Add stretch to push everything to the left
            status_layout.addStretch(1)

            main_layout.addWidget(status_widget)

        # Apply the theme to the central widget
        self.setCentralWidget(central_widget)
        self._apply_dashboard_theme()

        logger.debug("Central widget created with modern UI components.")

    def _load_settings(self):
        """Loads dashboard settings (e.g., window size, panel states) - STUB."""
        logger.debug("Loading dashboard settings (stub).")
        # Example: geometry = config_get("gui.dashboard.geometry")
        # if geometry: self.restoreGeometry(geometry)

    def _save_settings(self):
        """Saves dashboard settings - STUB."""
        logger.debug("Saving dashboard settings (stub).")
        # Example: config_set("gui.dashboard.geometry", self.saveGeometry())

    def closeEvent(self, event):
        """
        Handles the main window close event.

        This is called when the user attempts to close the window (e.g., by clicking X).
        It performs necessary cleanup and confirmation checks before closing.
        """
        logger.info("GangaQtDashboard closing...")

        # Ask for confirmation if there are active operations
        if hasattr(self, '_has_active_operations') and self._has_active_operations():
            reply = QMessageBox.warning(self, "Confirm Exit",
                                       "There are active operations in progress. Are you sure you want to exit?",
                                       QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.No:
                event.ignore()
                return

        # Call shutdown to handle cleanup
        self.shutdown()

        # Call the parent class's closeEvent
        super().closeEvent(event)

    def shutdown(self):
        """
        Performs a clean shutdown of the dashboard and all its components.
        Can be called programmatically or from closeEvent.
        """
        logger.info("Initiating dashboard shutdown sequence...")

        # Save settings
        self._save_settings()

        # Clean up all panels
        for panel_id in list(self.active_panels.keys()):  # list() for safe iteration while modifying
            try:
                self.unload_panel(panel_id)
            except Exception as e:
                logger.error(f"Error unloading panel {panel_id}: {e}")

        # Clean up terminal process if running
        if hasattr(self, 'terminal_process') and self.terminal_process is not None:
            try:
                logger.info("Terminating external terminal process")
                self.terminal_process.terminate()
                if hasattr(self.terminal_process, 'waitForFinished'):
                    self.terminal_process.waitForFinished(1000)  # Wait up to 1 sec for termination
                    if self.terminal_process.state() != QProcess.NotRunning:
                        self.terminal_process.kill()
            except Exception as e:
                logger.error(f"Error terminating terminal process: {e}")

        # Cancel any pending animations
        if hasattr(self, 'active_animations'):
            for animation in self.active_animations:
                if hasattr(animation, 'stop'):
                    animation.stop()
            self.active_animations.clear()

        # Disconnect from event bus
        if hasattr(self, 'event_bus_client') and self.event_bus_client:
            try:
                logger.info("Notifying event bus of dashboard closure")
                self.event_bus_client.publish_sync("system.ui.dashboard_closing", {})
                # Conceptual: self.event_bus_client.disconnect()
            except Exception as e:
                logger.error(f"Failed to notify event bus of closure: {e}")

        logger.info("GangaQtDashboard shutdown complete.")

    def discover_and_load_panels(self):
        """
        Discover and load available panels from the plugins directory.
        Uses dynamic loading with animations for a smooth, modern appearance.
        Implements panel isolation to prevent one buggy panel from affecting others.
        """
        if not QT_AVAILABLE:
            logger.warning("Panel discovery attempted without Qt support")
            return

        panel_plugin_dir = ConfigurationAPI.get("gui.dashboard.panel_plugin_dir", "plugins/dashboard_panels")

        logger.info(f"Discovering panels from {panel_plugin_dir}...")

        if not os.path.exists(panel_plugin_dir):
            logger.error(f"Panel plugin directory not found: {panel_plugin_dir}")
            # Create a default console panel if no panels are found
            self._create_default_panels()
            return

        # Track loaded panels for animation sequencing
        loaded_panels = []

        # Load panels in try-except blocks to isolate failures
        try:
            # Get Python files in the directory (excluding __init__.py)
            for filename in os.listdir(panel_plugin_dir):
                if not filename.endswith(".py") or filename == "__init__.py":
                        continue

                module_name = filename[:-3]  # Remove .py extension
                module_path = os.path.join(panel_plugin_dir, filename)

                # Isolate each panel module's loading
                self._safely_load_panel_module(module_name, module_path, loaded_panels)

            # Animate panel appearance in sequence if enabled
            if hasattr(self, 'animations_enabled') and self.animations_enabled and loaded_panels:
                self._animate_panel_loading_sequence(loaded_panels)

            # Update panels menu after loading all panels
            self._update_panels_menu()

            # If no panels were loaded, create default panels
            if not loaded_panels:
                logger.warning("No panels were loaded from plugins directory")
                self._create_default_panels()
            else:
                logger.info(f"Successfully loaded {len(loaded_panels)} panels")

        except Exception as e:
            logger.error(f"Error during panel discovery: {e}", exc_info=True)
            # Create default panels as fallback
            self._create_default_panels()

    def _safely_load_panel_module(self, module_name, module_path, loaded_panels):
        """
        Safely load a panel module, isolating any failures to just that module.

        Args:
            module_name: Name of the panel module
            module_path: Path to the panel module file
            loaded_panels: List to append successfully loaded panels
        """
        logger.debug(f"Attempting to load panel module: {module_name}")

        try:
            # Load the module with import isolation
            spec = importlib.util.spec_from_file_location(f"isolated_panel.{module_name}", module_path)
            if not spec or not spec.loader:
                logger.warning(f"Failed to create spec for {module_name}")
                return

            module = importlib.util.module_from_spec(spec)

            try:
                spec.loader.exec_module(module)
            except Exception as e:
                logger.error(f"Failed to execute module {module_name}: {e}")
                # Try to capture the exception traceback for better debugging
                import traceback
                logger.debug(f"Traceback for failed module {module_name}:\n{traceback.format_exc()}")
                return

            # Look for panel classes in the module
            panel_classes = []
            try:
                panel_classes = [
                    cls for name, cls in module.__dict__.items()
                    if isinstance(cls, type) and hasattr(cls, 'PANEL_TITLE')
                ]
            except Exception as e:
                logger.error(f"Error finding panel classes in {module_name}: {e}")
                return

            if not panel_classes:
                logger.warning(f"No panel classes found in {module_name}")
                return

            # Load each panel class individually
            for panel_class in panel_classes:
                self._safely_load_panel_class(module_name, panel_class, loaded_panels)

        except Exception as e:
            logger.error(f"Error loading panel module {module_name}: {e}", exc_info=True)
            # Don't let a single panel failure stop the dashboard

    def _safely_load_panel_class(self, module_name, panel_class, loaded_panels):
        """
        Safely instantiate and add a panel class, isolating any failures.

        Args:
            module_name: Name of the containing module
            panel_class: The panel class to instantiate
            loaded_panels: List to append successfully loaded panels
        """
        try:
            panel_id = f"{module_name}_{panel_class.__name__}"
            panel_title = getattr(panel_class, 'PANEL_TITLE', panel_id)

            logger.info(f"Loading panel: {panel_title} ({panel_id})")

            # Create panel instance with error isolation
            try:
                # Pass backend interfaces that the panel might need
                backend_interfaces = {
                    'telemetry_service': getattr(self, 'telemetry_service', None),
                    'agent_coordinator': getattr(self, 'agent_coordinator', None),
                    'event_bus': self.event_bus_client if hasattr(self, 'event_bus_client') else None
                }

                panel_instance = panel_class(parent=self, backend_interfaces=backend_interfaces)

                # Determine where to place the panel based on its ID
                if 'console' in panel_id.lower() or 'terminal' in panel_id.lower():
                    dock_area = Qt.BottomDockWidgetArea
                elif 'map' in panel_id.lower() or 'visualization' in panel_id.lower():
                    dock_area = Qt.RightDockWidgetArea
                elif 'control' in panel_id.lower() or 'operations' in panel_id.lower():
                    dock_area = Qt.LeftDockWidgetArea
                else:
                    dock_area = Qt.RightDockWidgetArea

                # Initially hide panel if animations enabled
                if hasattr(self, 'animations_enabled') and self.animations_enabled:
                    panel_instance.setVisible(False)

                # Add panel to dashboard
                self.add_panel_as_dock(
                    panel_id=panel_id,
                    panel_widget=panel_instance,
                    title=panel_title,
                    area=dock_area,
                    floating=False
                )

                # Store for animation sequence
                loaded_panels.append({
                    'panel_id': panel_id,
                    'dock': self.panel_docks.get(panel_id),
                    'title': panel_title
                })

                logger.debug(f"Panel {panel_id} loaded successfully")

            except Exception as e:
                logger.error(f"Error creating panel instance {panel_id}: {e}", exc_info=True)

        except Exception as e:
            logger.error(f"Error in panel class from {module_name}: {e}", exc_info=True)

    def _create_default_panels(self):
        """Create default panels when no plugins are available"""
        logger.info("Creating default panels")
        try:
            from PyQt5.QtWidgets import QTextEdit, QTreeView, QVBoxLayout

            # Create a simple console panel
            console_widget = QWidget()
            console_layout = QVBoxLayout(console_widget)
            text_edit = QTextEdit()
            text_edit.setReadOnly(True)
            text_edit.setStyleSheet("background-color: #0A0A12; color: #00FF88; font-family: Consolas, monospace; font-size: 12px;")
            text_edit.append("# GANGA Console Panel (Default)")
            text_edit.append("# No plugin panels were found, using default panels")
            text_edit.append("# System is operational")
            console_layout.addWidget(text_edit)

            self.add_panel_as_dock(
                panel_id="default_console",
                panel_widget=console_widget,
                title="Console (Default)",
                area=Qt.BottomDockWidgetArea,
                floating=False
            )

            # Create a simple control panel
            control_widget = QWidget()
            control_layout = QVBoxLayout(control_widget)
            info_label = QLabel("GANGA Control Panel (Default)")
            info_label.setStyleSheet("color: #00FFFF; font-weight: bold;")
            control_layout.addWidget(info_label)

            # Add buttons with styling
            start_btn = self.create_animated_button("Start Operation", style="success")
            stop_btn = self.create_animated_button("Stop Operation", style="danger")
            control_layout.addWidget(start_btn)
            control_layout.addWidget(stop_btn)
            control_layout.addStretch(1)

            self.add_panel_as_dock(
                panel_id="default_control",
                panel_widget=control_widget,
                title="Control Panel (Default)",
                area=Qt.LeftDockWidgetArea,
                floating=False
            )

            # Create a simple status panel
            status_widget = QWidget()
            status_layout = QVBoxLayout(status_widget)
            status_label = QLabel("GANGA Status Panel (Default)")
            status_label.setStyleSheet("color: #00FFFF; font-weight: bold;")
            status_layout.addWidget(status_label)

            # Add a tree view for system status
            tree = QTreeView()
            tree.setHeaderHidden(True)
            status_layout.addWidget(tree)

            self.add_panel_as_dock(
                panel_id="default_status",
                panel_widget=status_widget,
                title="System Status (Default)",
                area=Qt.RightDockWidgetArea,
                floating=False
            )

            logger.info("Default panels created successfully")
        except Exception as e:
            logger.error(f"Error creating default panels: {e}")
            # Last resort - create an empty panel with error message
            try:
                empty_widget = QWidget()
                layout = QVBoxLayout(empty_widget)
                error_label = QLabel("Error loading panels. See logs for details.")
                error_label.setStyleSheet("color: #FF0000;")
                layout.addWidget(error_label)

                self.add_panel_as_dock(
                    panel_id="error_panel",
                    panel_widget=empty_widget,
                    title="Error - Panel Loading Failed",
                    area=Qt.BottomDockWidgetArea,
                    floating=False
                )
            except:
                logger.critical("Failed to create even basic error panel")

    def _animate_panel_loading_sequence(self, panels):
        """
        Animate the appearance of panels in sequence for a smoother startup experience.

        Args:
            panels: List of panel data dictionaries with 'panel_id', 'dock', and 'title'
        """
        if not QT_AVAILABLE or not hasattr(self, 'animations_enabled') or not self.animations_enabled or not panels:
            return

        animation_delay = 200  # ms between panel animations
        animation_duration = 500  # ms for each panel animation

        # Initialize the active_animations list if it doesn't exist
        if not hasattr(self, 'active_animations'):
            self.active_animations = []

        for i, panel_data in enumerate(panels):
            dock = panel_data.get('dock')
            if not dock:
                continue

            # Set initial state
            dock.setVisible(True)
            dock.setWindowOpacity(0.0)

            # Create fade-in animation
            fade_anim = QPropertyAnimation(dock, b"windowOpacity")
            fade_anim.setDuration(animation_duration)
            fade_anim.setStartValue(0.0)
            fade_anim.setEndValue(1.0)
            fade_anim.setEasingCurve(QEasingCurve.InOutQuad)

            # Start with delay based on position
            QTimer.singleShot(i * animation_delay, fade_anim.start)

            # Store animation to prevent garbage collection
            self.active_animations.append(fade_anim)

    def _mock_init_ui(self):
        """Mock UI initialization when Qt is not available"""
        logger.critical("Using mock UI initialization (Qt not available)")

        # Create mock properties
        self.active_panels = {}
        self.panel_docks = {}
        self.terminal_process = None

        # Log the mock initialization
        print("Mock GangaQtDashboard created (Qt not available)")

        # Create a mock event bus client
        class MockEventBusClient:
            def __init__(self, **kwargs):
                pass

            async def subscribe(self, topic, handler):
                """
                Subscribe to an event topic using the event bus client.

                Args:
                    topic: The event topic to subscribe to
                    handler: Callback function to handle events

                Returns:
                    str: Subscription ID if successful
                """
                if not hasattr(self, 'event_bus_client') or self.event_bus_client is None:
                    logger.error(f"Cannot subscribe to {topic}: event bus client not available")
                    return None

                try:
                    # Forward to the actual EventBusClient subscribe method
                    subscription_id = await self.event_bus_client.subscribe(topic, handler)
                    logger.debug(f"Subscribed to {topic} with ID {subscription_id}")
                    return subscription_id
                except Exception as e:
                    logger.error(f"Failed to subscribe to {topic}: {e}")
                    return None

        self.event_bus_client = MockEventBusClient(source_module_id="gui.dashboard.mock")

    def generate_banner_image(self, width=980, height=80):
        """
        Generate a modern, cyberpunk-styled banner with dynamic elements for the dashboard.
        Uses gradient effects, neon glow, and matrix-inspired elements for a futuristic look.

        Returns:
            QPixmap: The generated banner image
        """
        if not QT_AVAILABLE:
            return None

        painter = None
        try:
            # Create a pixmap for the banner
            banner = QPixmap(width, height)
            banner.fill(QColor(0, 0, 0, 0))  # Transparent background

            painter = QPainter(banner)
            painter.setRenderHint(QPainter.Antialiasing, True)
            painter.setRenderHint(QPainter.TextAntialiasing, True)

            # Draw background gradient
            bg_gradient = QLinearGradient(0, 0, width, height)
            bg_gradient.setColorAt(0, QColor(10, 10, 18))
            bg_gradient.setColorAt(0.5, QColor(18, 18, 32))
            bg_gradient.setColorAt(1, QColor(10, 10, 18))
            painter.fillRect(0, 0, width, height, bg_gradient)

            # Add digital noise/matrix effect in background
            painter.setOpacity(0.15)
            for i in range(100):  # Reduced from 300 to improve performance
                x = random.randint(0, width)
                y = random.randint(0, height)
                if random.random() > 0.5:
                    char_width = 8
                    char_height = 12
                    intensity = random.random() * 0.8 + 0.2
                    green = int(255 * intensity)
                    blue = int(180 * intensity)
                    painter.setPen(QPen(QColor(0, green, blue, 120)))
                    if QT_AVAILABLE:
                        painter.drawText(QRectF(x, y, char_width, char_height),
                                        str(random.choice("01")))
                    else:
                        # Fallback for non-Qt environment
                        painter.drawText(x, y + char_height, str(random.choice("01")))

            # Draw glow effect
            painter.setOpacity(0.4)
            glow_gradient = QRadialGradient(width/2, height/2, width/3)
            glow_gradient.setColorAt(0, QColor(0, 200, 255, 40))
            glow_gradient.setColorAt(1, QColor(0, 0, 0, 0))
            painter.fillRect(0, 0, width, height, glow_gradient)

            # Draw horizontal lines
            painter.setOpacity(0.5)
            line_pen = QPen(QColor(0, 255, 255, 80))
            line_pen.setWidth(1)
            painter.setPen(line_pen)

            # Reduce number of lines for performance
            for i in range(3, height, 20):  # Changed from 10 to 20
                # Draw with varying opacity
                alpha = random.randint(30, 120)
                line_pen.setColor(QColor(0, 255, 255, alpha))
                painter.setPen(line_pen)
                painter.drawLine(0, i, width, i)

            # Draw side accents
            accent_gradient = QLinearGradient(0, 0, 0, height)
            accent_gradient.setColorAt(0, QColor(0, 255, 255, 0))
            accent_gradient.setColorAt(0.5, QColor(0, 255, 255, 180))
            accent_gradient.setColorAt(1, QColor(0, 255, 255, 0))

            painter.fillRect(0, 0, 3, height, accent_gradient)
            painter.fillRect(width-3, 0, 3, height, accent_gradient)

            # Draw main title text
            title = "GANGA OFFENSIVE OPS HACKER ASI"
            painter.setOpacity(1.0)

            # Main text
            title_font = QFont("Orbitron", 22, QFont.Bold)
            try:
                title_font.setFamily("Orbitron")  # Cyberpunk style font
            except:
                title_font.setFamily("Arial")  # Fallback font

            title_font.setBold(True)
            title_font.setLetterSpacing(QFont.AbsoluteSpacing, 2)
            painter.setFont(title_font)

            # Draw text glow (shadow)
            shadow_pen = QPen(QColor(0, 200, 255, 100))
            painter.setPen(shadow_pen)
            if QT_AVAILABLE:
                painter.drawText(QRectF(3, 3, width, height/2), Qt.AlignCenter, title)
            else:
                # Fallback for non-Qt environment
                painter.drawText(3, height/2, title)

            # Draw main text
            text_gradient = QLinearGradient(0, 0, width, 0)
            text_gradient.setColorAt(0, QColor(0, 200, 255))
            text_gradient.setColorAt(0.5, QColor(0, 255, 255))
            text_gradient.setColorAt(1, QColor(100, 255, 255))
            painter.setPen(QPen(text_gradient, 1))
            if QT_AVAILABLE:
                painter.drawText(QRectF(0, 0, width, height/2), Qt.AlignCenter, title)
            else:
                # Fallback for non-Qt environment
                painter.drawText(0, height/2, title)

            # Draw subtitle
            subtitle = "ADVANCED QUANTUM-RESISTANT CYBER WARFARE SYSTEM"
            subtitle_font = QFont("Courier New", 11)
            subtitle_font.setBold(False)
            painter.setFont(subtitle_font)
            painter.setPen(QPen(QColor(180, 180, 255)))
            if QT_AVAILABLE:
                painter.drawText(QRectF(0, height/2 - 10, width, height/2),
                                Qt.AlignCenter, subtitle)
            else:
                # Fallback for non-Qt environment
                painter.drawText(width/2, height*3/4, subtitle)

            # Add dynamic elements (circles pulsing) - reduced for performance
            timestamp = time.time()  # Use time for animation effect
            for i in range(3):  # Reduced from 5 to 3
                x = 20 + i * 15
                pulse = (math.sin(timestamp * 3 + i) + 1) / 2  # Value between 0 and 1
                size = 8 + pulse * 4

                # Draw glowing circle
                circle_gradient = QRadialGradient(x, height - 15, size)
                if i % 2 == 0:  # Alternate colors
                    circle_gradient.setColorAt(0, QColor(0, 255, 200))
                    circle_gradient.setColorAt(1, QColor(0, 100, 80, 0))
                else:
                    circle_gradient.setColorAt(0, QColor(0, 200, 255))
                    circle_gradient.setColorAt(1, QColor(0, 80, 100, 0))

                painter.setBrush(QBrush(circle_gradient))
                painter.setPen(Qt.NoPen)
                painter.drawEllipse(QPointF(x, height - 15), size, size)

            # Add random hex values on the right side - reduced for performance
            hex_font = QFont("Courier New", 9)
            painter.setFont(hex_font)
            painter.setOpacity(0.6)

            for i in range(2):  # Reduced from 4 to 2
                x = width - 100
                y = 10 + i * 15
                hex_value = "".join(random.choice("0123456789ABCDEF") for _ in range(8))
                painter.setPen(QPen(QColor(0, 255, 255)))
                painter.drawText(x, y, f"0x{hex_value}")

            # End painting BEFORE returning the pixmap
            painter.end()
            painter = None  # Set to None so we don't try to end it again in finally

            return banner

        except Exception as e:
            logger.error(f"Error generating banner: {e}")
            # Return a simple colored rectangle as fallback
            fallback = QPixmap(width, height)
            fallback.fill(QColor(10, 10, 18))  # Dark background
            return fallback
        finally:
            # Make sure painter is properly ended if it exists
            if painter is not None and painter.isActive():
                try:
                    painter.end()
                except:
                    pass  # Already ended or error ending

    def create_banner_widget(self, width=980, height=80):
        """
        Create a QWidget containing the animated cyberpunk banner

        Returns:
            QWidget: The banner widget
        """
        if not QT_AVAILABLE:
            return None

        try:
            banner_container = QWidget()
            layout = QVBoxLayout(banner_container)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(0)

            # Create label to hold the banner image
            banner_label = QLabel()
            banner_label.setMinimumHeight(height)
            banner_label.setMaximumHeight(height)
            layout.addWidget(banner_label)

            # Generate initial banner
            banner_pixmap = self.generate_banner_image(width, height)
            if banner_pixmap:
                banner_label.setPixmap(banner_pixmap)

            # Store references to prevent garbage collection
            self._banner_label = banner_label
            self._banner_container = banner_container

            # Setup refresh timer with a lower rate to reduce CPU usage
            # Instead of updating every second, update every 3 seconds
            refresh_timer = QTimer(banner_container)

            # Define update method that properly handles painter lifecycle
            def update_banner():
                try:
                    new_pixmap = self.generate_banner_image(width, height)
                    if new_pixmap and not new_pixmap.isNull():
                        banner_label.setPixmap(new_pixmap)
                except Exception as e:
                    # If banner generation fails, don't crash the application
                    logger.error(f"Error updating banner: {e}")

            refresh_timer.timeout.connect(update_banner)
            refresh_timer.start(3000)  # Refresh every 3 seconds instead of 1

            # Store timer reference to prevent garbage collection
            self._banner_timer = refresh_timer

            return banner_container

        except Exception as e:
            logger.error(f"Error creating banner widget: {e}")
            # Return a simple placeholder instead
            placeholder = QLabel("GANGA OFFENSIVE OPS HACKER ASI")
            placeholder.setAlignment(Qt.AlignCenter)
            placeholder.setStyleSheet("color: #00FFFF; font-weight: bold; font-size: 18px; background-color: #0A0A12;")
            placeholder.setMinimumHeight(height)
            placeholder.setMaximumHeight(height)
            return placeholder

    def add_panel_as_dock(self, panel_id: str, panel_widget: QWidget, title: str,
                          area: Any = Qt.RightDockWidgetArea,  # Qt.DockWidgetArea enum
                          floating: bool = False):
        """Adds a panel widget as a QDockWidget."""
        if not QT_AVAILABLE:
            logger.info(f"Mock adding panel '{title}' (ID: {panel_id})")
            self.active_panels[panel_id] = panel_widget
            return

        if panel_id in self.panel_docks:
            logger.warning(f"Panel dock for '{panel_id}' already exists.")
            self.panel_docks[panel_id].show()
            return

        dock = QDockWidget(title, self)
        dock.setObjectName(f"Dock_{panel_id}")
        dock.setWidget(panel_widget)
        dock.setAllowedAreas(Qt.AllDockWidgetAreas)
        dock.setFloating(floating)

        self.addDockWidget(area, dock)
        self.active_panels[panel_id] = panel_widget
        self.panel_docks[panel_id] = dock

        action = QAction(title, self, checkable=True)
        action.setChecked(True)
        action.triggered.connect(lambda checked, d=dock: d.setVisible(checked))
        self.panels_menu.addAction(action)

    def unload_panel(self, panel_id: str):
        """Unloads and removes a panel."""
        if not QT_AVAILABLE:
            if panel_id in self.active_panels: del self.active_panels[panel_id]
            logger.info(f"Mock unloading panel (ID: {panel_id})")
            return

        if panel_id in self.panel_docks:
            dock = self.panel_docks.pop(panel_id)
            self.removeDockWidget(dock)
            dock.deleteLater()  # Ensure proper Qt cleanup
            if panel_id in self.active_panels:
                del self.active_panels[panel_id]
            logger.info(f"Unloaded panel: {panel_id}")
            self._update_panels_menu()  # Rebuild menu
        else:
            logger.warning(f"Panel '{panel_id}' not found for unloading.")

    def _update_panels_menu(self):
        """Updates the View > Panels menu based on loaded/available panels."""
        if not QT_AVAILABLE or not hasattr(self, 'panels_menu'): return

        self.panels_menu.clear()
        for panel_id, dock in self.panel_docks.items():
            action = QAction(dock.windowTitle(), self, checkable=True)
            action.setChecked(dock.isVisible())
            action.triggered.connect(lambda checked, d=dock: d.setVisible(checked))
            self.panels_menu.addAction(action)
        # Could also add actions to load currently unloaded (but discovered) panels.

    # Placeholder for backend interactions
    def update_pqc_status(self, status_text: str, is_secure: bool):
        if hasattr(self, 'pqc_status_label') and QT_AVAILABLE:
            self.pqc_status_label.setText(f"PQC: {status_text}")
            # Update color based on is_secure (e.g., green/red)
            if is_secure:
                self.pqc_status_label.setStyleSheet("color: green;")
            else:
                self.pqc_status_label.setStyleSheet("color: red;")

    def update_ai_status(self, status_text: str, current_mode: str):
        if hasattr(self, 'ai_status_label') and QT_AVAILABLE:
            self.ai_status_label.setText(f"ASI: {status_text} ({current_mode})")
            # Update color based on mode
            if current_mode == "AGGRESSIVE":
                self.ai_status_label.setStyleSheet("color: red;")
            elif current_mode == "DEFENSIVE":
                self.ai_status_label.setStyleSheet("color: blue;")
            else:
                self.ai_status_label.setStyleSheet("color: green;")

    # New methods for terminal integration

    def launch_terminal(self):
        """
        Launch an integrated terminal within the dashboard.

        This terminal provides advanced command execution capabilities with:
        1. History tracking and recall
        2. Syntax highlighting
        3. Autocompletion
        4. Command analysis with AI support
        5. Visual command output formatting
        """
        if not QT_AVAILABLE:
            logger.warning("Cannot launch terminal: Qt is not available")
            return

        try:
            # Try to import the ConsolePanel class
            try:
                from plugins.dashboard_panels.console_panel import ConsolePanel
                panel_class = ConsolePanel
            except ImportError:
                # Fallback to a basic console implementation
                logger.warning("Console panel not found, using basic implementation")
                panel_class = self._create_basic_console_panel

            # Check if the terminal panel is already open
            panel_id = "ganga_console"
            existing_panel = self.active_panels.get(panel_id)

            if existing_panel:
                # Focus on the existing panel
                if panel_id in self.panel_docks:
                    self.panel_docks[panel_id].setVisible(True)
                    self.panel_docks[panel_id].raise_()
                logger.debug("Focused on existing terminal panel")
            else:
                # Create a new terminal panel
                if panel_class == ConsolePanel:
                    # If using the plugin panel
                    terminal_launcher_path = ConfigurationAPI.get("gui.dashboard.terminal_launcher_path",
                                                                "frontend/gui/cli/cli_main.py")
                    panel = panel_class(panel_id=panel_id, title="GANGA Terminal",
                                        launcher_path=terminal_launcher_path)
                else:
                    # If using the basic implementation
                    panel = panel_class()

                # Add the panel to the dashboard
                self.add_panel_as_dock(
                    panel_id=panel_id,
                    panel_widget=panel,
                    title="GANGA Terminal",
                    area=Qt.BottomDockWidgetArea,
                    floating=False
                )

                # Show welcome message if method exists
                if hasattr(self, '_show_terminal_welcome'):
                    self._show_terminal_welcome(panel_id)

                logger.info("New terminal panel created")
        except Exception as e:
            logger.error(f"Failed to launch terminal: {e}")
            # Try to launch external terminal as last resort
            self._launch_external_terminal()

    def _create_basic_console_panel(self):
        """Create a basic console panel as a fallback"""
        console_widget = QWidget()
        layout = QVBoxLayout(console_widget)

        # Create text display area
        output_area = QTextEdit()
        output_area.setReadOnly(True)
        output_area.setStyleSheet("background-color: #0A0A12; color: #00FF88; font-family: monospace;")

        # Create command input
        input_area = QLineEdit()
        input_area.setStyleSheet("background-color: #131326; color: #00FFFF; font-family: monospace;")
        input_area.setPlaceholderText("Enter command...")

        def process_command():
            cmd = input_area.text()
            if cmd:
                output_area.append(f"$ {cmd}")
                input_area.clear()

                # Echo command for now - in a real implementation this would execute the command
                try:
                    import subprocess
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    output = result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
                    output_area.append(output)
                except Exception as e:
                    output_area.append(f"Error executing command: {e}")

        input_area.returnPressed.connect(process_command)

        # Add welcome message
        output_area.append("=== GANGA Basic Terminal ===")
        output_area.append("Simple command execution interface")
        output_area.append("$ ")

        # Add widgets to layout
        layout.addWidget(output_area, 1)  # 1 = stretch factor
        layout.addWidget(input_area, 0)  # 0 = don't stretch

        return console_widget

    def _show_terminal_welcome(self, panel_id):
        """Show welcome message in the terminal"""
        if panel_id in self.active_panels:
            panel = self.active_panels[panel_id]
            if hasattr(panel, 'append_output'):
                panel.append_output("\n")
                panel.append_output("  ██████   █████  ███    ██  ██████   █████  \n")
                panel.append_output(" ██       ██   ██ ████   ██ ██       ██   ██ \n")
                panel.append_output(" ██   ███ ███████ ██ ██  ██ ██   ███ ███████ \n")
                panel.append_output(" ██    ██ ██   ██ ██  ██ ██ ██    ██ ██   ██ \n")
                panel.append_output("  ██████  ██   ██ ██   ████  ██████  ██   ██ \n")
                panel.append_output("\n")
                panel.append_output("+=================================================+\n")
                panel.append_output("| GANGA Offensive Ops Advanced Command Interface   |\n")
                panel.append_output("| Type 'help' for available commands               |\n")
                panel.append_output("+=================================================+\n")
                panel.append_output("\n")

                # Add current status info
                import datetime
                current_time = datetime.datetime.now().strftime("%H:%M:%S")
                panel.append_output(f"[{current_time}] Terminal session initialized\n")
                panel.append_output(f"[{current_time}] ASI status: ACTIVE\n")
                panel.append_output(f"[{current_time}] PQC status: SECURE\n")
                panel.append_output(f"[{current_time}] Network: ENCRYPTED\n")
                panel.append_output("\n")
                panel.append_output("$ ")

    def _launch_external_terminal(self):
        """Launch an external terminal process as fallback."""
        try:
            logger.info("Attempting to launch external terminal...")

            # First, try to launch through the more feature-rich integrated system
            terminal_launcher_path = ConfigurationAPI.get("gui.dashboard.terminal_launcher_path", "frontend/gui/cli/cli_main.py")

            if os.path.exists(terminal_launcher_path):
                cmd = [sys.executable, terminal_launcher_path]
                self.terminal_process = QProcess(self)
                self.terminal_process.start(sys.executable, cmd)

                if self.terminal_process.waitForStarted(3000):  # Wait up to 3 seconds
                    logger.info("External terminal launched via launcher script")
                    self.statusBar().showMessage("External GANGA Terminal launched", 3000)
                    return True
            else:
                    logger.error("Failed to start terminal through launcher script")

            # Fallback to system terminal
            if sys.platform.startswith('linux'):
                # Try common Linux terminals
                for terminal in ['gnome-terminal', 'xterm', 'konsole', 'terminator']:
                    try:
                        subprocess.Popen([terminal])
                        logger.info(f"External terminal launched via {terminal}")
                        self.statusBar().showMessage(f"External terminal launched ({terminal})", 3000)
                        return True
                    except FileNotFoundError:
                        continue
            elif sys.platform == 'darwin':  # macOS
                subprocess.Popen(['open', '-a', 'Terminal'])
                logger.info("External terminal launched via macOS Terminal.app")
                self.statusBar().showMessage("External terminal launched", 3000)
                return True
            elif sys.platform == 'win32':  # Windows
                subprocess.Popen(['start', 'cmd'], shell=True)
                logger.info("External terminal launched via Windows cmd")
                self.statusBar().showMessage("External terminal launched", 3000)
                return True

            logger.error("Could not launch external terminal on this platform")
            self.statusBar().showMessage("Failed to launch external terminal", 3000)
            return False

        except Exception as e:
            logger.error(f"Error launching external terminal: {e}")
            self.statusBar().showMessage("Failed to launch external terminal", 3000)
            return False

    def _process_quick_command(self, command: str):
        """Process a command from the quick-access command input."""
        if not command.strip():
            return

        logger.debug(f"Processing quick command: {command}")

        # Initialize CLI if needed
        if self.cli_instance is None:
            self.cli_instance = CLIMain(display_callback=self._display_cli_output)

        # Process the command
        self.cli_instance.process_command_input(command)

    def _display_cli_output(self, output: str):
        """Callback to display CLI output."""
        # In a real implementation, this would update a text area in the GUI
        logger.info(f"CLI Output: {output}")
        # Update status bar temporarily
        if hasattr(self, 'statusBar') and QT_AVAILABLE:
            self.statusBar().showMessage(f"CLI: {output}", 5000)

    def _handle_system_status_update(self, message: Dict[str, Any]):
        """Handles system status updates from the event bus."""
        # Example: message = {"status": "OPERATIONAL", "component": "PQC_SYSTEM"}
        logger.info(f"System Status Update: {message}")
        # In a real implementation, we would update the UI accordingly
        if message.get("component") == "PQC_SYSTEM":
            self.update_pqc_status(message.get("status", "N/A"), True)  # Example
        elif message.get("component") == "ASI_CORE":
            self.update_ai_status(message.get("status", "N/A"), "NORMAL")

    def _handle_security_alert(self, alert: Dict[str, Any]):
        """Handles security alerts from the event bus."""
        # Example: alert = {"severity": "CRITICAL", "message": "Intrusion Detected!"}
        logger.warning(f"Security Alert Received: {alert}")
        # In a real implementation, show a popup or highlight a panel.
        if QT_AVAILABLE:
            QMessageBox.warning(self, "Security Alert", alert.get("message", "Unknown Alert"))
        else:
            print(f"Mock Security Alert: {alert.get('message', 'Unknown Alert')}")

    # Add method to GangaQtDashboard:
    def register_data_provider(self, panel_id, data_provider):
        """Register a data provider for a specific panel."""
        if panel_id in self.active_panels:
            panel = self.active_panels[panel_id]
            if hasattr(panel, 'set_data_provider'):
                panel.set_data_provider(data_provider)
                return True
        return False

    def _apply_dashboard_theme(self):
        """Applies the selected theme to the dashboard."""
        self._apply_theme_to_application(self.theme_name)

    def apply_theme(self, theme_name):
        """
        Public method to apply a theme by name.
        Can be called from outside this class (e.g., by DashboardManager).

        Args:
            theme_name: Name of the theme to apply
        """
        logger.info(f"Setting dashboard theme to: {theme_name}")
        self.theme_name = theme_name
        self._apply_dashboard_theme()

    def _apply_theme_to_application(self, theme_name="cyberpunk_neon"):
        """Apply selected theme to the application."""
        if not QT_AVAILABLE:
            return

        try:
            # Get theme name from config or use default
            theme_name = ConfigurationAPI.get("gui.dashboard.theme", "cyberpunk_neon")

            # Define theme colors
            themes = {
                "cyberpunk_neon": {
                    "bg_primary": "#0A0A12",          # Nearly black for main background
                    "bg_secondary": "#131326",        # Slightly lighter panel backgrounds
                    "bg_tertiary": "#1A1A2E",         # Input field backgrounds
                    "text_primary": "#E0E0FF",        # Light blue-white for main text
                    "text_secondary": "#8888AA",      # Muted text
                    "accent_primary": "#00FFFF",      # Cyan for primary accents
                    "accent_secondary": "#FF00AA",    # Magenta for secondary accents
                    "accent_tertiary": "#FFAA00",     # Orange for warnings/highlights
                    "success": "#00FF88",             # Neon green for success states
                    "warning": "#FFAA00",             # Orange for warnings
                    "danger": "#FF5555",              # Red for errors/danger
                    "info": "#00AAFF",                # Blue for info
                    "grid_lines": "#1F1F3A",          # Subtle grid lines
                    "border": "#3D3D7A"               # Standard borders
                },
                "midnight_pulse": {
                    "bg_primary": "#0C0C14",
                    "bg_secondary": "#151528",
                    "bg_tertiary": "#1E1E32",
                    "text_primary": "#D6D6FF",
                    "text_secondary": "#8080AA",
                    "accent_primary": "#5C5CFF",
                    "accent_secondary": "#B15CFF",
                    "accent_tertiary": "#FF7B00",
                    "success": "#00DD66",
                    "warning": "#FFBB00",
                    "danger": "#FF5050",
                    "info": "#50AAFF",
                    "grid_lines": "#222244",
                    "border": "#383870"
                },
                "hacker_dark": {
                    "bg_primary": "#0A120A",
                    "bg_secondary": "#0E1E0E",
                    "bg_tertiary": "#162616",
                    "text_primary": "#CCFFCC",
                    "text_secondary": "#88AA88",
                    "accent_primary": "#00FF00",
                    "accent_secondary": "#AAFF00",
                    "accent_tertiary": "#FFCC00",
                    "success": "#00FF44",
                    "warning": "#FFDD00",
                    "danger": "#FF4444",
                    "info": "#00DDFF",
                    "grid_lines": "#1A321A",
                    "border": "#2D5A2D"
                }
            }

            # Use default theme if specified theme doesn't exist
            theme = themes.get(theme_name, themes["cyberpunk_neon"])

            # Store current theme for use by other methods
            self.current_theme = theme

            # Create application palette
            palette = QPalette()

            # Set application colors
            palette.setColor(QPalette.Window, QColor(theme["bg_primary"]))
            palette.setColor(QPalette.WindowText, QColor(theme["text_primary"]))
            palette.setColor(QPalette.Base, QColor(theme["bg_secondary"]))
            palette.setColor(QPalette.AlternateBase, QColor(theme["bg_tertiary"]))
            palette.setColor(QPalette.Text, QColor(theme["text_primary"]))
            palette.setColor(QPalette.Button, QColor(theme["bg_tertiary"]))
            palette.setColor(QPalette.ButtonText, QColor(theme["text_primary"]))
            palette.setColor(QPalette.BrightText, QColor(theme["accent_primary"]))
            palette.setColor(QPalette.Highlight, QColor(theme["accent_primary"]))
            palette.setColor(QPalette.HighlightedText, QColor(theme["bg_primary"]))
            palette.setColor(QPalette.Link, QColor(theme["accent_primary"]))
            palette.setColor(QPalette.LinkVisited, QColor(theme["accent_secondary"]))

            # Apply palette to application
            app = QApplication.instance()
            if app:
                app.setPalette(palette)

            # Apply stylesheet to entire application
            stylesheet = f"""
                /* Main Window */
                QMainWindow {{
                    background-color: {theme["bg_primary"]};
                    color: {theme["text_primary"]};
                }}

                /* Central Widget */
                QWidget {{
                    background-color: {theme["bg_primary"]};
                    color: {theme["text_primary"]};
                }}

                /* Menu Bar */
                QMenuBar {{
                    background-color: {theme["bg_secondary"]};
                    color: {theme["text_primary"]};
                    border-bottom: 1px solid {theme["border"]};
                    spacing: 2px;
                }}

                QMenuBar::item {{
                    background: transparent;
                    padding: 4px 12px;
                }}

                QMenuBar::item:selected {{
                    background-color: {theme["accent_primary"]};
                    color: {theme["bg_primary"]};
                }}

                /* Menu */
                QMenu {{
                    background-color: {theme["bg_secondary"]};
                    color: {theme["text_primary"]};
                    border: 1px solid {theme["border"]};
                }}

                QMenu::item {{
                    padding: 6px 25px 6px 20px;
                }}

                QMenu::item:selected {{
                    background-color: {theme["accent_primary"]};
                    color: {theme["bg_primary"]};
                }}

                /* Status Bar */
                QStatusBar {{
                    background-color: {theme["bg_secondary"]};
                    color: {theme["text_primary"]};
                    border-top: 1px solid {theme["border"]};
                }}

                /* Dock Widget */
                QDockWidget {{
                    titlebar-close-icon: url(close.png);
                    titlebar-normal-icon: url(undock.png);
                }}

                QDockWidget::title {{
                    text-align: center;
                    background-color: {theme["bg_tertiary"]};
                    color: {theme["accent_primary"]};
                    padding: 6px;
                    border: 1px solid {theme["border"]};
                    border-top-left-radius: 4px;
                    border-top-right-radius: 4px;
                }}

                /* Tool Bar */
                QToolBar {{
                    background-color: {theme["bg_secondary"]};
                    border-bottom: 1px solid {theme["border"]};
                    spacing: 2px;
                    padding: 2px;
                }}

                /* Scroll Bar */
                QScrollBar:vertical {{
                    border: none;
                    background-color: {theme["bg_secondary"]};
                    width: 10px;
                    margin: 0px;
                }}

                QScrollBar::handle:vertical {{
                    background-color: {theme["border"]};
                    min-height: 20px;
                    border-radius: 5px;
                }}

                QScrollBar::handle:vertical:hover {{
                    background-color: {theme["accent_primary"]};
                }}

                QScrollBar:horizontal {{
                    border: none;
                    background-color: {theme["bg_secondary"]};
                    height: 10px;
                    margin: 0px;
                }}

                QScrollBar::handle:horizontal {{
                    background-color: {theme["border"]};
                    min-width: 20px;
                    border-radius: 5px;
                }}

                QScrollBar::handle:horizontal:hover {{
                    background-color: {theme["accent_primary"]};
                }}

                /* Inputs and Controls */
                QLineEdit, QTextEdit, QPlainTextEdit {{
                    background-color: {theme["bg_tertiary"]};
                    color: {theme["text_primary"]};
                    border: 1px solid {theme["border"]};
                    border-radius: 4px;
                    padding: 4px 8px;
                    selection-background-color: {theme["accent_primary"]};
                    selection-color: {theme["bg_primary"]};
                }}

                QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
                    border: 1px solid {theme["accent_primary"]};
                }}

                /* Tabs */
                QTabWidget::pane {{
                    border: 1px solid {theme["border"]};
                    background-color: {theme["bg_secondary"]};
                    top: -1px;
                }}

                QTabBar::tab {{
                    background-color: {theme["bg_tertiary"]};
                    color: {theme["text_secondary"]};
                    border: 1px solid {theme["border"]};
                    padding: 6px 15px;
                    border-top-left-radius: 4px;
                    border-top-right-radius: 4px;
                }}

                QTabBar::tab:selected {{
                    background-color: {theme["accent_primary"]};
                    color: {theme["bg_primary"]};
                }}

                QTabBar::tab:!selected {{
                    margin-top: 3px; /* Make non-selected tabs look smaller */
                }}

                /* MDI Area */
                QMdiArea {{
                    background-color: {theme["bg_primary"]};
                }}

                QMdiSubWindow {{
                    background-color: {theme["bg_secondary"]};
                    border: 1px solid {theme["border"]};
                }}

                QMdiSubWindow::title {{
                    color: {theme["text_primary"]};
                    background-color: {theme["bg_tertiary"]};
                }}

                /* Labels */
                QLabel {{
                    color: {theme["text_primary"]};
                }}

                /* Special Status Indicators */
                QLabel#status_secure {{
                    color: {theme["success"]};
                    font-weight: bold;
                }}

                QLabel#status_warning {{
                    color: {theme["warning"]};
                    font-weight: bold;
                }}

                QLabel#status_danger {{
                    color: {theme["danger"]};
                    font-weight: bold;
                }}
            """

            # Apply stylesheet to application
            if app:
                app.setStyleSheet(stylesheet)

            # Set application fonts
            default_font = QFont("Consolas", 10)

            # Try to use a cyberpunk-style font if available
            cyberpunk_fonts = ["Orbitron", "Rajdhani", "Blender Pro", "Electrolize", "Consolas", "Courier New"]

            for font_name in cyberpunk_fonts:
                try:
                    if QFontDatabase.hasFamily(font_name):
                        default_font = QFont(font_name, 10)
                        break
                except:
                    pass

            if app:
                app.setFont(default_font)

            logger.info(f"Applied '{theme_name}' theme to dashboard")

        except Exception as e:
            logger.error(f"Failed to apply dashboard theme: {e}")
            # Apply minimal theme as fallback
            if QT_AVAILABLE and hasattr(self, 'setStyleSheet'):
                self.setStyleSheet("QMainWindow { background-color: #0A0A12; color: #E0E0FF; }")

    def create_animated_button(self, text, tooltip=None, icon=None, style=None):
        """
        Create a modern, animated button with hover effects

        Args:
            text: Button text
            tooltip: Optional tooltip text
            icon: Optional icon for the button
            style: Optional custom style ("success", "danger", "warning", "info")

        Returns:
            QPushButton: Stylized button with hover effects
        """
        if not QT_AVAILABLE:
            return QPushButton(text)

        try:
            button = QPushButton(text)

            if tooltip:
                button.setToolTip(tooltip)

            if icon:
                button.setIcon(icon)
                button.setIconSize(QSize(18, 18))

            # Default cyberpunk style
            base_color = "#1A1A2E"
            text_color = "#00FFFF"
            border_color = "#3D3D7A"
            hover_bg_color = "#252540"
            hover_border_color = "#00FFFF"
            pressed_bg_color = "#00FFFF"
            pressed_text_color = "#0A0A12"

            # Apply style variations if specified
            if style == "success":
                text_color = "#00FF88"
                hover_border_color = "#00FF88"
                pressed_bg_color = "#00FF88"
            elif style == "danger":
                text_color = "#FF5555"
                hover_border_color = "#FF5555"
                pressed_bg_color = "#FF5555"
            elif style == "warning":
                text_color = "#FFAA00"
                hover_border_color = "#FFAA00"
                pressed_bg_color = "#FFAA00"
            elif style == "info":
                text_color = "#00AAFF"
                hover_border_color = "#00AAFF"
                pressed_bg_color = "#00AAFF"

            # Apply stylesheet with hover and pressed effects
            button.setStyleSheet(f"""
                QPushButton {{
                    background-color: {base_color};
                    color: {text_color};
                    border: 1px solid {border_color};
                    border-radius: 4px;
                    padding: 8px 16px;
                    font-weight: bold;
                    text-transform: uppercase;
                    font-size: 11px;
                }}

                QPushButton:hover {{
                    background-color: {hover_bg_color};
                    border: 1px solid {hover_border_color};
                }}

                QPushButton:pressed {{
                    background-color: {pressed_bg_color};
                    color: {pressed_text_color};
                }}
            """)

            # Install event filter to handle animations
            button.installEventFilter(self)

            return button

        except Exception as e:
            logger.error(f"Error creating animated button: {e}")
            return QPushButton(text)

    def eventFilter(self, watched, event):
        """Event filter to add hover animations to buttons"""
        if QT_AVAILABLE and isinstance(watched, QPushButton) and hasattr(self, 'animated_buttons'):
            if event.type() == QEvent.Enter:
                # Mouse enter animation
                try:
                    # Create glow effect on hover
                    glow = QGraphicsDropShadowEffect()
                    glow.setBlurRadius(15)
                    glow.setOffset(0, 0)
                    glow.setColor(QColor("#00FFFF"))
                    watched.setGraphicsEffect(glow)
                except Exception:
                    pass
                return False

            elif event.type() == QEvent.Leave:
                # Mouse leave animation
                try:
                    watched.setGraphicsEffect(None)
                except Exception:
                    pass
                return False

        return super().eventFilter(watched, event)


# This file should not be executed directly.
# Use the dashboard_manager.py's launch_dashboard() function instead.
if __name__ == "__main__":
    logger.warning("This file should not be run directly. Use dashboard_manager.launch_dashboard() instead.")
    logger.info("Redirecting to proper launcher...")
    from frontend.gui.dashboard.dashboard_manager import launch_dashboard
    dashboard = launch_dashboard()
    if dashboard and hasattr(dashboard, 'app_instance'):
        sys.exit(dashboard.app_instance.exec_())
