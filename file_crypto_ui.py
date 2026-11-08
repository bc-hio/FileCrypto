#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
file_crypto_ui.py —— FileCrypto 文件加解密工具（Tkinter 图形界面）

功能一览
--------
* 文件加解密：单文件流式加解密（默认 AES-256-GCM 标准 AEAD），原子落盘（.part + 替换）
* 密码安全：派生前做 Unicode NFC 归一化；提交前查常见弱口令字典并强提示
* 批量处理：多文件 / 整目录递归，逐行状态、总进度、错误继续、导出 CSV 报告
* 文本加密：站内文本加解密，输出可直接复制的 Base64 密文块
* 工具箱：文件摘要（MD5/SHA1/SHA256/SHA512）、强密码生成器、安全擦除、加密文件头部查看
* 设置：算法 / KDF 强度 / 分块大小 / 主题 / 默认目录，配置持久化
* 日志：带时间戳与颜色的运行日志，可导出

运行：python file_crypto_ui.py
依赖：仅标准库（如需 AES-256-GCM / ChaCha20-Poly1305 请额外安装 cryptography）
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import json
import os
import queue
import sys
import threading
import time
import traceback
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

# 打包成 --noconsole 的 exe 后 sys.stdout/stderr 为 None，会让 print 报错，这里兜底
for _name in ("stdout", "stderr"):
    if getattr(sys, _name, None) is None:
        try:
            setattr(sys, _name, open(os.devnull, "w", encoding="utf-8"))
        except Exception:
            pass

import fcrypt_core as core  # noqa: E402

APP_NAME = "FileCrypto 文件加解密工具"
APP_VERSION = "1.0"
CONFIG_PATH = Path.home() / ".filecrypto" / "config.json"
CONFIG_VERSION = 2          # v2：默认算法升级为 AES-256-GCM
MAX_LOG_LINES = 4000

# 可选：拖拽支持（装了 tkinterdnd2 就能把文件拖进来）
try:  # pragma: no cover
    from tkinterdnd2 import DND_FILES, TkinterDnD  # type: ignore

    DND_AVAILABLE = True
except Exception:  # pragma: no cover
    DND_FILES = None  # type: ignore
    TkinterDnD = None  # type: ignore
    DND_AVAILABLE = False


# --------------------------------------------------------------------------
# 主题配色
# --------------------------------------------------------------------------

THEMES = {
    "dark": {
        "name": "深色",
        "BG": "#1b1f27", "PANEL": "#232833", "CARD": "#2a3040", "FIELD": "#2f3542",
        "FG": "#e8ecf3", "MUTED": "#98a2b3", "BORDER": "#39414f",
        "ACCENT": "#3b82f6", "ACCENT_DARK": "#2563eb", "ACCENT_FG": "#ffffff",
        "OK": "#22c55e", "WARN": "#f59e0b", "ERR": "#ef4444", "INFO": "#38bdf8",
        "SEL_BG": "#2f4a7a", "LOG_BG": "#171b22",
    },
    "light": {
        "name": "浅色",
        "BG": "#f2f5fa", "PANEL": "#ffffff", "CARD": "#ffffff", "FIELD": "#ffffff",
        "FG": "#1b2130", "MUTED": "#5f6b7c", "BORDER": "#cfd8e6",
        "ACCENT": "#2563eb", "ACCENT_DARK": "#1d4ed8", "ACCENT_FG": "#ffffff",
        "OK": "#15803d", "WARN": "#b45309", "ERR": "#dc2626", "INFO": "#0369a1",
        "SEL_BG": "#cfe0ff", "LOG_BG": "#fbfcfe",
    },
}


def pick_font(size: int = 10, bold: bool = False, mono: bool = False) -> tuple:
    """挑一个当前系统上存在的中文友好字体。"""
    if mono:
        families = ("Cascadia Mono", "Consolas", "DejaVu Sans Mono", "Courier New")
    else:
        families = ("Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC",
                    "Noto Sans CJK SC", "Segoe UI", "Helvetica")
    return (families[0], size, "bold" if bold else "normal")


def available_font(families: tuple) -> str:
    try:
        from tkinter import font as tkfont

        installed = set(tkfont.families())
        for f in families:
            if f in installed:
                return f
    except Exception:
        pass
    return families[-1]


# --------------------------------------------------------------------------
# 通用小部件
# --------------------------------------------------------------------------


class Tooltip:
    """轻量气泡提示。"""

    def __init__(self, widget: tk.Widget, text: str) -> None:
        self.widget = widget
        self.text = text
        self.tip: tk.Toplevel | None = None
        widget.bind("<Enter>", self._show, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _show(self, _event=None) -> None:
        if self.tip or not self.text:
            return
        x = self.widget.winfo_rootx() + 16
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        tk.Label(self.tip, text=self.text, justify="left", padx=8, pady=4,
                 relief="solid", borderwidth=1).pack()

    def _hide(self, _event=None) -> None:
        if self.tip:
            self.tip.destroy()
            self.tip = None


# --------------------------------------------------------------------------
# 主应用
# --------------------------------------------------------------------------


class FileCryptoApp:
    def __init__(self, root: tk.Tk, theme: str = "dark") -> None:
        self.root = root
        self.config = self._load_config()
        self.theme_key = theme or self.config.get("theme", "dark")
        if self.theme_key not in THEMES:
            self.theme_key = "dark"
        self.C = THEMES[self.theme_key]

        self.q: "queue.Queue[tuple]" = queue.Queue()
        self.task: dict | None = None          # 当前任务上下文
        self.worker: threading.Thread | None = None
        self.cancel_event = threading.Event()
        self.log_lines: list[str] = []
        self.text_widgets: list[tuple[tk.Text, str]] = []
        self._poll_id: str | None = None
        self._closing = False
        self.batch_items: list[dict] = []
        self.pw_var = tk.StringVar()           # 单文件密码
        self.batch_pw_var = tk.StringVar()     # 批量密码
        self.text_pw_var = tk.StringVar()      # 文本密码

        self._setup_window()
        self._setup_fonts()
        self._setup_styles()
        self._build_header()
        self._build_notebook()
        self._build_statusbar()

        self._apply_theme_to_texts()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(80, self._poll_queue)
        self.log("程序启动完成，默认算法：" + core.ALGORITHMS[core.DEFAULT_ALGO]
                + ("（cryptography " + core.CRYPTOGRAPHY_VERSION + " 已加载）"
                   if core.CRYPTOGRAPHY_AVAILABLE else "（未安装 cryptography，将退回内置算法）"), "ok")
        if not core.CRYPTOGRAPHY_AVAILABLE:
            self.log("提示：pip install cryptography 后可启用 AES-256-GCM / ChaCha20-Poly1305", "warn")
        if DND_AVAILABLE:
            self.log("已启用拖拽支持（可直接把文件拖到窗口）", "ok")

    # ------------------------------------------------------------------
    # 窗口 / 样式
    # ------------------------------------------------------------------
    def _setup_window(self) -> None:
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        geo = self.config.get("geometry") or "1120x780"
        self.root.geometry(geo)
        self.root.minsize(960, 660)
        self.root.configure(bg=self.C["BG"])
        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass

    def _setup_fonts(self) -> None:
        self.f_ui = available_font(("Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC",
                                    "Noto Sans CJK SC", "Segoe UI"))
        self.f_mono = available_font(("Cascadia Mono", "Consolas", "DejaVu Sans Mono",
                                      "Courier New"))
        self.f_h1 = (self.f_ui, 15, "bold")
        self.f_h2 = (self.f_ui, 11, "bold")
        self.f_base = (self.f_ui, 10)
        self.f_small = (self.f_ui, 9)

    def _setup_styles(self) -> None:
        C = self.C
        st = ttk.Style(self.root)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure(".", background=C["BG"], foreground=C["FG"], font=self.f_base,
                     bordercolor=C["BORDER"], focuscolor=C["ACCENT"])
        st.configure("TFrame", background=C["BG"])
        st.configure("Card.TFrame", background=C["PANEL"], relief="flat")
        st.configure("TLabel", background=C["BG"], foreground=C["FG"], font=self.f_base)
        st.configure("Card.TLabel", background=C["PANEL"], foreground=C["FG"])
        st.configure("Muted.TLabel", background=C["BG"], foreground=C["MUTED"], font=self.f_small)
        st.configure("CardMuted.TLabel", background=C["PANEL"], foreground=C["MUTED"], font=self.f_small)
        st.configure("H1.TLabel", background=C["BG"], foreground=C["FG"], font=self.f_h1)
        st.configure("H2.TLabel", background=C["PANEL"], foreground=C["ACCENT"], font=self.f_h2)
        st.configure("Badge.TLabel", background=C["CARD"], foreground=C["ACCENT"], padding=(8, 3),
                     font=self.f_small)
        st.configure("OK.TLabel", background=C["BG"], foreground=C["OK"], font=self.f_small)
        st.configure("Warn.TLabel", background=C["BG"], foreground=C["WARN"], font=self.f_small)
        st.configure("Err.TLabel", background=C["BG"], foreground=C["ERR"], font=self.f_small)

        st.configure("TLabelframe", background=C["BG"], bordercolor=C["BORDER"], relief="solid",
                     borderwidth=1)
        st.configure("TLabelframe.Label", background=C["BG"], foreground=C["ACCENT"],
                     font=self.f_h2)

        st.configure("TButton", background=C["CARD"], foreground=C["FG"], padding=(12, 6),
                     relief="flat", borderwidth=1, font=self.f_base)
        st.map("TButton",
               background=[("pressed", C["BORDER"]), ("active", C["FIELD"]), ("disabled", C["BG"])],
               foreground=[("disabled", C["MUTED"])])
        st.configure("Accent.TButton", background=C["ACCENT"], foreground=C["ACCENT_FG"],
                     padding=(16, 7), font=(self.f_ui, 10, "bold"), borderwidth=0)
        st.map("Accent.TButton",
               background=[("pressed", C["ACCENT_DARK"]), ("active", C["ACCENT_DARK"]),
                           ("disabled", C["BORDER"])],
               foreground=[("disabled", C["MUTED"])])
        st.configure("Danger.TButton", background=C["ERR"], foreground="#ffffff",
                     padding=(12, 7), font=(self.f_ui, 10, "bold"), borderwidth=0)
        st.map("Danger.TButton", background=[("active", "#b91c1c"), ("disabled", C["BORDER"])])
        st.configure("Ghost.TButton", background=C["BG"], foreground=C["MUTED"], borderwidth=0,
                     padding=(8, 4))
        st.map("Ghost.TButton", background=[("active", C["FIELD"])], foreground=[("active", C["FG"])])

        st.configure("TEntry", fieldbackground=C["FIELD"], foreground=C["FG"],
                     insertcolor=C["FG"], bordercolor=C["BORDER"], lightcolor=C["BORDER"],
                     darkcolor=C["BORDER"], padding=4)
        st.map("TEntry", fieldbackground=[("disabled", C["BG"])],
               foreground=[("disabled", C["MUTED"])])
        st.configure("TCombobox", fieldbackground=C["FIELD"], background=C["CARD"],
                     foreground=C["FG"], arrowcolor=C["FG"], bordercolor=C["BORDER"], padding=4)
        st.map("TCombobox", fieldbackground=[("readonly", C["FIELD"])],
               foreground=[("readonly", C["FG"])])
        self.root.option_add("*TCombobox*Listbox.background", C["FIELD"])
        self.root.option_add("*TCombobox*Listbox.foreground", C["FG"])
        self.root.option_add("*TCombobox*Listbox.selectBackground", C["ACCENT"])
        self.root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")
        self.root.option_add("*TCombobox*Listbox.font", self.f_base)

        st.configure("TCheckbutton", background=C["BG"], foreground=C["FG"], focuscolor=C["BG"],
                     font=self.f_base)
        st.map("TCheckbutton", background=[("active", C["BG"])],
               indicatorcolor=[("selected", C["ACCENT"]), ("!selected", C["FIELD"])])
        st.configure("Card.TCheckbutton", background=C["PANEL"], foreground=C["FG"],
                     focuscolor=C["PANEL"])
        st.map("Card.TCheckbutton", background=[("active", C["PANEL"])])
        st.configure("TRadiobutton", background=C["BG"], foreground=C["FG"], focuscolor=C["BG"])
        st.map("TRadiobutton", background=[("active", C["BG"])])

        st.configure("TNotebook", background=C["BG"], bordercolor=C["BORDER"], tabmargins=(6, 6, 6, 0))
        st.configure("TNotebook.Tab", background=C["PANEL"], foreground=C["MUTED"],
                     padding=(18, 9), font=self.f_base, borderwidth=0)
        st.map("TNotebook.Tab",
               background=[("selected", C["BG"]), ("active", C["CARD"])],
               foreground=[("selected", C["ACCENT"]), ("active", C["FG"])])

        st.configure("Treeview", background=C["PANEL"], fieldbackground=C["PANEL"],
                     foreground=C["FG"], bordercolor=C["BORDER"], rowheight=26,
                     font=self.f_base, borderwidth=0)
        st.configure("Treeview.Heading", background=C["CARD"], foreground=C["MUTED"],
                     font=(self.f_ui, 9, "bold"), relief="flat", padding=(6, 6))
        st.map("Treeview.Heading", background=[("active", C["BORDER"])])
        st.map("Treeview", background=[("selected", C["SEL_BG"])],
               foreground=[("selected", C["FG"])])

        st.configure("TProgressbar", background=C["ACCENT"], troughcolor=C["FIELD"],
                     bordercolor=C["BORDER"], lightcolor=C["ACCENT"], darkcolor=C["ACCENT"],
                     thickness=14)
        st.configure("Strength.Horizontal.TProgressbar", thickness=8)
        st.configure("TSeparator", background=C["BORDER"])
        st.configure("TPanedwindow", background=C["BG"])

    def _apply_theme_to_texts(self) -> None:
        C = self.C
        for widget, role in self.text_widgets:
            try:
                widget.configure(bg=C["LOG_BG"] if role == "log" else C["FIELD"], fg=C["FG"],
                                 insertbackground=C["FG"], selectbackground=C["SEL_BG"],
                                 selectforeground=C["FG"], relief="flat", borderwidth=0,
                                 highlightthickness=1, highlightbackground=C["BORDER"],
                                 highlightcolor=C["ACCENT"])
                widget.tag_configure("info", foreground=C["FG"])
                widget.tag_configure("ok", foreground=C["OK"])
                widget.tag_configure("warn", foreground=C["WARN"])
                widget.tag_configure("err", foreground=C["ERR"])
                widget.tag_configure("time", foreground=C["MUTED"])
                widget.tag_configure("accent", foreground=C["ACCENT"])
            except tk.TclError:
                pass

    # ------------------------------------------------------------------
    # 顶栏 / 状态栏
    # ------------------------------------------------------------------
    def _build_header(self) -> None:
        C = self.C
        bar = ttk.Frame(self.root, padding=(16, 12, 16, 6))
        bar.pack(fill="x")
        # 先打包右侧固定宽度控件，再打包可伸展的标题区，避免被挤出可视范围
        right = ttk.Frame(bar)
        right.pack(side="right")
        self.algo_badge = ttk.Label(right, text="", style="Badge.TLabel")
        self.algo_badge.pack(side="left", padx=(0, 8))
        ttk.Button(right, text="切换主题", style="Ghost.TButton",
                   command=self._toggle_theme).pack(side="left")

        left = ttk.Frame(bar)
        left.pack(side="left", fill="x", expand=True)
        ttk.Label(left, text="🔐  " + APP_NAME, style="H1.TLabel").pack(anchor="w")
        sub = ("AES-256-GCM 标准 AEAD（默认）· ChaCha20 / SHAKE-256 可选 · 分块流式 · "
               "密码 NFC 归一化 + 弱口令检测"
               if core.CRYPTOGRAPHY_AVAILABLE else
               "未检测到 cryptography，已退回内置 SHAKE-256 流密码（安全性弱于标准 AEAD）")
        ttk.Label(left, text=sub, style="Muted.TLabel").pack(anchor="w", pady=(2, 0))

    def _build_statusbar(self) -> None:
        C = self.C
        bar = tk.Frame(self.root, bg=C["PANEL"], height=46)
        bar.pack(side="bottom", fill="x")
        inner = ttk.Frame(bar, style="Card.TFrame", padding=(14, 6))
        inner.pack(fill="both", expand=True)
        self.status_var = tk.StringVar(value="就绪")
        self.status_lbl = ttk.Label(inner, textvariable=self.status_var, style="Card.TLabel")
        self.status_lbl.pack(side="left")
        # 右侧控件按“由外向内”的顺序打包
        self.cancel_btn = ttk.Button(inner, text="取消", style="Danger.TButton",
                                     command=self._cancel_task, state="disabled")
        self.cancel_btn.pack(side="right", padx=(10, 0))
        self.detail_var = tk.StringVar(value="")
        ttk.Label(inner, textvariable=self.detail_var, style="CardMuted.TLabel",
                  width=30, anchor="e").pack(side="right", padx=(0, 12))
        self.progress = ttk.Progressbar(inner, mode="determinate", maximum=1000, length=280)
        self.progress.pack(side="right", fill="x", expand=True, padx=10)

    # ------------------------------------------------------------------
    # 选项卡
    # ------------------------------------------------------------------
    def _build_notebook(self) -> None:
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=16, pady=(4, 12))
        self.tabs: dict[str, ttk.Frame] = {}
        for key, title in (("file", "  文件加解密  "), ("batch", "  批量 / 文件夹  "),
                           ("text", "  文本加密  "), ("tools", "  工具箱  "),
                           ("settings", "  设置  "), ("log", "  日志  "), ("about", "  帮助  ")):
            frame = ttk.Frame(self.nb, padding=14)
            self.nb.add(frame, text=title)
            self.tabs[key] = frame

        self._build_file_tab(self.tabs["file"])
        self._build_batch_tab(self.tabs["batch"])
        self._build_text_tab(self.tabs["text"])
        self._build_tools_tab(self.tabs["tools"])
        self._build_settings_tab(self.tabs["settings"])
        self._build_log_tab(self.tabs["log"])
        self._build_about_tab(self.tabs["about"])
        self._refresh_algo_badge()

    # -- 小工具 ---------------------------------------------------------
    def _make_text(self, parent, height: int = 10, role: str = "text", wrap: str = "word",
                   readonly: bool = False, width: int = 30) -> tk.Text:
        # width 用较小值，避免 Text 默认 80 字符宽度把整个窗口请求宽度撑大
        widget = ScrolledText(parent, height=height, width=width, wrap=wrap,
                              font=(self.f_mono, 10), relief="flat", borderwidth=0)
        if readonly:
            widget.configure(state="disabled")
        self.text_widgets.append((widget, role))
        C = self.C
        widget.configure(bg=C["LOG_BG"] if role == "log" else C["FIELD"], fg=C["FG"],
                         insertbackground=C["FG"])
        return widget

    def _section(self, parent, title: str) -> ttk.Frame:
        box = ttk.LabelFrame(parent, text="  " + title + "  ", padding=12)
        box.pack(fill="x", pady=(0, 10))
        return box

    # ------------------------------------------------------------------
    # 文件加解密页
    # ------------------------------------------------------------------
    def _build_file_tab(self, parent: ttk.Frame) -> None:
        self.file_in = tk.StringVar()
        self.file_out_dir = tk.StringVar()
        self.file_keyfile = tk.StringVar()
        self.file_note = tk.StringVar()
        self.file_out_same = tk.BooleanVar(value=True)
        self.file_store_name = tk.BooleanVar(value=True)
        self.file_keep_mtime = tk.BooleanVar(value=True)
        self.file_overwrite = tk.BooleanVar(value=False)
        self.file_delete_src = tk.BooleanVar(value=False)
        self.file_wipe = tk.BooleanVar(value=False)
        self.file_show_pw = tk.BooleanVar(value=False)
        self.file_confirm = tk.StringVar()

        sec1 = self._section(parent, "文件")
        row = ttk.Frame(sec1)
        row.pack(fill="x", pady=2)
        ttk.Label(row, text="源文件", width=10).pack(side="left")
        ttk.Button(row, text="选择文件夹…", command=self._pick_folder_single).pack(side="right")
        ttk.Button(row, text="选择文件…", command=self._pick_file).pack(side="right", padx=6)
        e = ttk.Entry(row, textvariable=self.file_in)
        e.pack(side="left", fill="x", expand=True)
        if DND_AVAILABLE:
            self._register_drop(e, self._drop_files_single)

        info = ttk.Frame(sec1)
        info.pack(fill="x", pady=(6, 0))
        self.file_info_lbl = ttk.Label(info, text="尚未选择文件", style="Muted.TLabel")
        self.file_info_lbl.pack(side="left")
        self.file_in.trace_add("write", lambda *_: self._update_file_info())

        sec2 = self._section(parent, "输出")
        r = ttk.Frame(sec2)
        r.pack(fill="x")
        ttk.Radiobutton(r, text="与源文件同目录", variable=self.file_out_same,
                        value=True, command=self._sync_out_dir_state).pack(side="left")
        ttk.Radiobutton(r, text="指定目录", variable=self.file_out_same,
                        value=False, command=self._sync_out_dir_state).pack(side="left", padx=12)
        self.out_dir_entry = ttk.Entry(sec2, textvariable=self.file_out_dir)
        self.out_dir_entry.pack(fill="x", pady=6)
        btns = ttk.Frame(sec2)
        btns.pack(fill="x")
        ttk.Button(btns, text="浏览目录…", command=self._pick_out_dir).pack(side="left")
        ttk.Button(btns, text="打开输出目录", command=self._open_out_dir).pack(side="left", padx=6)
        self._sync_out_dir_state()

        sec3 = self._section(parent, "密码")
        pwrow = ttk.Frame(sec3)
        pwrow.pack(fill="x")
        ttk.Label(pwrow, text="密码", width=10).pack(side="left")
        ttk.Button(pwrow, text="随机生成", command=self._gen_password_single).pack(side="right")
        ttk.Button(pwrow, text="显示", width=6, command=self._toggle_pw).pack(side="right", padx=6)
        self.pw_entry = ttk.Entry(pwrow, textvariable=self.pw_var, show="●")
        self.pw_entry.pack(side="left", fill="x", expand=True)
        self.pw_var.trace_add("write", lambda *_: self._update_strength())

        self.strength_bar = ttk.Progressbar(sec3, maximum=100, style="Strength.Horizontal.TProgressbar")
        self.strength_bar.pack(fill="x", pady=(8, 2))
        self.strength_lbl = ttk.Label(sec3, text="强度：—", style="Muted.TLabel")
        self.strength_lbl.pack(anchor="w")

        crow = ttk.Frame(sec3)
        crow.pack(fill="x", pady=(6, 0))
        ttk.Label(crow, text="确认密码", width=10).pack(side="left")
        ttk.Label(crow, text="（加密时校验两次输入一致）", style="Muted.TLabel").pack(side="right")
        ttk.Entry(crow, textvariable=self.file_confirm, show="●").pack(side="left", fill="x", expand=True)

        krow = ttk.Frame(sec3)
        krow.pack(fill="x", pady=(8, 0))
        ttk.Label(krow, text="密钥文件", width=10).pack(side="left")
        ttk.Button(krow, text="清除", width=6,
                   command=lambda: self.file_keyfile.set("")).pack(side="right")
        ttk.Button(krow, text="选择…", command=self._pick_keyfile).pack(side="right", padx=6)
        ttk.Entry(krow, textvariable=self.file_keyfile).pack(side="left", fill="x", expand=True)
        Tooltip(krow, "可选。选择后，解密必须同时提供相同密钥文件，安全性更高。")

        nrow = ttk.Frame(sec3)
        nrow.pack(fill="x", pady=(8, 0))
        ttk.Label(nrow, text="备注", width=10).pack(side="left")
        ttk.Label(nrow, text="（加密时写入文件头，解密后可查看）", style="Muted.TLabel").pack(side="right")
        ttk.Entry(nrow, textvariable=self.file_note).pack(side="left", fill="x", expand=True)

        sec4 = self._section(parent, "选项与操作")
        grid = ttk.Frame(sec4)
        grid.pack(fill="x")
        opts = [(self.file_store_name, "记录原始文件名（加密在文件头，防泄露）"),
                (self.file_keep_mtime, "解密后恢复原始修改时间"),
                (self.file_overwrite, "覆盖已存在的输出文件"),
                (self.file_delete_src, "完成后删除源文件"),
                (self.file_wipe, "删除源文件前覆写擦除（SSD 上无效，见帮助）")]
        for i, (var, text) in enumerate(opts):
            ttk.Checkbutton(grid, text=text, variable=var).grid(
                row=i // 2, column=i % 2, sticky="w", padx=(0, 18), pady=2)

        act = ttk.Frame(sec4)
        act.pack(fill="x", pady=(12, 0))
        ttk.Button(act, text="🔒  加密文件", style="Accent.TButton",
                   command=self._do_encrypt_file).pack(side="left")
        ttk.Button(act, text="🔓  解密文件", style="Accent.TButton",
                   command=self._do_decrypt_file).pack(side="left", padx=8)
        ttk.Button(act, text="查看文件头", command=self._inspect_selected_file).pack(side="left", padx=8)
        ttk.Button(act, text="清空", command=self._clear_file_tab).pack(side="right")

        self.file_result = ttk.Label(parent, text="", style="Muted.TLabel", wraplength=980,
                                     justify="left")
        self.file_result.pack(fill="x", pady=(4, 0))

    # ------------------------------------------------------------------
    # 批量页
    # ------------------------------------------------------------------
    def _build_batch_tab(self, parent: ttk.Frame) -> None:
        self.batch_out_dir = tk.StringVar()
        self.batch_out_same = tk.BooleanVar(value=True)
        self.batch_mirror = tk.BooleanVar(value=True)
        self.batch_suffix = tk.StringVar(value=core.DEFAULT_SUFFIX)
        self.batch_conflict = tk.StringVar(value="rename")
        self.batch_keep_going = tk.BooleanVar(value=True)
        self.batch_auto = tk.BooleanVar(value=True)
        self.batch_delete_src = tk.BooleanVar(value=False)
        self.batch_show_pw = tk.BooleanVar(value=False)

        sec1 = self._section(parent, "待处理列表")
        bar = ttk.Frame(sec1)
        bar.pack(fill="x", pady=(0, 6))
        for text, cmd in (("添加文件…", self._batch_add_files), ("添加文件夹…", self._batch_add_folder),
                          ("移除选中", self._batch_remove_selected), ("清空列表", self._batch_clear),
                          ("导出报告 CSV", self._batch_export_report)):
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=(0, 6))
        self.batch_auto_btn = ttk.Checkbutton(
            bar, text="自动识别加密文件（按文件头）", variable=self.batch_auto,
            command=self._batch_refresh_types)
        self.batch_auto_btn.pack(side="right")

        wrap = ttk.Frame(sec1)
        wrap.pack(fill="both", expand=True)
        cols = ("name", "size", "type", "status")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", height=8,
                                 selectmode="extended")
        for col, title, width, anchor in (("name", "文件", 460, "w"), ("size", "大小", 100, "e"),
                                          ("type", "识别类型", 110, "center"),
                                          ("status", "状态", 160, "center")):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor=anchor, stretch=(col == "name"))
        vs = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.tree.tag_configure("ok", foreground=self.C["OK"])
        self.tree.tag_configure("err", foreground=self.C["ERR"])
        self.tree.tag_configure("skip", foreground=self.C["WARN"])
        self.tree.tag_configure("run", foreground=self.C["ACCENT"])
        if DND_AVAILABLE:
            self._register_drop(self.tree, self._drop_files_batch)

        self.batch_summary = ttk.Label(sec1, text="列表为空", style="Muted.TLabel")
        self.batch_summary.pack(anchor="w", pady=(6, 0))

        sec2 = self._section(parent, "输出与策略")
        r1 = ttk.Frame(sec2)
        r1.pack(fill="x")
        ttk.Radiobutton(r1, text="输出到源文件目录", variable=self.batch_out_same, value=True,
                        command=self._sync_batch_dir).pack(side="left")
        ttk.Radiobutton(r1, text="统一输出到", variable=self.batch_out_same, value=False,
                        command=self._sync_batch_dir).pack(side="left", padx=(12, 6))
        ttk.Button(r1, text="浏览…", command=self._pick_batch_dir).pack(side="right")
        self.batch_dir_entry = ttk.Entry(r1, textvariable=self.batch_out_dir)
        self.batch_dir_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))

        r2 = ttk.Frame(sec2)
        r2.pack(fill="x", pady=(8, 0))
        ttk.Checkbutton(r2, text="保持子目录结构", variable=self.batch_mirror).pack(side="left")
        ttk.Label(r2, text="加密后缀").pack(side="left", padx=(16, 4))
        ttk.Entry(r2, textvariable=self.batch_suffix, width=12).pack(side="left")
        ttk.Label(r2, text="同名文件").pack(side="left", padx=(16, 4))
        ttk.Combobox(r2, textvariable=self.batch_conflict, state="readonly", width=10,
                     values=("rename", "overwrite", "skip")).pack(side="left")
        ttk.Checkbutton(r2, text="出错后继续处理剩余文件",
                        variable=self.batch_keep_going).pack(side="left", padx=16)

        pw = ttk.Frame(sec2)
        pw.pack(fill="x", pady=(8, 0))
        ttk.Label(pw, text="统一密码", width=10).pack(side="left")
        ttk.Checkbutton(pw, text="完成后删除源文件",
                        variable=self.batch_delete_src).pack(side="right")
        ttk.Button(pw, text="随机生成",
                   command=lambda: self.batch_pw_var.set(core.generate_password(22))).pack(side="right", padx=6)
        ttk.Button(pw, text="显示", width=6,
                   command=lambda: self._toggle_entry_show(self.batch_pw_entry)).pack(side="right", padx=6)
        self.batch_pw_entry = ttk.Entry(pw, textvariable=self.batch_pw_var, show="●")
        self.batch_pw_entry.pack(side="left", fill="x", expand=True)

        act = ttk.Frame(sec2)
        act.pack(fill="x", pady=(12, 0))
        ttk.Button(act, text="🔒  全部加密", style="Accent.TButton",
                   command=lambda: self._run_batch("encrypt")).pack(side="left")
        ttk.Button(act, text="🔓  全部解密", style="Accent.TButton",
                   command=lambda: self._run_batch("decrypt")).pack(side="left", padx=8)
        ttk.Button(act, text="▶  自动处理（按识别类型）", style="Accent.TButton",
                   command=lambda: self._run_batch("auto")).pack(side="left", padx=8)
        ttk.Button(act, text="移除已完成", command=self._batch_remove_done).pack(side="right")

    # ------------------------------------------------------------------
    # 文本页
    # ------------------------------------------------------------------
    def _build_text_tab(self, parent: ttk.Frame) -> None:
        self.text_show_pw = tk.BooleanVar(value=False)
        sec = self._section(parent, "文本加密 / 解密")
        pw = ttk.Frame(sec)
        pw.pack(fill="x", pady=(0, 8))
        ttk.Label(pw, text="密码", width=10).pack(side="left")
        ttk.Button(pw, text="随机生成",
                   command=lambda: self.text_pw_var.set(core.generate_password(20))).pack(side="right")
        ttk.Button(pw, text="显示", width=6,
                   command=lambda: self._toggle_entry_show(self.text_pw_entry)).pack(side="right", padx=6)
        self.text_pw_entry = ttk.Entry(pw, textvariable=self.text_pw_var, show="●")
        self.text_pw_entry.pack(side="left", fill="x", expand=True)

        body = ttk.Frame(sec)
        body.pack(fill="both", expand=True)
        left = ttk.Frame(body)
        left.pack(side="left", fill="both", expand=True)
        right = ttk.Frame(body)
        right.pack(side="left", fill="both", expand=True, padx=(12, 0))
        ttk.Label(left, text="明文输入", style="CardMuted.TLabel").pack(anchor="w")
        self.text_in = self._make_text(left, height=12)
        self.text_in.pack(fill="both", expand=True)
        ttk.Label(right, text="密文输出 / 输入", style="CardMuted.TLabel").pack(anchor="w")
        self.text_out = self._make_text(right, height=12)
        self.text_out.pack(fill="both", expand=True)

        act = ttk.Frame(sec)
        act.pack(fill="x", pady=(10, 0))
        ttk.Button(act, text="🔒  加密 →", style="Accent.TButton",
                   command=self._do_text_encrypt).pack(side="left")
        ttk.Button(act, text="🔓  ← 解密", style="Accent.TButton",
                   command=self._do_text_decrypt).pack(side="left", padx=8)
        ttk.Button(act, text="复制输出", command=self._copy_text_out).pack(side="left", padx=8)
        ttk.Button(act, text="↑ 用输出替换输入", command=self._swap_text).pack(side="left", padx=8)
        ttk.Button(act, text="清空",
                   command=lambda: (self._set_text(self.text_in, ""),
                                    self._set_text(self.text_out, ""))).pack(side="right")
        ttk.Label(sec, text="加密结果可直接通过微信/邮件发送；解密时把整段密文（含 BEGIN/END 行）粘到右侧即可。",
                  style="CardMuted.TLabel").pack(anchor="w", pady=(8, 0))

    # ------------------------------------------------------------------
    # 工具箱页
    # ------------------------------------------------------------------
    def _build_tools_tab(self, parent: ttk.Frame) -> None:
        # 摘要
        sec = self._section(parent, "文件摘要（哈希）")
        self.hash_file = tk.StringVar()
        row = ttk.Frame(sec)
        row.pack(fill="x")
        ttk.Label(row, text="文件", width=10).pack(side="left")
        ttk.Button(row, text="选择…", command=self._pick_hash_file).pack(side="right")
        ttk.Entry(row, textvariable=self.hash_file).pack(side="left", fill="x", expand=True, padx=(0, 6))
        row2 = ttk.Frame(sec)
        row2.pack(fill="x", pady=8)
        self.hash_algos = {a: tk.BooleanVar(value=(a in ("sha256", "md5")))
                           for a in ("md5", "sha1", "sha256", "sha512")}
        for a, var in self.hash_algos.items():
            ttk.Checkbutton(row2, text=a.upper(), variable=var).pack(side="left", padx=(0, 12))
        ttk.Button(row2, text="计算摘要", style="Accent.TButton",
                   command=self._do_hash).pack(side="left", padx=8)
        ttk.Button(row2, text="复制结果", command=self._copy_hash).pack(side="left")
        self.hash_out = self._make_text(sec, height=5, wrap="none")
        self.hash_out.pack(fill="x")
        self._set_text(self.hash_out, "")
        self.hash_result_text = ""

        # 密码生成
        sec2 = self._section(parent, "强密码生成器")
        r = ttk.Frame(sec2)
        r.pack(fill="x")
        ttk.Label(r, text="长度").pack(side="left")
        self.gen_len = tk.IntVar(value=20)
        ttk.Spinbox(r, from_=6, to=128, textvariable=self.gen_len, width=5).pack(side="left", padx=6)
        ttk.Label(r, text="数量").pack(side="left", padx=(12, 0))
        self.gen_count = tk.IntVar(value=5)
        ttk.Spinbox(r, from_=1, to=50, textvariable=self.gen_count, width=5).pack(side="left", padx=6)
        ttk.Button(r, text="复制全部", command=self._copy_generated).pack(side="right", padx=(6, 0))
        ttk.Button(r, text="生成", style="Accent.TButton",
                   command=self._do_generate).pack(side="right")
        r_chars = ttk.Frame(sec2)
        r_chars.pack(fill="x", pady=(8, 0))
        ttk.Label(r_chars, text="字符集 ").pack(side="left")
        self.gen_opts = {k: tk.BooleanVar(value=True) for k in ("小写", "大写", "数字", "符号")}
        for k, var in self.gen_opts.items():
            ttk.Checkbutton(r_chars, text=k, variable=var).pack(side="left", padx=(10, 0))
        self.gen_ambig = tk.BooleanVar(value=True)
        ttk.Checkbutton(r_chars, text="排除易混字符", variable=self.gen_ambig).pack(side="left", padx=12)
        self.gen_out = self._make_text(sec2, height=5, wrap="none")
        self.gen_out.pack(fill="x", pady=(8, 0))
        self.generated: list[str] = []

        # 安全擦除
        sec3 = self._section(parent, "文件覆写擦除（机械盘有效；SSD 请依赖全盘加密）")
        r3 = ttk.Frame(sec3)
        r3.pack(fill="x")
        ttk.Label(r3, text="目标", width=10).pack(side="left")
        ttk.Button(r3, text="选择文件夹…", command=self._pick_wipe_dir).pack(side="right")
        ttk.Button(r3, text="选择文件…", command=self._pick_wipe_file).pack(side="right", padx=6)
        self.wipe_path = tk.StringVar()
        ttk.Entry(r3, textvariable=self.wipe_path).pack(side="left", fill="x", expand=True, padx=(0, 6))
        r4 = ttk.Frame(sec3)
        r4.pack(fill="x", pady=8)
        ttk.Label(r4, text="覆写次数").pack(side="left")
        self.wipe_passes = tk.IntVar(value=3)
        ttk.Spinbox(r4, from_=1, to=35, textvariable=self.wipe_passes, width=5).pack(side="left", padx=6)
        ttk.Button(r4, text="⚠  立即擦除", style="Danger.TButton",
                   command=self._do_wipe).pack(side="left", padx=10)
        ttk.Label(r4, text="⚠ SSD / NVMe / 写时复制文件系统上覆写无法清除物理块，请启用以 BitLocker 为代表的整盘加密。",
                  style="Warn.TLabel").pack(side="left")

        # 头部查看
        sec4 = self._section(parent, "加密文件信息")
        r5 = ttk.Frame(sec4)
        r5.pack(fill="x")
        self.inspect_file = tk.StringVar()
        ttk.Button(r5, text="查看信息", command=self._do_inspect).pack(side="right")
        ttk.Button(r5, text="选择…", command=self._pick_inspect_file).pack(side="right", padx=6)
        ttk.Entry(r5, textvariable=self.inspect_file).pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.inspect_out = self._make_text(sec4, height=7, wrap="word")
        self.inspect_out.pack(fill="x", pady=(8, 0))

    # ------------------------------------------------------------------
    # 设置页
    # ------------------------------------------------------------------
    def _build_settings_tab(self, parent: ttk.Frame) -> None:
        cfg = self.config
        self.set_algo = tk.StringVar()
        self.set_kdf = tk.StringVar()
        self.set_preset = tk.StringVar()
        self.set_chunk = tk.StringVar()
        self.set_theme = tk.StringVar()
        self.set_out_dir = tk.StringVar(value=cfg.get("default_out_dir", ""))
        self.set_autoscroll = tk.BooleanVar(value=cfg.get("auto_scroll", True))
        self.set_confirm_delete = tk.BooleanVar(value=cfg.get("confirm_delete", True))

        sec = self._section(parent, "默认加密参数（对所有页面生效）")
        g = ttk.Frame(sec)
        g.pack(fill="x")
        ttk.Label(g, text="加密算法", width=12).grid(row=0, column=0, sticky="w", pady=4)
        self.algo_combo = ttk.Combobox(g, textvariable=self.set_algo, state="readonly", width=52,
                                       values=[core.ALGORITHMS[k] for k in core.ALGORITHMS])
        self.algo_combo.grid(row=0, column=1, sticky="w", pady=4)
        self.algo_combo.bind("<<ComboboxSelected>>", lambda *_: self._set_algo_from_label())

        ttk.Label(g, text="密钥派生", width=12).grid(row=1, column=0, sticky="w", pady=4)
        self.kdf_combo = ttk.Combobox(g, textvariable=self.set_kdf, state="readonly", width=32,
                                      values=[core.KDFS[k] for k in core.KDFS])
        self.kdf_combo.grid(row=1, column=1, sticky="w", pady=4)
        self.kdf_combo.bind("<<ComboboxSelected>>", lambda *_: self._set_kdf_from_label())

        ttk.Label(g, text="KDF 强度", width=12).grid(row=2, column=0, sticky="w", pady=4)
        ttk.Combobox(g, textvariable=self.set_preset, state="readonly", width=16,
                     values=list(core.KDF_PRESETS)).grid(row=2, column=1, sticky="w", pady=4)
        self.kdf_hint = ttk.Label(g, text="", style="Muted.TLabel")
        self.kdf_hint.grid(row=2, column=1, sticky="w", padx=(140, 0), pady=4)
        self.set_preset.trace_add("write", lambda *_: self._update_kdf_hint())

        ttk.Label(g, text="分块大小", width=12).grid(row=3, column=0, sticky="w", pady=4)
        ttk.Combobox(g, textvariable=self.set_chunk, state="readonly", width=16,
                     values=list(core.CHUNK_SIZES)).grid(row=3, column=1, sticky="w", pady=4)

        sec2 = self._section(parent, "界面与默认值")
        r = ttk.Frame(sec2)
        r.pack(fill="x")
        ttk.Label(r, text="主题", width=12).pack(side="left")
        ttk.Combobox(r, textvariable=self.set_theme, state="readonly", width=10,
                     values=[THEMES[k]["name"] for k in THEMES]).pack(side="left")
        ttk.Button(r, text="应用主题", command=self._apply_theme_from_settings).pack(side="left", padx=8)
        r2 = ttk.Frame(sec2)
        r2.pack(fill="x", pady=8)
        ttk.Label(r2, text="默认输出目录", width=12).pack(side="left")
        ttk.Button(r2, text="浏览…", command=self._pick_set_out_dir).pack(side="right")
        ttk.Entry(r2, textvariable=self.set_out_dir).pack(side="left", fill="x", expand=True, padx=(0, 6))
        r3 = ttk.Frame(sec2)
        r3.pack(fill="x")
        ttk.Checkbutton(r3, text="日志自动滚动到最新", variable=self.set_autoscroll).pack(side="left")
        ttk.Checkbutton(r3, text="敏感操作（删除/擦除）二次确认",
                        variable=self.set_confirm_delete).pack(side="left", padx=16)
        r4 = ttk.Frame(sec2)
        r4.pack(fill="x", pady=(12, 0))
        ttk.Button(r4, text="保存设置", style="Accent.TButton",
                   command=self._save_settings).pack(side="left")
        ttk.Button(r4, text="恢复默认", command=self._reset_settings).pack(side="left", padx=8)
        ttk.Button(r4, text="打开配置文件位置",
                   command=lambda: self._reveal(CONFIG_PATH)).pack(side="left", padx=8)

        # 运行时状态
        sec3 = self._section(parent, "运行环境")
        env = (f"Python {sys.version.split()[0]}    Tk {tk.TkVersion}    "
               f"cryptography：{'可用 ✔' if core.CRYPTOGRAPHY_AVAILABLE else '未安装'}\n"
               f"拖拽支持：{'可用' if DND_AVAILABLE else '未安装 tkinterdnd2'}\n"
               f"配置文件：{CONFIG_PATH}")
        ttk.Label(sec3, text=env, style="Muted.TLabel", justify="left").pack(anchor="w")

        # 初始化控件值
        key = cfg.get("algo", core.DEFAULT_ALGO)
        if not core.algorithm_available(key):
            key = core.DEFAULT_ALGO
        self.algo_key = key
        self.kdf_key = cfg.get("kdf", core.KDF_PBKDF2)
        self.set_algo.set(core.ALGORITHMS[self.algo_key])
        self.set_kdf.set(core.KDFS.get(self.kdf_key, core.KDFS[core.KDF_PBKDF2]))
        preset = cfg.get("preset", "标准")
        self.set_preset.set(preset if preset in core.KDF_PRESETS else "标准")
        chunk_label = next((k for k, v in core.CHUNK_SIZES.items()
                            if v == cfg.get("chunk_size", core.DEFAULT_CHUNK)), "1 MiB（推荐）")
        self.set_chunk.set(chunk_label)
        self.set_theme.set(THEMES[self.theme_key]["name"])
        self._update_kdf_hint()

    # ------------------------------------------------------------------
    # 日志页 / 帮助页
    # ------------------------------------------------------------------
    def _build_log_tab(self, parent: ttk.Frame) -> None:
        bar = ttk.Frame(parent)
        bar.pack(fill="x")
        ttk.Label(bar, text="运行日志", style="H2.TLabel").pack(side="left")
        ttk.Button(bar, text="清空日志", command=self._clear_log).pack(side="right")
        ttk.Button(bar, text="导出日志…", command=self._export_log).pack(side="right", padx=6)
        ttk.Button(bar, text="复制全部", command=self._copy_log).pack(side="right", padx=6)
        self.log_text = self._make_text(parent, height=22, role="log", wrap="word")
        self.log_text.pack(fill="both", expand=True, pady=(8, 0))
        self.log_text.configure(state="disabled")

    def _build_about_tab(self, parent: ttk.Frame) -> None:
        sec = self._section(parent, "关于本工具")
        intro = (
            f"{APP_NAME} v{APP_VERSION}\n\n"
            "• 全程本地运行，不上传任何数据，不依赖网络。\n"
            "• 分块流式加解密：内存占用与文件大小无关，可处理超大文件。\n"
            "• 每块独立认证 + 文件尾 EOF 认证，可检测密码错误、内容篡改与文件截断。\n"
            "• 原子写盘：先写 .part 临时文件，全部成功后才替换目标文件，中途失败不留残缺文件。\n"
            "• 密码经 PBKDF2 / scrypt 加盐派生，可选密钥文件形成“密码 + 密钥文件”双因子。\n"
        )
        ttk.Label(sec, text=intro, style="CardMuted.TLabel", justify="left").pack(anchor="w")

        sec2 = self._section(parent, "文件格式（FCRYPT01）")
        fmt = (
            "偏移        内容\n"
            "0           魔数 \"FCRYPT01\"（8 字节）\n"
            "8           头部长度（uint32 大端，4 字节）\n"
            "12          JSON 头部（UTF-8）：算法、KDF 参数、盐、随机数、分块大小、\n"
            "            原始大小/时间、可选加密文件名、密码校验令牌、备注\n"
            "…           数据块 × N：块长度(4) + 密文 + 认证标签(16)\n"
            "末尾        EOF 标记 0xFFFFFFFE(4) + EOF 标签(16，认证明文总长度)\n"
        )
        ttk.Label(sec2, text=fmt, style="CardMuted.TLabel", justify="left",
                  font=(self.f_mono, 9)).pack(anchor="w")

        sec3 = self._section(parent, "算法与安全说明")
        notes = (
            "【默认算法】AES-256-GCM —— 标准 AEAD，经广泛审查、有 CPU 硬件加速。"
            "ChiCha20-Poly1305 可作为无 AES 加速时的替代。\n"
            "【兜底算法】SHAKE-256 自构造流密码 + HMAC-SHA256（Encrypt-then-MAC）："
            "仅在未安装 cryptography 时使用。它是自构造方案，安全性弱于标准 AEAD，不建议长期依赖。\n\n"
            "【密码归一化】派生密钥前统一做 Unicode NFC 归一化，避免「同一密码因输入法不同而打不开」。"
            "旧版本（未归一化）生成的文件在解密时会自动回退兼容。\n"
            "【弱口令检测】熵估算会高估 Password2026! 这类密码；本工具另加常见弱口令字典"
            "（含 leet 变形、键盘序列、中文常见组合）与结构规则，命中时强提示。\n\n"
            "【擦除的局限】覆写擦除只在机械硬盘上有效。SSD/NVMe 有磨损均衡、TRIM 与"
            "写时复制（Btrfs/ZFS/APFS），覆写会写到新块，旧数据仍留在介质里，"
            "主控回收前都可能被恢复。可靠做法是**整盘加密**（BitLocker/LUKS/FileVault）："
            "密钥一销毁，旧数据即不可读。\n"
            "安全提醒：密码一旦遗失无法找回；请务必妥善保存密码与密钥文件。"
        )
        ttk.Label(sec3, text=notes, style="CardMuted.TLabel", justify="left",
                  wraplength=940).pack(anchor="w")

        sec4 = self._section(parent, "自检")
        r = ttk.Frame(sec4)
        r.pack(fill="x")
        ttk.Button(r, text="运行自检（约 3 秒）", style="Accent.TButton",
                   command=self._run_selftest).pack(side="left")
        self.selftest_out = self._make_text(sec4, height=10, wrap="word", readonly=True)
        self.selftest_out.pack(fill="both", expand=True, pady=(8, 0))

    # ------------------------------------------------------------------
    # 配置
    # ------------------------------------------------------------------
    def _load_config(self) -> dict:
        cfg: dict = {}
        try:
            if CONFIG_PATH.exists():
                cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            cfg = {}
        # 一次性迁移：v1 的默认算法是自构造 SHAKE-256，v2 起改为标准 AES-256-GCM。
        # 若配置里仍是旧的默认值，说明用户没有主动选择过，这里顺手升级。
        if int(cfg.get("cfg_ver", 1)) < CONFIG_VERSION:
            if cfg.get("algo") in (None, core.ALGO_STREAM) and core.algorithm_available(core.ALGO_AESGCM):
                cfg["algo"] = core.ALGO_AESGCM
            cfg["cfg_ver"] = CONFIG_VERSION
        return cfg

    def _save_config(self) -> None:
        try:
            CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            CONFIG_PATH.write_text(json.dumps(self.config, ensure_ascii=False, indent=2),
                                   encoding="utf-8")
        except OSError as exc:
            self.log(f"配置保存失败：{exc}", "warn")

    def _collect_config(self) -> None:
        self.config.update({
            "theme": self.theme_key,
            "auto_scroll": bool(self.set_autoscroll.get()),
            "confirm_delete": bool(self.set_confirm_delete.get()),
            "default_out_dir": self.set_out_dir.get(),
        })

    # ------------------------------------------------------------------
    # 主题
    # ------------------------------------------------------------------
    def _toggle_theme(self) -> None:
        self._switch_theme("light" if self.theme_key == "dark" else "dark")

    def _apply_theme_from_settings(self) -> None:
        picked = self.set_theme.get()
        for key, pal in THEMES.items():
            if pal["name"] == picked:
                self._switch_theme(key)
                return

    def _switch_theme(self, key: str) -> None:
        if key not in THEMES or key == self.theme_key:
            return
        self.theme_key = key
        self.C = THEMES[key]
        self._setup_styles()
        self.root.configure(bg=self.C["BG"])
        self._apply_theme_to_texts()
        self.tree.tag_configure("ok", foreground=self.C["OK"])
        self.tree.tag_configure("err", foreground=self.C["ERR"])
        self.tree.tag_configure("skip", foreground=self.C["WARN"])
        self.tree.tag_configure("run", foreground=self.C["ACCENT"])
        self.set_theme.set(THEMES[key]["name"])
        self._rerender_log()
        self._refresh_algo_badge()
        self.log(f"已切换到{THEMES[key]['name']}主题", "info")

    # ------------------------------------------------------------------
    # 选项汇总
    # ------------------------------------------------------------------
    def current_options(self, **overrides) -> core.CryptOptions:
        preset = self.set_preset.get() or "标准"
        params = dict(core.KDF_PRESETS.get(preset, core.KDF_PRESETS["标准"]))
        opts = core.CryptOptions(
            algo=self.algo_key,
            kdf=self.kdf_key,
            kdf_params=params,
            chunk_size=core.CHUNK_SIZES.get(self.set_chunk.get(), core.DEFAULT_CHUNK),
            overwrite=bool(overrides.pop("overwrite", False)),
            delete_source=bool(overrides.pop("delete_source", False)),
            wipe_source=bool(overrides.pop("wipe_source", False)),
        )
        for k, v in overrides.items():
            setattr(opts, k, v)
        return opts

    def _refresh_algo_badge(self) -> None:
        label = core.ALGORITHMS.get(self.algo_key, self.algo_key).split("（")[0]
        self.algo_badge.configure(text=f"{label} · {self.set_preset.get()} · {self.set_chunk.get()}")

    def _update_kdf_hint(self) -> None:
        p = core.KDF_PRESETS.get(self.set_preset.get())
        if not p:
            self.kdf_hint.configure(text="")
            return
        if self.kdf_key == core.KDF_SCRYPT:
            self.kdf_hint.configure(text=f"scrypt n=2^{p['n'].bit_length() - 1}, r={p['r']}, p={p['p']}")
        else:
            self.kdf_hint.configure(text=f"PBKDF2 迭代 {p['iterations']:,} 次")
        self._refresh_algo_badge()

    def _set_algo_from_label(self) -> None:
        label = self.set_algo.get()
        for k, v in core.ALGORITHMS.items():
            if v == label:
                self.algo_key = k
                break
        if not core.algorithm_available(self.algo_key):
            messagebox.showwarning("算法不可用",
                                   "该算法需要 cryptography 库，请先执行：\n\npip install cryptography")
            self.algo_key = core.DEFAULT_ALGO
            self.set_algo.set(core.ALGORITHMS[core.DEFAULT_ALGO])
        self._refresh_algo_badge()

    def _set_kdf_from_label(self) -> None:
        label = self.set_kdf.get()
        for k, v in core.KDFS.items():
            if v == label:
                self.kdf_key = k
                break
        self._update_kdf_hint()

    def _save_settings(self) -> None:
        self._collect_config()
        self.config.update({
            "cfg_ver": CONFIG_VERSION,
            "algo": self.algo_key,
            "kdf": self.kdf_key,
            "preset": self.set_preset.get(),
            "chunk_size": core.CHUNK_SIZES.get(self.set_chunk.get(), core.DEFAULT_CHUNK),
        })
        self._save_config()
        self._refresh_algo_badge()
        self.log("设置已保存", "ok")
        messagebox.showinfo("设置", "设置已保存到：\n" + str(CONFIG_PATH))

    def _reset_settings(self) -> None:
        self.algo_key = core.DEFAULT_ALGO
        self.kdf_key = core.KDF_PBKDF2
        self.set_algo.set(core.ALGORITHMS[self.algo_key])
        self.set_kdf.set(core.KDFS[self.kdf_key])
        self.set_preset.set("标准")
        self.set_chunk.set("1 MiB（推荐）")
        self.set_out_dir.set("")
        self.set_autoscroll.set(True)
        self.set_confirm_delete.set(True)
        self._update_kdf_hint()
        self.log("已恢复默认设置（点击“保存设置”后生效）", "warn")

    # ------------------------------------------------------------------
    # 任务框架
    # ------------------------------------------------------------------
    def start_task(self, title: str, worker_fn, on_done=None) -> bool:
        """在后台线程执行 worker_fn(progress=..., cancel=...)，结果通过队列回主线程。"""
        if self.task is not None:
            messagebox.showwarning("正在执行", "已有任务在运行，请等待完成或点击“取消”。")
            return False
        self.cancel_event = threading.Event()
        self.task = {
            "title": title, "on_done": on_done, "start": time.time(),
            "last_time": time.time(), "last_done": 0, "rate": 0.0, "phase": title,
        }
        self.progress.configure(mode="determinate", value=0)
        self.cancel_btn.configure(state="normal")
        self.status_var.set(title + "…")
        self.detail_var.set("")
        self.log(f"开始：{title}", "info")

        def runner() -> None:
            try:
                result = worker_fn(progress=self._progress_cb(), cancel=self.cancel_event.is_set)
                self.q.put(("done", title, result))
            except core.CancelledError as exc:
                self.q.put(("failed", title, exc, "cancel"))
            except Exception as exc:  # noqa: BLE001
                self.q.put(("failed", title, exc, "error"))

        self.worker = threading.Thread(target=runner, daemon=True)
        self.worker.start()
        return True

    def _progress_cb(self):
        def cb(phase: str, done: int, total: int) -> None:
            self.q.put(("progress", phase, done, total))
        return cb

    def _cancel_task(self) -> None:
        if self.task:
            self.cancel_event.set()
            self.status_var.set("正在取消…")
            self.log("用户请求取消当前任务", "warn")

    def _poll_queue(self) -> None:
        if self._closing:
            return
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "progress":
                    self._on_progress(msg[1], msg[2], msg[3])
                elif kind == "log":
                    self._append_log(msg[1], msg[2])
                elif kind == "item":
                    self._on_item_status(*msg[1:])
                elif kind == "done":
                    self._on_task_done(msg[1], msg[2])
                elif kind == "failed":
                    self._on_task_failed(msg[1], msg[2], msg[3])
        except queue.Empty:
            pass
        except Exception:  # noqa: BLE001
            self.log("界面刷新异常：" + traceback.format_exc(limit=2), "err")
        if not self._closing:
            try:
                self._poll_id = self.root.after(80, self._poll_queue)
            except tk.TclError:
                pass

    def _on_progress(self, phase: str, done: int, total: int) -> None:
        if not self.task:
            return
        self.task["phase"] = phase
        fraction = (done / total) if total > 0 else 0.0
        self.progress.configure(value=max(0, min(1000, int(fraction * 1000))))
        now = time.time()
        dt = now - self.task["last_time"]
        if dt >= 0.4:
            rate = (done - self.task["last_done"]) / dt
            self.task["rate"] = rate if rate > 0 else self.task["rate"]
            self.task["last_time"] = now
            self.task["last_done"] = done
        rate = self.task.get("rate") or 0.0
        parts = [f"{phase} {fraction * 100:5.1f}%"]
        if total > 0:
            parts.append(f"{core.human_size(done)} / {core.human_size(total)}")
        if rate > 0:
            parts.append(f"{core.human_size(rate)}/s")
            if total > done:
                parts.append("剩余 " + core.human_time((total - done) / rate))
        self.status_var.set(" · ".join(parts))

    def _on_task_done(self, title: str, result) -> None:
        on_done = (self.task or {}).get("on_done")
        self.task = None
        self.cancel_btn.configure(state="disabled")
        self.progress.configure(value=1000)
        self.status_var.set(f"{title} 完成")
        self.detail_var.set("")
        self.log(f"完成：{title}", "ok")
        if on_done:
            try:
                on_done(result)
            except Exception:  # noqa: BLE001
                self.log("回调处理失败：" + traceback.format_exc(limit=3), "err")

    def _on_task_failed(self, title: str, exc: BaseException, kind: str) -> None:
        self.task = None
        self.cancel_btn.configure(state="disabled")
        self.progress.configure(value=0)
        if kind == "cancel":
            self.status_var.set(f"{title} 已取消")
            self.log(f"{title} 已由用户取消", "warn")
            return
        self.status_var.set(f"{title} 失败")
        self.log(f"{title} 失败：{type(exc).__name__}: {exc}", "err")
        if isinstance(exc, core.WrongPasswordError):
            messagebox.showerror("解密失败", "密码错误、密钥文件不匹配，或文件已被篡改。")
        elif isinstance(exc, core.FormatError):
            messagebox.showerror("文件格式错误", str(exc))
        elif isinstance(exc, core.UnsupportedAlgorithm):
            messagebox.showerror("算法不可用", str(exc))
        else:
            messagebox.showerror("操作失败", f"{type(exc).__name__}: {exc}")

    # ------------------------------------------------------------------
    # 日志
    # ------------------------------------------------------------------
    def log(self, message: str, level: str = "info") -> None:
        self.q.put(("log", level, message))

    def _append_log(self, level: str, message: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        line = f"[{stamp}] {message}"
        self.log_lines.append(line)
        if len(self.log_lines) > MAX_LOG_LINES:
            del self.log_lines[: len(self.log_lines) - MAX_LOG_LINES]
            self._rerender_log()
            return
        widget = self.log_text
        widget.configure(state="normal")
        widget.insert("end", f"[{stamp}] ", "time")
        widget.insert("end", message + "\n", level if level in ("info", "ok", "warn", "err") else "info")
        if self.set_autoscroll.get():
            widget.see("end")
        widget.configure(state="disabled")

    def _rerender_log(self) -> None:
        widget = self.log_text
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        for line in self.log_lines:
            if len(line) > 11 and line[10] == "]":
                widget.insert("end", line[:11], "time")
                widget.insert("end", line[11:].lstrip() + "\n", "info")
            else:
                widget.insert("end", line + "\n", "info")
        if self.set_autoscroll.get():
            widget.see("end")
        widget.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log_lines.clear()
        self._rerender_log()

    def _copy_log(self) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(self.log_lines))
        self.log("日志已复制到剪贴板", "info")

    def _export_log(self) -> None:
        path = filedialog.asksaveasfilename(
            title="导出日志", defaultextension=".txt",
            initialfile=f"filecrypto-log-{time.strftime('%Y%m%d-%H%M%S')}.txt",
            filetypes=[("文本文件", "*.txt"), ("全部文件", "*.*")])
        if not path:
            return
        try:
            Path(path).write_text("\n".join(self.log_lines), encoding="utf-8")
            self.log(f"日志已导出：{path}", "ok")
        except OSError as exc:
            messagebox.showerror("导出失败", str(exc))

    # ------------------------------------------------------------------
    # 文件页逻辑
    # ------------------------------------------------------------------
    def _register_drop(self, widget: tk.Widget, handler) -> None:
        try:
            widget.drop_target_register(DND_FILES)  # type: ignore[attr-defined]
            widget.dnd_bind("<<Drop>>", handler)    # type: ignore[attr-defined]
        except Exception:
            pass

    def _drop_files_single(self, event) -> None:
        paths = self.root.tk.splitlist(event.data)
        if paths:
            self.file_in.set(paths[0])
            self.log(f"拖入文件：{paths[0]}", "info")
            if len(paths) > 1:
                self._batch_add_paths(paths[1:])
                self.nb.select(self.tabs["batch"])

    def _drop_files_batch(self, event) -> None:
        paths = self.root.tk.splitlist(event.data)
        self._batch_add_paths(paths)

    def _pick_file(self) -> None:
        path = filedialog.askopenfilename(title="选择要加密或解密的文件",
                                          filetypes=[("全部文件", "*.*"),
                                                     ("加密文件", "*" + core.DEFAULT_SUFFIX)])
        if path:
            self.file_in.set(path)

    def _pick_folder_single(self) -> None:
        path = filedialog.askdirectory(title="选择文件夹（将加密该文件夹下所有文件）")
        if path:
            self._batch_add_paths([path])
            self.nb.select(self.tabs["batch"])

    def _pick_out_dir(self) -> None:
        path = filedialog.askdirectory(title="选择输出目录")
        if path:
            self.file_out_dir.set(path)
            self.file_out_same.set(False)
            self._sync_out_dir_state()

    def _pick_set_out_dir(self) -> None:
        path = filedialog.askdirectory(title="选择默认输出目录")
        if path:
            self.set_out_dir.set(path)

    def _pick_batch_dir(self) -> None:
        path = filedialog.askdirectory(title="选择批量输出目录")
        if path:
            self.batch_out_dir.set(path)
            self.batch_out_same.set(False)
            self._sync_batch_dir()

    def _pick_keyfile(self) -> None:
        path = filedialog.askopenfilename(title="选择密钥文件（任意文件）")
        if path:
            self.file_keyfile.set(path)
            self.log(f"已选择密钥文件：{Path(path).name}", "info")

    def _sync_out_dir_state(self) -> None:
        state = "disabled" if self.file_out_same.get() else "normal"
        self.out_dir_entry.configure(state=state)

    def _sync_batch_dir(self) -> None:
        self.batch_dir_entry.configure(state="disabled" if self.batch_out_same.get() else "normal")

    def _toggle_pw(self) -> None:
        self._toggle_entry_show(self.pw_entry)

    @staticmethod
    def _toggle_entry_show(entry: ttk.Entry) -> None:
        """在明文 / 掩码之间切换输入框显示。"""
        entry.configure(show="" if entry.cget("show") else "●")

    def _gen_password_single(self) -> None:
        pwd = core.generate_password(22)
        self.pw_var.set(pwd)
        self.file_confirm.set(pwd)
        self.log("已生成随机密码（请立即保存到密码管理器）", "warn")

    def _update_strength(self) -> None:
        password = self.pw_var.get()
        score, label = core.password_strength(password)
        self.strength_bar.configure(value=score)
        color = self.C["ERR"] if score < 40 else (self.C["WARN"] if score < 70 else self.C["OK"])
        text = f"强度：{label}（{score}/100）"
        warnings = core.password_warnings(password) if password else []
        if warnings:
            text += "　⚠ " + warnings[0]
        self.strength_lbl.configure(text=text, foreground=color)
        if warnings:
            self._strength_tip = Tooltip(self.strength_lbl,
                                        "\n".join("• " + w for w in warnings))

    def _update_file_info(self) -> None:
        path = Path(self.file_in.get()) if self.file_in.get().strip() else None
        if not path or not path.exists() or not path.is_file():
            self.file_info_lbl.configure(text="尚未选择文件", style="Muted.TLabel")
            return
        size = core.human_size(path.stat().st_size)
        kind = "普通文件"
        try:
            with open(path, "rb") as fh:
                if fh.read(8) == core.MAGIC:
                    header = core.read_encrypted_header(path)
                    algo = header.get("algo", "?")
                    created = header.get("created", "")
                    note = header.get("note") or "无"
                    kind = (f"FileCrypto 加密文件 · {algo} · 原名已隐藏"
                            + f" · 创建于 {created} · 备注：{note}")
        except Exception:
            pass
        self.file_info_lbl.configure(text=f"{path.name} · {size} · {kind}", style="CardMuted.TLabel"
                                     if kind != "普通文件" else "Muted.TLabel")

    def _clear_file_tab(self) -> None:
        self.file_in.set("")
        self.pw_var.set("")
        self.file_confirm.set("")
        self.file_note.set("")
        self.file_result.configure(text="")

    def _output_dir_for_file(self) -> Path | None:
        if self.file_out_same.get():
            return None
        text = self.file_out_dir.get().strip()
        return Path(text) if text else None

    def _confirm_password(self, password: str) -> bool:
        if self.file_confirm.get() and self.file_confirm.get() != password:
            messagebox.showerror("密码不一致", "两次输入的密码不相同，请检查后重试。")
            return False
        return True

    def _check_weak_password(self, password: str, where: str = "") -> bool:
        """
        弱口令拦截：命中常见字典时明确劝阻（默认"否"）。
        纯熵估算会把 Password2026! 之类评为"强"，实际几秒就会被字典攻击攻破。
        """
        if not core.is_common_password(password):
            return True
        reasons = "\n".join("· " + w for w in core.password_warnings(password))
        self.log(f"{where}密码命中弱口令字典，已提示用户确认", "warn")
        return messagebox.askyesno(
            "这个密码太弱",
            "该密码命中了常见弱口令字典，字典攻击通常几秒内就能破解。\n\n"
            + reasons
            + "\n\n强烈建议点「随机生成」用高熵密码。\n仍要用它继续吗？",
            icon="warning")

    def _do_encrypt_file(self) -> None:
        src = self.file_in.get().strip()
        if not src or not Path(src).is_file():
            messagebox.showwarning("提示", "请先选择一个存在的文件。")
            return
        password = self.pw_var.get()
        if not password:
            messagebox.showwarning("提示", "请输入密码。")
            return
        if not self._confirm_password(password):
            return
        if not self._check_weak_password(password, "文件加密："):
            return
        if len(password) < 8 and not messagebox.askyesno(
                "密码较短", "密码长度少于 8 位，穷举空间很小。仍要继续吗？"):
            return
        opts = self.current_options(
            keyfile=self.file_keyfile.get().strip() or None,
            store_name=bool(self.file_store_name.get()),
            keep_mtime=bool(self.file_keep_mtime.get()),
            overwrite=bool(self.file_overwrite.get()),
            delete_source=bool(self.file_delete_src.get()),
            wipe_source=bool(self.file_wipe.get()),
            wipe_passes=self.wipe_passes.get() if hasattr(self, "wipe_passes") else 3,
            note=self.file_note.get().strip(),
        )
        out_dir = self._output_dir_for_file()
        src_path = Path(src)
        dst = core.default_output_path(src_path, decrypt=False, out_dir=out_dir)

        def work(progress, cancel):
            return core.encrypt_file(src_path, dst, password, opts, progress, cancel)

        def done(stats: core.CryptStats) -> None:
            self.file_result.configure(
                text=f"✔ 加密完成：{stats.src}  →  {stats.dst}\n"
                     f"   原始大小 {core.human_size(stats.size)} · 耗时 {stats.elapsed:.2f}s · "
                     f"平均 {core.human_size(stats.speed)}/s · 算法 {stats.algo} · KDF {stats.kdf}",
                style="OK.TLabel")
            self.log(f"加密成功：{stats.dst}", "ok")
            if messagebox.askyesno("加密完成", f"文件已加密：\n{stats.dst}\n\n是否打开所在目录？"):
                self._reveal(Path(stats.dst))

        self.start_task(f"加密 {src_path.name}", work, done)

    def _do_decrypt_file(self) -> None:
        src = self.file_in.get().strip()
        if not src or not Path(src).is_file():
            messagebox.showwarning("提示", "请先选择一个存在的文件。")
            return
        password = self.pw_var.get()
        if not password:
            messagebox.showwarning("提示", "请输入密码。")
            return
        opts = self.current_options(
            keyfile=self.file_keyfile.get().strip() or None,
            keep_mtime=bool(self.file_keep_mtime.get()),
            overwrite=bool(self.file_overwrite.get()),
            delete_source=bool(self.file_delete_src.get()),
            wipe_source=bool(self.file_wipe.get()),
        )
        out_dir = self._output_dir_for_file()
        src_path = Path(src)

        def work(progress, cancel):
            return core.decrypt_file(src_path, None, password, opts, out_dir=out_dir,
                                     progress=progress, cancel=cancel)

        def done(stats: core.CryptStats) -> None:
            self.file_result.configure(
                text=f"✔ 解密完成：{stats.src}  →  {stats.dst}\n"
                     f"   明文大小 {core.human_size(stats.size)} · 耗时 {stats.elapsed:.2f}s · "
                     f"平均 {core.human_size(stats.speed)}/s",
                style="OK.TLabel")
            self.log(f"解密成功：{stats.dst}", "ok")
            if messagebox.askyesno("解密完成", f"文件已解密：\n{stats.dst}\n\n是否打开所在目录？"):
                self._reveal(Path(stats.dst))

        self.start_task(f"解密 {src_path.name}", work, done)

    def _inspect_selected_file(self) -> None:
        path = self.file_in.get().strip()
        if not path:
            messagebox.showwarning("提示", "请先选择文件。")
            return
        self.inspect_file.set(path)
        self.nb.select(self.tabs["tools"])
        self._do_inspect()

    # ------------------------------------------------------------------
    # 批量逻辑
    # ------------------------------------------------------------------
    def _batch_add_paths(self, paths: list[str]) -> None:
        files: list[tuple[Path, str]] = []
        for raw in paths:
            p = Path(raw)
            if p.is_dir():
                for child in sorted(p.rglob("*")):
                    if child.is_file():
                        try:
                            rel = str(child.parent.relative_to(p)) if child.parent != p else ""
                        except ValueError:
                            rel = ""
                        files.append((child, rel))
            elif p.is_file():
                files.append((p, ""))
        if not files:
            return
        added = 0
        for path, rel in files:
            key = str(path.resolve())
            if any(item["path"] == key for item in self.batch_items):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            self.batch_items.append({"path": key, "display": str(path), "size": size,
                                     "enc": self._detect_encrypted(path), "rel": rel,
                                     "status": "待处理", "result": "", "tag": ""})
            added += 1
        self.log(f"已加入 {added} 个文件到批量列表（共 {len(self.batch_items)} 个）", "info")
        self._batch_refresh_tree()

    def _detect_encrypted(self, path: Path) -> bool:
        """判断是否为本工具的加密文件：勾选自动识别时读文件头，否则只看扩展名。"""
        name = path.name.lower()
        if not self.batch_auto.get():
            return name.endswith(core.DEFAULT_SUFFIX) or name.endswith(".enc")
        try:
            with open(path, "rb") as fh:
                return fh.read(len(core.MAGIC)) == core.MAGIC
        except OSError:
            return False

    def _batch_add_files(self) -> None:
        paths = filedialog.askopenfilenames(title="选择要处理的文件")
        if paths:
            self._batch_add_paths(list(paths))

    def _batch_add_folder(self) -> None:
        path = filedialog.askdirectory(title="选择文件夹（含子目录）")
        if path:
            self._batch_add_paths([path])

    def _batch_refresh_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for i, item in enumerate(self.batch_items):
            kind = self._item_kind(item)
            self.tree.insert("", "end", iid=str(i),
                             values=(item["display"], core.human_size(item["size"]), kind,
                                     item.get("status", "待处理")),
                             tags=(item.get("tag", ""),) if item.get("tag") else ())
        enc = sum(1 for it in self.batch_items if self._item_kind(it) == "加密文件")
        total = sum(it["size"] for it in self.batch_items)
        self.batch_summary.configure(
            text=f"共 {len(self.batch_items)} 个文件 · 合计 {core.human_size(total)} · "
                 f"其中加密文件 {enc} 个 · 普通文件 {len(self.batch_items) - enc} 个")

    def _item_kind(self, item: dict) -> str:
        return "加密文件" if item.get("enc") else "普通文件"

    def _batch_refresh_types(self) -> None:
        for item in self.batch_items:
            item["enc"] = self._detect_encrypted(Path(item["path"]))
        self.log("批量类型识别：" + ("按文件头自动识别" if self.batch_auto.get() else "按扩展名识别"),
                 "info")
        self._batch_refresh_tree()

    def _batch_remove_selected(self) -> None:
        sel = sorted((int(i) for i in self.tree.selection()), reverse=True)
        for i in sel:
            if 0 <= i < len(self.batch_items):
                del self.batch_items[i]
        self._batch_refresh_tree()

    def _batch_remove_done(self) -> None:
        self.batch_items = [it for it in self.batch_items if it.get("tag") != "ok"]
        self._batch_refresh_tree()

    def _batch_clear(self) -> None:
        self.batch_items.clear()
        self._batch_refresh_tree()

    def _batch_export_report(self) -> None:
        if not self.batch_items:
            messagebox.showinfo("导出报告", "列表为空，没有可导出的内容。")
            return
        path = filedialog.asksaveasfilename(
            title="导出处理报告", defaultextension=".csv",
            initialfile=f"filecrypto-report-{time.strftime('%Y%m%d-%H%M%S')}.csv",
            filetypes=[("CSV 文件", "*.csv"), ("全部文件", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                writer = csv.writer(fh)
                writer.writerow(["序号", "文件", "大小(字节)", "识别类型", "状态", "说明"])
                for i, item in enumerate(self.batch_items, 1):
                    writer.writerow([i, item["display"], item["size"], self._item_kind(item),
                                     item.get("status", ""), item.get("result", "")])
            self.log(f"批量报告已导出：{path}", "ok")
            self._reveal(Path(path))
        except OSError as exc:
            messagebox.showerror("导出失败", str(exc))

    def _on_item_status(self, index: int, status: str, tag: str, result: str = "") -> None:
        if not (0 <= index < len(self.batch_items)):
            return
        item = self.batch_items[index]
        item["status"] = status
        item["tag"] = tag
        item["result"] = result or item.get("result", "")
        iid = str(index)
        if self.tree.exists(iid):
            self.tree.set(iid, "status", status)
            self.tree.item(iid, tags=(tag,) if tag else ())
            if tag == "run":
                self.tree.see(iid)

    def _run_batch(self, mode: str) -> None:
        if not self.batch_items:
            messagebox.showinfo("批量处理", "请先添加文件或文件夹。")
            return
        password = self.batch_pw_var.get()
        if not password:
            messagebox.showwarning("提示", "请输入统一密码。")
            return
        if self.batch_auto.get():
            for item in self.batch_items:
                item["enc"] = self._detect_encrypted(Path(item["path"]))
        if mode != "decrypt" and not self._check_weak_password(password, "批量加密："):
            return
        opts_base = self.current_options(
            keep_mtime=bool(self.file_keep_mtime.get()),
            store_name=bool(self.file_store_name.get()),
            delete_source=bool(self.batch_delete_src.get()),
            wipe_source=bool(self.file_wipe.get()),
            overwrite=(self.batch_conflict.get() == "overwrite"),
        )
        out_dir = None if self.batch_out_same.get() else (
            Path(self.batch_out_dir.get()) if self.batch_out_dir.get().strip() else None)
        mirror = bool(self.batch_mirror.get())
        conflict = self.batch_conflict.get()
        keep_going = bool(self.batch_keep_going.get())
        suffix = self.batch_suffix.get().strip() or core.DEFAULT_SUFFIX
        items = [dict(it) for it in self.batch_items]
        total_bytes = sum(it["size"] for it in items) or 1

        def work(progress, cancel):
            results = []
            done_bytes = 0
            started = time.time()
            for idx, item in enumerate(items):
                if cancel():
                    raise core.CancelledError("批量任务已取消")
                src = Path(item["path"])
                is_enc = bool(item["enc"])
                action = "decrypt" if is_enc else "encrypt"
                if mode != "auto" and mode != action:
                    self.q.put(("item", idx, "跳过", "skip", "与所选操作不符"))
                    results.append(("skip", str(src), "", 0, "与所选操作不符"))
                    done_bytes += item["size"]
                    progress("批量处理", done_bytes, total_bytes)
                    continue
                self.q.put(("item", idx, "处理中…", "run", ""))
                try:
                    rel_dir = item["rel"] if mirror and out_dir else ""
                    base_dir = (out_dir / rel_dir) if out_dir else None
                    opts = dataclasses.replace(opts_base, overwrite=(conflict == "overwrite"))

                    def sub_progress(phase, done, total, _idx=idx, _base=done_bytes, _size=item["size"]):
                        progress(phase, min(_base + done, total_bytes), total_bytes)

                    if action == "encrypt":
                        target_dir = base_dir if base_dir is not None else src.parent
                        target_dir.mkdir(parents=True, exist_ok=True)
                        dst = target_dir / (src.name + suffix)
                        if conflict == "skip" and dst.exists():
                            self.q.put(("item", idx, "跳过", "skip", "目标已存在"))
                            results.append(("skip", str(src), str(dst), item["size"], "目标已存在"))
                        else:
                            stats = core.encrypt_file(src, dst, password, opts,
                                                      sub_progress, cancel)
                            self.q.put(("item", idx, "已加密", "ok", str(stats.dst)))
                            results.append(("encrypt", str(src), str(stats.dst), item["size"], ""))
                    else:
                        target_dir = base_dir if base_dir is not None else None
                        if target_dir is not None:
                            target_dir.mkdir(parents=True, exist_ok=True)
                        stats = core.decrypt_file(src, None, password, opts, out_dir=target_dir,
                                                  progress=sub_progress, cancel=cancel)
                        self.q.put(("item", idx, "已解密", "ok", str(stats.dst)))
                        results.append(("decrypt", str(src), str(stats.dst), item["size"], ""))
                except core.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    msg = f"{type(exc).__name__}: {exc}"
                    self.q.put(("item", idx, "失败", "err", msg))
                    results.append(("error", str(src), "", item["size"], msg))
                    if not keep_going:
                        break
                done_bytes += item["size"]
                progress("批量处理", min(done_bytes, total_bytes), total_bytes)
            return {"results": results, "elapsed": time.time() - started}

        def done(payload) -> None:
            results = payload["results"]
            ok = sum(1 for r in results if r[0] in ("encrypt", "decrypt"))
            skip = sum(1 for r in results if r[0] == "skip")
            err = sum(1 for r in results if r[0] == "error")
            total_size = sum(r[3] for r in results if r[0] in ("encrypt", "decrypt"))
            self.log(f"批量完成：成功 {ok} · 跳过 {skip} · 失败 {err} · "
                     f"共处理 {core.human_size(total_size)} · 耗时 {payload['elapsed']:.2f}s",
                     "ok" if err == 0 else "warn")
            self._batch_refresh_tree()
            messagebox.showinfo("批量处理完成",
                                f"成功：{ok}\n跳过：{skip}\n失败：{err}\n"
                                f"处理数据量：{core.human_size(total_size)}\n"
                                f"耗时：{payload['elapsed']:.2f} 秒")

        self.start_task(f"批量处理 {len(items)} 个文件", work, done)

    # ------------------------------------------------------------------
    # 文本加解密
    # ------------------------------------------------------------------
    def _get_text(self, widget: tk.Text) -> str:
        return widget.get("1.0", "end-1c")

    def _set_text(self, widget: tk.Text, content: str) -> None:
        state = widget.cget("state")
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state=state)

    def _do_text_encrypt(self) -> None:
        text = self._get_text(self.text_in)
        password = self.text_pw_var.get()
        if not text.strip():
            messagebox.showwarning("提示", "请输入要加密的文本。")
            return
        if not password:
            messagebox.showwarning("提示", "请输入密码。")
            return
        if not self._check_weak_password(password, "文本加密："):
            return
        try:
            opts = self.current_options()
            armored = core.seal_text(text, password, opts)
            self._set_text(self.text_out, armored)
            self.log(f"文本已加密（{len(text)} 字符 → {len(armored)} 字符）", "ok")
        except Exception as exc:  # noqa: BLE001
            self.log(f"文本加密失败：{exc}", "err")
            messagebox.showerror("加密失败", str(exc))

    def _do_text_decrypt(self) -> None:
        blob = self._get_text(self.text_out).strip() or self._get_text(self.text_in).strip()
        password = self.text_pw_var.get()
        if not blob:
            messagebox.showwarning("提示", "请把密文粘贴到右侧输入框。")
            return
        if not password:
            messagebox.showwarning("提示", "请输入密码。")
            return
        try:
            opts = self.current_options()
            text = core.open_text(blob, password, opts)
            self._set_text(self.text_in, text)
            self.log("文本解密成功", "ok")
        except core.WrongPasswordError:
            messagebox.showerror("解密失败", "密码错误或密文已被篡改。")
            self.log("文本解密失败：密码错误或密文被篡改", "err")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("解密失败", str(exc))
            self.log(f"文本解密失败：{exc}", "err")

    def _copy_text_out(self) -> None:
        content = self._get_text(self.text_out)
        if not content:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.log("已复制输出内容到剪贴板", "info")

    def _swap_text(self) -> None:
        content = self._get_text(self.text_out)
        self._set_text(self.text_in, content)
        self._set_text(self.text_out, "")
        self.log("已用输出内容替换输入内容", "info")

    # ------------------------------------------------------------------
    # 工具箱
    # ------------------------------------------------------------------
    def _pick_hash_file(self) -> None:
        path = filedialog.askopenfilename(title="选择要计算摘要的文件")
        if path:
            self.hash_file.set(path)

    def _do_hash(self) -> None:
        path = self.hash_file.get().strip()
        if not path or not Path(path).is_file():
            messagebox.showwarning("提示", "请先选择文件。")
            return
        algos = [a for a, v in self.hash_algos.items() if v.get()]
        if not algos:
            messagebox.showwarning("提示", "请至少勾选一种算法。")
            return
        size = Path(path).stat().st_size

        def work(progress, cancel):
            lines = []
            for algo in algos:
                digest = core.file_hash(path, algo, progress, cancel)
                lines.append(f"{algo.upper():<8} {digest}")
            return lines

        def done(lines: list) -> None:
            text = "\n".join(lines) + f"\n\n文件：{path}\n大小：{core.human_size(size)} 字节"
            self.hash_result_text = "\n".join(lines)
            self._set_text(self.hash_out, text)
            self.log(f"摘要计算完成：{Path(path).name}", "ok")

        self.start_task(f"计算摘要 {Path(path).name}", work, done)

    def _copy_hash(self) -> None:
        if not self.hash_result_text:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self.hash_result_text)
        self.log("摘要已复制到剪贴板", "info")

    def _do_generate(self) -> None:
        try:
            opts = self.gen_opts
            self.generated = [
                core.generate_password(self.gen_len.get(),
                                       opts["小写"].get(), opts["大写"].get(),
                                       opts["数字"].get(), opts["符号"].get(),
                                       self.gen_ambig.get())
                for _ in range(max(1, self.gen_count.get()))
            ]
        except core.CryptError as exc:
            messagebox.showerror("生成失败", str(exc))
            return
        self._set_text(self.gen_out, "\n".join(self.generated))
        self.log(f"已生成 {len(self.generated)} 个随机密码", "ok")

    def _copy_generated(self) -> None:
        if not self.generated:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(self.generated))
        self.log("已复制生成的密码", "info")

    def _pick_wipe_file(self) -> None:
        path = filedialog.askopenfilename(title="选择要安全擦除的文件")
        if path:
            self.wipe_path.set(path)

    def _pick_wipe_dir(self) -> None:
        path = filedialog.askdirectory(title="选择要安全擦除的文件夹（含子文件）")
        if path:
            self.wipe_path.set(path)

    def _do_wipe(self) -> None:
        raw = self.wipe_path.get().strip()
        if not raw:
            messagebox.showwarning("提示", "请选择要擦除的文件或文件夹。")
            return
        target = Path(raw)
        if not target.exists():
            messagebox.showerror("错误", "目标不存在。")
            return
        files = [target] if target.is_file() else [p for p in target.rglob("*") if p.is_file()]
        total_size = sum(p.stat().st_size for p in files)
        if self.set_confirm_delete.get() and not messagebox.askyesno(
                "确认安全擦除",
                f"即将覆写 {self.wipe_passes.get()} 次（最后一遍写全零）并删除：\n\n{target}\n"
                f"包含 {len(files)} 个文件，共 {core.human_size(total_size)}。\n\n此操作不可恢复，是否继续？"):
            return
        passes = self.wipe_passes.get()

        def work(progress, cancel):
            done_size = 0
            for p in files:
                size_p = p.stat().st_size if p.exists() else 0
                core.secure_delete(p, passes, progress, cancel)
                done_size += size_p
                progress("安全擦除", min(done_size, total_size or 1), total_size or 1)
            if target.is_dir():
                for p in sorted(target.rglob("*"), reverse=True):
                    try:
                        p.rmdir()
                    except OSError:
                        pass
                try:
                    target.rmdir()
                except OSError:
                    pass
            return len(files)

        self.start_task(f"安全擦除 {len(files)} 个文件", work,
                        lambda n: self.log(f"安全擦除完成，共 {n} 个文件", "ok"))

    def _pick_inspect_file(self) -> None:
        path = filedialog.askopenfilename(title="选择加密文件",
                                          filetypes=[("加密文件", "*" + core.DEFAULT_SUFFIX),
                                                     ("全部文件", "*.*")])
        if path:
            self.inspect_file.set(path)

    def _do_inspect(self) -> None:
        path = self.inspect_file.get().strip()
        if not path or not Path(path).is_file():
            messagebox.showwarning("提示", "请先选择文件。")
            return
        try:
            header = core.read_encrypted_header(path)
        except core.CryptError as exc:
            self._set_text(self.inspect_out, f"读取失败：{exc}")
            return
        info = {
            "文件名": Path(path).name,
            "文件大小": core.human_size(Path(path).stat().st_size),
            "格式版本": header.get("v"),
            "加密算法": header.get("algo"),
            "密钥派生": f"{header.get('kdf')} {header.get('kdf_params')}",
            "分块大小": core.human_size(int(header.get("chunk_size", 0))),
            "原始大小": core.human_size(int(header.get("size", 0))),
            "原始修改时间": time.strftime("%Y-%m-%d %H:%M:%S",
                                          time.localtime(header.get("mtime", 0))),
            "加密时间": header.get("created"),
            "使用密钥文件": "是" if header.get("keyfile") else "否",
            "原始文件名": "已加密保存（需密码才能还原）" if header.get("name_ct") else "未记录",
            "备注": header.get("note") or "（无）",
            "生成工具": header.get("tool"),
        }
        text = "\n".join(f"{k:<12}{v}" for k, v in info.items())
        self._set_text(self.inspect_out, text)
        self.log(f"已读取加密文件信息：{Path(path).name}", "info")

    # ------------------------------------------------------------------
    # 自检
    # ------------------------------------------------------------------
    def _run_selftest(self) -> None:
        def work(progress, cancel):
            progress("自检", 0, 1)
            ok, results = core.self_test(verbose=False)
            progress("自检", 1, 1)
            return ok, results

        def done(payload) -> None:
            ok, results = payload
            lines = [("✔ " if r[1] else "✘ ") + r[0] + (f"   ← {r[2]}" if r[2] else "")
                     for r in results]
            lines.append("")
            lines.append("自检结果：" + ("全部通过" if ok else "存在失败项"))
            self._set_text(self.selftest_out, "\n".join(lines))
            self.log("自检" + ("全部通过" if ok else "存在失败项"),
                     "ok" if ok else "err")

        self.start_task("运行自检", work, done)

    # ------------------------------------------------------------------
    # 杂项
    # ------------------------------------------------------------------
    def _reveal(self, path: Path) -> None:
        """在资源管理器中定位文件（跨平台尽力而为）。"""
        try:
            if sys.platform.startswith("win"):
                if path.is_dir():
                    os.startfile(str(path))  # type: ignore[attr-defined]
                else:
                    os.system(f'explorer /select,"{path}"')
            elif sys.platform == "darwin":
                os.system(f'open -R "{path}"')
            else:
                os.system(f'xdg-open "{path.parent}"')
        except Exception as exc:  # noqa: BLE001
            self.log(f"无法打开目录：{exc}", "warn")

    def _open_out_dir(self) -> None:
        target = self.file_out_dir.get().strip()
        if target and Path(target).is_dir():
            self._reveal(Path(target))
        else:
            messagebox.showinfo("提示", "输出目录尚未设置或不存在。")

    def _on_close(self) -> None:
        if self.task is not None:
            if not messagebox.askyesno("任务进行中", "仍有任务在执行，确定要退出吗？\n"
                                                     "（未完成的加密会留下 .part 临时文件）"):
                return
            self.cancel_event.set()
        self._closing = True
        if self._poll_id is not None:
            try:
                self.root.after_cancel(self._poll_id)
            except tk.TclError:
                pass
            self._poll_id = None
        try:
            # 仅在窗口正常显示且尺寸合理时记录几何信息（避免隐藏/最小化状态污染配置）
            geo = self.root.geometry()
            size = geo.split("+")[0]
            w, _, h = size.partition("x")
            if self.root.winfo_viewable() and int(w) >= 600 and int(h) >= 400:
                self.config["geometry"] = geo
            self._collect_config()
            self._save_config()
        except Exception:
            pass
        self.root.destroy()


# --------------------------------------------------------------------------
# 入口
# --------------------------------------------------------------------------


def build_root() -> tk.Tk:
    if DND_AVAILABLE:
        try:
            return TkinterDnD.Tk()  # type: ignore[attr-defined]
        except Exception:
            pass
    return tk.Tk()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="FileCrypto 文件加解密工具（图形界面）")
    parser.add_argument("--theme", choices=list(THEMES), help="启动主题：dark / light")
    parser.add_argument("--selftest", action="store_true", help="只运行加密引擎自检后退出")
    parser.add_argument("--probe", nargs="?", const="-",
                        help="输出运行环境与默认算法的 JSON（供打包/运维验证）")
    parser.add_argument("--cli", nargs=argparse.REMAINDER, help="转发参数给命令行模式")
    args = parser.parse_args(argv)

    if args.probe is not None:
        import platform

        info = {
            "app_version": APP_VERSION,
            "python": sys.version.split()[0],
            "tk": str(tk.TkVersion),
            "frozen": bool(getattr(sys, "frozen", False)),
            "platform": platform.platform(),
            "cryptography_available": core.CRYPTOGRAPHY_AVAILABLE,
            "cryptography_version": core.CRYPTOGRAPHY_VERSION,
            "default_algo": core.DEFAULT_ALGO,
            "algorithms": {k: core.algorithm_available(k) for k in core.ALGORITHMS},
            "weak_password_dict_size": len(core.WEAK_PASSWORDS),
        }
        text = json.dumps(info, ensure_ascii=False, indent=2)
        if args.probe and args.probe != "-":
            Path(args.probe).write_text(text, encoding="utf-8")
        else:
            print(text)
        return 0

    if args.selftest:
        ok, _ = core.self_test()
        return 0 if ok else 1
    if args.cli:
        return core._cli(args.cli)

    root = build_root()
    app = FileCryptoApp(root, theme=args.theme or "")
    if app.config.get("window_maximized"):
        try:
            root.state("zoomed")
        except tk.TclError:
            pass
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
