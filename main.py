"""
WindRelay Protection Scanner
Android Permission & Data Risk Analyzer
Educational Cyber Security Project

Run:  python main.py
Needs: Python 3.8+ (tkinter is included with the standard installer)
"""

import tkinter as tk
from tkinter import ttk, messagebox

# ----------------------------------------------------------------------
# Permission database: permission -> (possible data exposed, risk weight)
# ----------------------------------------------------------------------
PERMISSIONS = {
    "CAMERA": ("Photos, video, surroundings", 6),
    "RECORD_AUDIO": ("Voice, conversations, ambient sound", 8),
    "ACCESS_FINE_LOCATION": ("Exact GPS location, movement history", 9),
    "ACCESS_COARSE_LOCATION": ("Approximate location", 5),
    "READ_CONTACTS": ("Names, phone numbers, emails", 7),
    "READ_SMS": ("Messages, OTP codes", 10),
    "SEND_SMS": ("Premium SMS fraud, spam", 8),
    "READ_CALL_LOG": ("Call history, who you talk to", 7),
    "READ_EXTERNAL_STORAGE": ("Files, photos, documents", 6),
    "WRITE_EXTERNAL_STORAGE": ("Modify or delete files", 6),
    "READ_PHONE_STATE": ("Device ID, phone number", 5),
    "READ_CALENDAR": ("Events, meetings, schedule", 4),
    "BODY_SENSORS": ("Health and activity data", 5),
    "SYSTEM_ALERT_WINDOW": ("Draw over other apps (overlay attacks)", 9),
    "BIND_ACCESSIBILITY_SERVICE": ("Screen content, keystrokes", 10),
    "INTERNET": ("Send data to remote servers", 2),
    "VIBRATE": ("Vibration control", 1),
    "WAKE_LOCK": ("Keep device awake", 1),
    "POST_NOTIFICATIONS": ("Show notifications", 1),
}

# ----------------------------------------------------------------------
# Sample applications (sample data for educational purposes)
# ----------------------------------------------------------------------
APPS = {
    "Calculator": ["VIBRATE"],
    "Chrome": ["INTERNET", "ACCESS_COARSE_LOCATION", "CAMERA", "RECORD_AUDIO",
               "READ_EXTERNAL_STORAGE", "POST_NOTIFICATIONS"],
    "Facebook": ["INTERNET", "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION",
                 "READ_CONTACTS", "READ_EXTERNAL_STORAGE", "READ_CALENDAR",
                 "READ_PHONE_STATE", "POST_NOTIFICATIONS"],
    "Fake Banking App": ["INTERNET", "READ_SMS", "SEND_SMS", "READ_CONTACTS",
                         "READ_CALL_LOG", "SYSTEM_ALERT_WINDOW",
                         "BIND_ACCESSIBILITY_SERVICE", "READ_PHONE_STATE",
                         "ACCESS_FINE_LOCATION"],
    "Google Maps": ["INTERNET", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
                    "POST_NOTIFICATIONS"],
    "Instagram": ["INTERNET", "CAMERA", "RECORD_AUDIO", "ACCESS_COARSE_LOCATION",
                  "READ_CONTACTS", "READ_EXTERNAL_STORAGE", "POST_NOTIFICATIONS"],
    "Music Player": ["INTERNET", "READ_EXTERNAL_STORAGE", "WAKE_LOCK", "VIBRATE"],
    "Notes": ["READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"],
    "Telegram": ["INTERNET", "CAMERA", "RECORD_AUDIO", "READ_CONTACTS",
                 "READ_EXTERNAL_STORAGE", "ACCESS_FINE_LOCATION",
                 "READ_PHONE_STATE", "POST_NOTIFICATIONS"],
    "WhatsApp": ["INTERNET", "CAMERA", "RECORD_AUDIO", "READ_CONTACTS",
                 "READ_EXTERNAL_STORAGE", "ACCESS_FINE_LOCATION",
                 "READ_CALL_LOG", "READ_PHONE_STATE", "POST_NOTIFICATIONS"],
}

# Weight total that maps to a 100% score (higher sums are capped at 100%)
MAX_REFERENCE_SCORE = 60

# Colors
DARK = "#1e1e1e"
BG = "#f0f0f0"
BLUE = "#2b8be0"
RED = "#d32f2f"


def risk_level(score):
    if score < 25:
        return "Low", "#2e7d32"
    if score < 50:
        return "Medium", "#f9a825"
    if score < 75:
        return "High", "#ef6c00"
    return "Critical", RED


class WindRelayApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("WindRelay Protection Scanner")
        self.geometry("1000x680")
        self.minsize(900, 600)
        self.configure(bg=BG)

        self.selected_app = None
        self._build_header()
        self._build_search()
        self._build_body()
        self._build_footer()
        self._populate_apps()

    # ------------------------------------------------------------ UI
    def _build_header(self):
        header = tk.Frame(self, bg=DARK)
        header.pack(fill="x")
        tk.Label(header, text="WindRelay Protection Scanner", bg=DARK, fg="white",
                 font=("Arial", 22, "bold")).pack(pady=(12, 0))
        tk.Label(header, text="Android Permission & Data Risk Analyzer", bg=DARK,
                 fg="white", font=("Arial", 10)).pack(pady=(0, 10))

    def _build_search(self):
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=20, pady=10)
        tk.Label(bar, text="Search Application:", bg=BG,
                 font=("Arial", 12, "bold")).pack(side="left")

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._populate_apps())
        ttk.Entry(bar, textvariable=self.search_var, width=45).pack(
            side="left", padx=10)
        ttk.Button(bar, text="Clear",
                   command=lambda: self.search_var.set("")).pack(side="left")

    def _build_body(self):
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        # Left: application list
        left = tk.LabelFrame(body, bg=BG)
        left.grid(row=0, column=0, sticky="ns", padx=(0, 10))
        tk.Label(left, text="Applications", bg=BG,
                 font=("Arial", 14, "bold")).pack(pady=10)
        self.app_list = tk.Listbox(left, width=28, font=("Arial", 12),
                                   bd=0, highlightthickness=0, bg=BG,
                                   activestyle="none",
                                   selectbackground=BLUE, selectforeground="white")
        self.app_list.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.app_list.bind("<<ListboxSelect>>", self._on_select)

        # Right: details
        right = tk.LabelFrame(body, bg=BG)
        right.grid(row=0, column=1, sticky="nsew")
        self.selected_label = tk.Label(right, text="Selected Application: None",
                                       bg=BG, font=("Arial", 13, "bold"))
        self.selected_label.pack(pady=10)

        cols = ("permission", "data", "weight")
        table_frame = tk.Frame(right, bg=BG)
        table_frame.pack(fill="both", expand=True, padx=15)
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings")
        for col, text, width in (("permission", "Permission", 200),
                                 ("data", "Possible Data", 300),
                                 ("weight", "Risk Weight", 90)):
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width,
                             anchor="center" if col == "weight" else "w")
        scroll = ttk.Scrollbar(table_frame, orient="vertical",
                               command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        # Score row
        score_row = tk.Frame(right, bg=BG)
        score_row.pack(fill="x", padx=15, pady=10)
        tk.Label(score_row, text="Risk Score:", bg=BG,
                 font=("Arial", 12, "bold")).pack(side="left")
        self.score_label = tk.Label(score_row, text="0%", bg=BG, fg=BLUE,
                                    font=("Arial", 14, "bold"))
        self.score_label.pack(side="left", padx=(8, 40))
        tk.Label(score_row, text="Risk Level:", bg=BG,
                 font=("Arial", 12, "bold")).pack(side="left")
        self.level_label = tk.Label(score_row, text="Not Analyzed", bg=BG,
                                    fg=RED, font=("Arial", 14, "bold"))
        self.level_label.pack(side="left", padx=8)

        self.progress = ttk.Progressbar(right, maximum=100, length=300)
        self.progress.pack(pady=(0, 10))

        tk.Button(right, text="ANALYZE APP", bg=BLUE, fg="white",
                  font=("Arial", 11, "bold"), relief="flat", padx=20, pady=8,
                  command=self.analyze).pack(pady=(0, 15))

    def _build_footer(self):
        tk.Label(self, text="Educational Cyber Security Project | "
                            "WindRelay Protection Scanner",
                 bg=BG, fg="gray", font=("Arial", 8)).pack(pady=(0, 6))

    # ------------------------------------------------------- Logic
    def _populate_apps(self):
        query = self.search_var.get().strip().lower()
        self.app_list.delete(0, tk.END)
        for name in sorted(APPS):
            if query in name.lower():
                self.app_list.insert(tk.END, name)

    def _on_select(self, _event=None):
        sel = self.app_list.curselection()
        if not sel:
            return
        self.selected_app = self.app_list.get(sel[0])
        self.selected_label.config(
            text=f"Selected Application: {self.selected_app}")
        self._reset_results()

    def _reset_results(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.score_label.config(text="0%")
        self.level_label.config(text="Not Analyzed", fg=RED)
        self.progress["value"] = 0

    def analyze(self):
        if not self.selected_app:
            messagebox.showwarning("No app selected",
                                   "Please select an application first.")
            return

        self._reset_results()
        perms = APPS[self.selected_app]
        total = 0
        # Show highest-risk permissions first
        for perm in sorted(perms, key=lambda p: PERMISSIONS[p][1], reverse=True):
            data, weight = PERMISSIONS[perm]
            total += weight
            self.tree.insert("", tk.END, values=(perm, data, weight))

        score = min(100, round(total / MAX_REFERENCE_SCORE * 100))
        level, color = risk_level(score)
        self.score_label.config(text=f"{score}%")
        self.level_label.config(text=level, fg=color)
        self.progress["value"] = score


if __name__ == "__main__":
    WindRelayApp().mainloop()
