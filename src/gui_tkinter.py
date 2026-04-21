"""
Password Strength Checker — Modern UI (Cybersecurity Edition)
- 100% local; no password ever leaves your machine.
- Built with Python + Tkinter (standard library only).
"""
import tkinter as tk
from tkinter import ttk, font as tkfont
from password_strength import evaluate_password, load_common_passwords

COMMON = load_common_passwords()

# ---------- Theme ----------
BG        = "#0f172a"   # slate-900
CARD      = "#1e293b"   # slate-800
CARD_2    = "#334155"   # slate-700
TEXT      = "#e2e8f0"   # slate-200
MUTED     = "#94a3b8"   # slate-400
ACCENT    = "#38bdf8"   # sky-400
OK        = "#22c55e"   # green-500
WARN      = "#f59e0b"   # amber-500
BAD       = "#ef4444"   # red-500

LABEL_COLORS = {
    "Very Weak":   "#ef4444",
    "Weak":        "#f97316",
    "Medium":      "#f59e0b",
    "Strong":      "#22c55e",
    "Very Strong": "#10b981",
}

CHECK_LABELS = {
    "length>=8":  "At least 8 characters",
    "has_lower":  "Lowercase letter (a-z)",
    "has_upper":  "Uppercase letter (A-Z)",
    "has_digit":  "Number (0-9)",
    "has_symbol": "Symbol (!@#$...)",
    "length>=12": "12+ characters (recommended)",
}


class PasswordCheckerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("SecurePass - Password Strength Analyzer")
        root.geometry("760x640")
        root.configure(bg=BG)
        root.minsize(720, 620)

        # Fonts
        self.f_title    = tkfont.Font(family="Segoe UI", size=20, weight="bold")
        self.f_sub      = tkfont.Font(family="Segoe UI", size=10)
        self.f_label    = tkfont.Font(family="Segoe UI", size=10, weight="bold")
        self.f_body     = tkfont.Font(family="Segoe UI", size=10)
        self.f_meter    = tkfont.Font(family="Segoe UI", size=14, weight="bold")
        self.f_metric   = tkfont.Font(family="Segoe UI", size=13, weight="bold")
        self.f_metric_l = tkfont.Font(family="Segoe UI", size=9)
        self.f_entry    = tkfont.Font(family="Consolas",  size=13)

        self._target_percent = 0
        self._current_percent = 0
        self._show_password = False

        self._build_ui()
        self._update()

    def _build_ui(self):
        # Header
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=28, pady=(22, 6))

        tk.Label(header, text="SecurePass",
                 font=self.f_title, fg=TEXT, bg=BG).pack(anchor="w")
        tk.Label(header,
                 text="Analyze password strength locally - Nothing is stored or sent",
                 font=self.f_sub, fg=MUTED, bg=BG).pack(anchor="w", pady=(2, 0))

        # Input card
        input_card = tk.Frame(self.root, bg=CARD, highlightthickness=0)
        input_card.pack(fill="x", padx=28, pady=(18, 10))

        tk.Label(input_card, text="ENTER A PASSWORD",
                 font=self.f_label, fg=MUTED, bg=CARD).pack(anchor="w", padx=18, pady=(14, 6))

        entry_row = tk.Frame(input_card, bg=CARD)
        entry_row.pack(fill="x", padx=18, pady=(0, 14))

        self.entry = tk.Entry(entry_row, show="*", font=self.f_entry,
                              bg=CARD_2, fg=TEXT, insertbackground=TEXT,
                              relief="flat", bd=0)
        self.entry.pack(side="left", fill="x", expand=True, ipady=10, padx=(0, 10))
        self.entry.bind("<KeyRelease>", lambda e: self._update())

        self.toggle_btn = tk.Button(entry_row, text="Show", width=7,
                                    font=self.f_label, bg=CARD_2, fg=TEXT,
                                    activebackground=ACCENT, activeforeground=BG,
                                    relief="flat", bd=0, cursor="hand2",
                                    command=self._toggle_show)
        self.toggle_btn.pack(side="right", ipady=7)

        # Strength meter card
        meter_card = tk.Frame(self.root, bg=CARD)
        meter_card.pack(fill="x", padx=28, pady=8)

        meter_head = tk.Frame(meter_card, bg=CARD)
        meter_head.pack(fill="x", padx=18, pady=(14, 6))
        tk.Label(meter_head, text="STRENGTH",
                 font=self.f_label, fg=MUTED, bg=CARD).pack(side="left")
        self.strength_lbl = tk.Label(meter_head, text="-",
                                     font=self.f_meter, fg=TEXT, bg=CARD)
        self.strength_lbl.pack(side="right")

        self.meter_canvas = tk.Canvas(meter_card, height=14, bg=CARD_2,
                                      highlightthickness=0, bd=0)
        self.meter_canvas.pack(fill="x", padx=18, pady=(0, 14))
        self.meter_canvas.bind("<Configure>", lambda e: self._draw_meter())

        # Metrics row
        metrics = tk.Frame(self.root, bg=BG)
        metrics.pack(fill="x", padx=28, pady=8)

        self.entropy_val, entropy_card = self._metric_card(metrics, "ENTROPY", "0 bits")
        entropy_card.pack(side="left", fill="both", expand=True, padx=(0, 6))

        self.crack_val, crack_card = self._metric_card(metrics, "EST. CRACK TIME", "-")
        crack_card.pack(side="left", fill="both", expand=True, padx=(6, 0))

        # Two-column: checklist + feedback
        two_col = tk.Frame(self.root, bg=BG)
        two_col.pack(fill="both", expand=True, padx=28, pady=(8, 6))

        check_card = tk.Frame(two_col, bg=CARD)
        check_card.pack(side="left", fill="both", expand=True, padx=(0, 6))
        tk.Label(check_card, text="REQUIREMENTS",
                 font=self.f_label, fg=MUTED, bg=CARD).pack(anchor="w", padx=18, pady=(14, 8))

        self.check_labels = {}
        for key, text in CHECK_LABELS.items():
            lbl = tk.Label(check_card, text=f"O   {text}",
                           font=self.f_body, fg=MUTED, bg=CARD, anchor="w")
            lbl.pack(fill="x", padx=18, pady=3)
            self.check_labels[key] = lbl
        tk.Frame(check_card, bg=CARD, height=10).pack()

        fb_card = tk.Frame(two_col, bg=CARD)
        fb_card.pack(side="left", fill="both", expand=True, padx=(6, 0))
        tk.Label(fb_card, text="FEEDBACK",
                 font=self.f_label, fg=MUTED, bg=CARD).pack(anchor="w", padx=18, pady=(14, 8))

        self.tips_frame = tk.Frame(fb_card, bg=CARD)
        self.tips_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        tk.Label(self.root,
                 text="Runs 100% offline - No data stored - No network calls",
                 font=self.f_sub, fg=MUTED, bg=BG).pack(pady=(4, 14))

    def _metric_card(self, parent, title, value):
        frame = tk.Frame(parent, bg=CARD)
        tk.Label(frame, text=title, font=self.f_metric_l,
                 fg=MUTED, bg=CARD).pack(anchor="w", padx=16, pady=(14, 4))
        val = tk.Label(frame, text=value, font=self.f_metric,
                       fg=TEXT, bg=CARD, anchor="w")
        val.pack(anchor="w", padx=16, pady=(0, 14))
        return val, frame

    def _draw_meter(self):
        c = self.meter_canvas
        c.delete("all")
        w = c.winfo_width()
        h = c.winfo_height()
        if w <= 1:
            return
        c.create_rectangle(0, 0, w, h, fill=CARD_2, outline="")
        fill_w = int(w * (self._current_percent / 100))
        if fill_w > 0:
            color = self._color_for_percent(self._current_percent)
            c.create_rectangle(0, 0, fill_w, h, fill=color, outline="")

    def _color_for_percent(self, p):
        if p < 30:  return BAD
        if p < 55:  return "#f97316"
        if p < 75:  return WARN
        if p < 90:  return OK
        return "#10b981"

    def _animate_meter(self):
        if abs(self._current_percent - self._target_percent) < 1:
            self._current_percent = self._target_percent
            self._draw_meter()
            return
        step = (self._target_percent - self._current_percent) * 0.25
        if abs(step) < 1:
            step = 1 if self._target_percent > self._current_percent else -1
        self._current_percent += step
        self._current_percent = max(0, min(100, self._current_percent))
        self._draw_meter()
        self.root.after(16, self._animate_meter)

    def _toggle_show(self):
        self._show_password = not self._show_password
        self.entry.config(show="" if self._show_password else "*")
        self.toggle_btn.config(text="Hide" if self._show_password else "Show")

    def _update(self):
        pw = self.entry.get()
        if not pw:
            self._target_percent = 0
            self._animate_meter()
            self.strength_lbl.config(text="-", fg=TEXT)
            self.entropy_val.config(text="0 bits", fg=TEXT)
            self.crack_val.config(text="-", fg=TEXT)
            for key, lbl in self.check_labels.items():
                lbl.config(text=f"O   {CHECK_LABELS[key]}", fg=MUTED)
            for widget in self.tips_frame.winfo_children():
                widget.destroy()
            tk.Label(self.tips_frame, text="Start typing to see feedback...",
                     font=self.f_body, fg=MUTED, bg=CARD,
                     wraplength=280, justify="left", anchor="w").pack(
                fill="x", padx=6, pady=4, anchor="w")
            return

        res = evaluate_password(pw, COMMON)

        percent = int((res["score"] / 6) * 100)
        self._target_percent = percent
        self._animate_meter()

        color = LABEL_COLORS.get(res["label"], TEXT)
        self.strength_lbl.config(text=res["label"], fg=color)

        self.entropy_val.config(text=f"{res['entropy_bits']} bits",
                                fg=self._entropy_color(res["entropy_bits"]))
        self.crack_val.config(text=res["est_crack_time"], fg=color)

        for key, lbl in self.check_labels.items():
            ok = res["checks"].get(key, False)
            icon = "+" if ok else "x"
            lbl.config(text=f"{icon}   {CHECK_LABELS[key]}",
                       fg=OK if ok else BAD)

        for widget in self.tips_frame.winfo_children():
            widget.destroy()
        for tip in res["suggestions"]:
            bullet_color = OK if "Looks good" in tip else WARN
            row = tk.Frame(self.tips_frame, bg=CARD)
            row.pack(fill="x", pady=3, padx=6)
            tk.Label(row, text=">", font=self.f_body, fg=bullet_color,
                     bg=CARD).pack(side="left", padx=(0, 6), anchor="n")
            tk.Label(row, text=tip, font=self.f_body, fg=TEXT, bg=CARD,
                     wraplength=260, justify="left", anchor="w").pack(
                side="left", fill="x", expand=True, anchor="w")

    def _entropy_color(self, bits):
        if bits < 28:  return BAD
        if bits < 50:  return WARN
        if bits < 70:  return OK
        return "#10b981"


if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    app = PasswordCheckerApp(root)
    root.mainloop()
