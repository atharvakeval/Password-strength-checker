import tkinter as tk
from tkinter import ttk
from password_strength import evaluate_password, load_common_passwords

COMMON = load_common_passwords()

def color_for_label(label: str) -> str:
    return {
        "Very Weak": "#d90429",
        "Weak": "#ef233c",
        "Medium": "#f7b801",
        "Strong": "#2a9d8f",
        "Very Strong": "#2b9348",
    }[label]

def update_strength(*_):
    pw = entry.get()
    res = evaluate_password(pw, COMMON)

    percent = int((res["score"] / 6) * 100)
    meter["value"] = percent

    label_text = f"{res['label']}  |  {res['entropy_bits']} bits  |  ~{res['est_crack_time']}"
    strength_lbl.config(text=label_text, foreground=color_for_label(res["label"]))

    for i, (name, ok) in enumerate(res["checks"].items()):
        crit_labels[i].config(text=f"{'✔' if ok else '✘'} {name}",
                              foreground="#2b9348" if ok else "#d90429")

    tips_box.config(state="normal")
    tips_box.delete("1.0", "end")
    for tip in res["suggestions"]:
        tips_box.insert("end", f"• {tip}\n")
    tips_box.config(state="disabled")

root = tk.Tk()
root.title("Password Strength Checker (Cybersecurity)")
root.geometry("640x420")

tk.Label(root, text="Enter password:", font=("Segoe UI", 11)).pack(pady=(16, 4))
entry = ttk.Entry(root, show="*")
entry.pack(fill="x", padx=16)

meter = ttk.Progressbar(root, mode="determinate", maximum=100)
meter.pack(fill="x", padx=16, pady=10)

strength_lbl = tk.Label(root, text="", font=("Segoe UI", 10, "bold"))
strength_lbl.pack(padx=16)

crit_frame = ttk.LabelFrame(root, text="Policy checks")
crit_frame.pack(fill="x", padx=16, pady=8)
crit_labels = []
for _ in range(6):
    lbl = tk.Label(crit_frame, text="", anchor="w")
    lbl.pack(fill="x", padx=10)
    crit_labels.append(lbl)

tips_frame = ttk.LabelFrame(root, text="Feedback")
tips_frame.pack(fill="both", expand=True, padx=16, pady=8)
tips_box = tk.Text(tips_frame, height=6, wrap="word")
tips_box.pack(fill="both", expand=True, padx=10, pady=8)
tips_box.config(state="disabled")

entry.bind("<KeyRelease>", update_strength)
entry.focus_set()
update_strength()

root.mainloop()
