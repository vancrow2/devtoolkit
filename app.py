import hashlib
import json
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk


def format_json(raw: str) -> tuple[bool, str]:
    """Validate and pretty-format JSON text."""
    cleaned = raw.strip()
    if not cleaned:
        return False, "Adj meg JSON szöveget."
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        return False, f"Hibás JSON: {exc}"
    return True, json.dumps(parsed, ensure_ascii=False, indent=2)


def sha256_for_file(path: Path) -> str:
    """Compute SHA-256 for a file in chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(8192):
            digest.update(chunk)
    return digest.hexdigest()


class DeveloperToolkitApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Developer Tool-kit")
        self.geometry("1000x650")
        self.minsize(920, 560)

        self.current_tool = tk.StringVar(value="Üdvözlő")
        self.status_text = tk.StringVar(value="Készen áll.")
        self._build_layout()
        self._select_tool("Üdvözlő")

    def _build_layout(self) -> None:
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        sidebar = ttk.Frame(self, padding=(12, 12))
        sidebar.grid(row=0, column=0, sticky="ns")

        ttk.Label(
            sidebar,
            text="Developer Tool-kit",
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", pady=(0, 10))

        self.menu = tk.Listbox(
            sidebar,
            height=8,
            exportselection=False,
            activestyle="none",
            font=("Segoe UI", 10),
        )
        self.menu.pack(fill="x")

        self.tools: dict[str, callable] = {
            "Üdvözlő": self._render_home,
            "Jegyzet": self._render_notes,
            "JSON ellenőrző": self._render_json_validator,
            "Fájl hash": self._render_file_hash,
            "Névjegy": self._render_about,
        }
        for tool_name in self.tools:
            self.menu.insert("end", tool_name)
        self.menu.bind("<<ListboxSelect>>", self._on_tool_selected)

        ttk.Button(sidebar, text="Kilépés", command=self.destroy).pack(
            fill="x", pady=(10, 0)
        )

        self.content = ttk.Frame(self, padding=(18, 16))
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.columnconfigure(0, weight=1)
        self.content.rowconfigure(1, weight=1)

        status = ttk.Label(
            self,
            textvariable=self.status_text,
            relief="sunken",
            anchor="w",
            padding=(8, 3),
        )
        status.grid(row=1, column=0, columnspan=2, sticky="ew")

    def _on_tool_selected(self, _event: tk.Event) -> None:
        selected = self.menu.curselection()
        if not selected:
            return
        tool_name = self.menu.get(selected[0])
        self._select_tool(tool_name)

    def _select_tool(self, tool_name: str) -> None:
        if tool_name not in self.tools:
            return
        self.current_tool.set(tool_name)
        tool_index = list(self.tools.keys()).index(tool_name)
        self.menu.selection_clear(0, "end")
        self.menu.selection_set(tool_index)
        self.menu.activate(tool_index)
        self.tools[tool_name]()

    def _clear_content(self, title: str) -> ttk.Frame:
        for widget in self.content.winfo_children():
            widget.destroy()

        header = ttk.Label(self.content, text=title, font=("Segoe UI", 15, "bold"))
        header.grid(row=0, column=0, sticky="w", pady=(0, 10))

        body = ttk.Frame(self.content)
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)
        return body

    def _render_home(self) -> None:
        body = self._clear_content("Üdv a Developer Tool-kitben")
        self.status_text.set("Üdvözlő panel megnyitva.")
        message = (
            "Ez egy Windowsra csomagolható desktop app sablon.\n\n"
            "A bal oldali menüből választhatsz tool-okat.\n"
            "A panelek külön funkciókhoz bővíthetők."
        )
        ttk.Label(body, text=message, justify="left").grid(row=0, column=0, sticky="nw")

    def _render_notes(self) -> None:
        body = self._clear_content("Jegyzet")
        self.status_text.set("Jegyzet panel megnyitva.")
        editor = tk.Text(body, wrap="word", font=("Consolas", 11))
        editor.grid(row=0, column=0, sticky="nsew")

        controls = ttk.Frame(body)
        controls.grid(row=1, column=0, sticky="ew", pady=(8, 0))

        def save_note() -> None:
            path = filedialog.asksaveasfilename(
                title="Jegyzet mentése",
                defaultextension=".txt",
                filetypes=[("Szövegfájl", "*.txt"), ("Minden fájl", "*.*")],
            )
            if not path:
                return
            try:
                Path(path).write_text(editor.get("1.0", "end").rstrip(), encoding="utf-8")
            except OSError as exc:
                messagebox.showerror("Mentési hiba", f"Nem sikerült menteni:\n{exc}")
                self.status_text.set("Mentési hiba történt.")
                return
            messagebox.showinfo("Mentve", f"Jegyzet elmentve ide:\n{path}")
            self.status_text.set(f"Jegyzet elmentve: {path}")

        ttk.Button(controls, text="Mentés .txt-be", command=save_note).pack(anchor="e")

    def _render_json_validator(self) -> None:
        body = self._clear_content("JSON ellenőrző")
        self.status_text.set("JSON ellenőrző panel megnyitva.")

        input_area = tk.Text(body, wrap="none", font=("Consolas", 11), height=16)
        input_area.grid(row=0, column=0, sticky="nsew")

        result = ttk.Label(body, text="")
        result.grid(row=2, column=0, sticky="w", pady=(8, 0))

        def validate() -> None:
            ok, output = format_json(input_area.get("1.0", "end"))
            if ok:
                input_area.delete("1.0", "end")
                input_area.insert("1.0", output)
                result.config(text="✅ Érvényes JSON")
                self.status_text.set("JSON ellenőrzés sikeres.")
            else:
                result.config(text=f"❌ {output}")
                self.status_text.set("JSON ellenőrzés hibát talált.")

        ttk.Button(body, text="Ellenőrzés", command=validate).grid(
            row=1, column=0, sticky="e", pady=(8, 0)
        )

    def _render_file_hash(self) -> None:
        body = self._clear_content("Fájl hash (SHA-256)")
        self.status_text.set("Fájl hash panel megnyitva.")
        body.columnconfigure(1, weight=1)

        path_var = tk.StringVar()
        output_var = tk.StringVar(value="Válassz fájlt...")

        ttk.Label(body, text="Fájl:").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(body, textvariable=path_var).grid(row=0, column=1, sticky="ew")

        def choose_file() -> None:
            selected = filedialog.askopenfilename(title="Fájl kiválasztása")
            if selected:
                path_var.set(selected)

        def hash_file() -> None:
            path = Path(path_var.get().strip())
            if not str(path):
                output_var.set("Adj meg fájlt.")
                return
            if not path.exists() or not path.is_file():
                output_var.set("A megadott útvonal nem érvényes fájl.")
                return
            try:
                output_var.set(sha256_for_file(path))
                self.status_text.set(f"Hash elkészült: {path.name}")
            except OSError as exc:
                output_var.set(f"Hiba: {exc}")
                self.status_text.set("Hash számítás sikertelen.")

        ttk.Button(body, text="Tallózás", command=choose_file).grid(
            row=0, column=2, padx=(8, 0)
        )
        ttk.Button(body, text="Hash számítás", command=hash_file).grid(
            row=1, column=2, padx=(8, 0), pady=(8, 0)
        )
        ttk.Label(body, textvariable=output_var, wraplength=620).grid(
            row=2, column=0, columnspan=3, sticky="w", pady=(12, 0)
        )

    def _render_about(self) -> None:
        body = self._clear_content("Névjegy")
        self.status_text.set("Névjegy panel megnyitva.")
        ttk.Label(
            body,
            text=(
                "Developer Tool-kit\n"
                "Verzió: 0.2.0\n\n"
                "Cél: bővíthető desktop eszköztár fejlesztőknek.\n"
                "A mostani modulok alapként szolgálnak további tool-okhoz."
            ),
            justify="left",
        ).grid(row=0, column=0, sticky="nw")


if __name__ == "__main__":
    app = DeveloperToolkitApp()
    app.mainloop()
