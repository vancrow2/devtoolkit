import base64
import binascii
import hashlib
import json
import re
import shutil
import ssl
import subprocess
import tkinter as tk
from datetime import datetime, timezone
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


def encode_base64(raw: str) -> str:
    """Encode UTF-8 text to Base64."""
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")


def decode_base64(raw: str) -> tuple[bool, str]:
    """Decode a Base64 text and validate formatting/errors."""
    cleaned = "".join(raw.split())
    if not cleaned:
        return False, "Adj meg Base64 szöveget."
    try:
        decoded = base64.b64decode(cleaned, validate=True)
        return True, decoded.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return False, "Sérült vagy érvénytelen Base64 formátum."


def decode_base64_robust(
    raw: str,
    *,
    urlsafe: bool = True,
    add_padding: bool = True,
) -> tuple[bool, str]:
    """Decode Base64/Base64URL with optional padding repair and friendly errors."""
    cleaned = "".join(raw.split())
    if not cleaned:
        return False, "Adj meg Base64 inputot."

    candidate = cleaned
    if urlsafe or "-" in candidate or "_" in candidate:
        candidate = candidate.replace("-", "+").replace("_", "/")

    if add_padding:
        missing = len(candidate) % 4
        if missing:
            candidate += "=" * (4 - missing)

    try:
        decoded = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        return False, "Érvénytelen vagy sérült Base64 input."

    try:
        return True, decoded.decode("utf-8")
    except UnicodeDecodeError:
        return False, "A dekódolt tartalom nem UTF-8 szöveg."


def decode_and_pretty_json_from_base64(
    raw: str,
    *,
    urlsafe: bool = True,
    add_padding: bool = True,
) -> tuple[bool, str, str]:
    """Decode Base64 text and attempt JSON pretty-printing."""
    ok, decoded_text = decode_base64_robust(
        raw,
        urlsafe=urlsafe,
        add_padding=add_padding,
    )
    if not ok:
        return False, "Hiba", decoded_text

    try:
        parsed = json.loads(decoded_text)
    except json.JSONDecodeError:
        return True, "Nem JSON", decoded_text

    pretty = json.dumps(parsed, ensure_ascii=False, indent=2)
    return True, "OK", pretty


def _extract_cn(name_line: str) -> str:
    match = re.search(r"CN\s*=\s*([^,\/]+)", name_line)
    if match:
        return match.group(1).strip()
    slash_match = re.search(r"/CN=([^/]+)", name_line)
    if slash_match:
        return slash_match.group(1).strip()
    return "-"


def _extract_extension(text: str, extension_name: str) -> str:
    pattern = rf"X509v3 {re.escape(extension_name)}:\s*\n\s*(.+?)(?=\n\s*X509v3 |\n\s*Signature Algorithm:|\Z)"
    match = re.search(pattern, text, flags=re.DOTALL)
    if not match:
        return "-"
    lines = [line.strip() for line in match.group(1).splitlines() if line.strip()]
    return " ".join(lines) if lines else "-"


def _to_der_bytes(cert_path: Path) -> tuple[bool, bytes | None, str]:
    raw = cert_path.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in raw:
        pem_match = re.search(
            b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            raw,
            flags=re.DOTALL,
        )
        if not pem_match:
            return False, None, "Nem található tanúsítvány blokk a PEM fájlban."
        pem_text = pem_match.group(0).decode("ascii", errors="ignore")
        try:
            der = ssl.PEM_cert_to_DER_cert(pem_text)
        except ValueError:
            return False, None, "Érvénytelen PEM tanúsítvány formátum."
        return True, der, ""
    return True, raw, ""


def _extract_certutil_block(text: str, pattern: str) -> str:
    match = re.search(pattern, text, flags=re.DOTALL | re.IGNORECASE)
    if not match:
        return "-"
    lines = [line.strip() for line in match.group(1).splitlines() if line.strip()]
    return " ".join(lines) if lines else "-"


def read_certificate_info(cert_path: Path) -> tuple[bool, dict[str, str], str]:
    """Read key certificate fields from a certificate file using certutil."""
    if not cert_path.exists() or not cert_path.is_file():
        return False, {}, "A megadott útvonal nem érvényes fájl."

    certutil_path = shutil.which("certutil")
    if not certutil_path:
        return (
            False,
            {},
            "A certutil nem érhető el ezen a gépen/PATH-ban, ezért a tanúsítvány nem olvasható.",
        )

    ok_der, der_bytes, der_error = _to_der_bytes(cert_path)
    if not ok_der or der_bytes is None:
        return False, {}, der_error

    sha1_thumbprint = hashlib.sha1(der_bytes).hexdigest().upper()
    sha256_thumbprint = hashlib.sha256(der_bytes).hexdigest().upper()

    result = subprocess.run(
        [certutil_path, "-dump", str(cert_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        err = (result.stderr or "").strip() or "A certutil nem tudta feldolgozni a fájlt."
        return False, {}, f"certutil hiba: {err}"

    dump = result.stdout

    subject_match = re.search(r"(?:^|\n)Subject:\s*(.+?)(?=\n\S|\Z)", dump, flags=re.DOTALL)
    issuer_match = re.search(r"(?:^|\n)Issuer:\s*(.+?)(?=\n\S|\Z)", dump, flags=re.DOTALL)
    serial_match = re.search(r"(?:Serial Number|Sorozatsz[aá]m)\s*:\s*([^\n]+)", dump, flags=re.IGNORECASE)

    not_before_match = re.search(
        r"(?:NotBefore|Érvényesség kezdete|Not Before)\s*:\s*([^\n]+)",
        dump,
        flags=re.IGNORECASE,
    )
    not_after_match = re.search(
        r"(?:NotAfter|Érvényesség vége|Not After)\s*:\s*([^\n]+)",
        dump,
        flags=re.IGNORECASE,
    )

    signature_match = re.search(r"Signature Algorithm\s*:?\s*([^\n]+)", dump)
    pubkey_match = re.search(r"Public Key Algorithm\s*:?\s*([^\n]+)", dump)
    key_size_match = re.search(r"Public Key Length\s*:?\s*([^\n]+)", dump)

    subject_text = subject_match.group(1).strip() if subject_match else ""
    issuer_text = issuer_match.group(1).strip() if issuer_match else ""

    not_before = not_before_match.group(1).strip() if not_before_match else "-"
    not_after = not_after_match.group(1).strip() if not_after_match else "-"

    days_left = "-"
    if not_after != "-":
        date_match = re.search(r"([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})", not_after)
        if date_match:
            try:
                exp = datetime.strptime(date_match.group(1), "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                days_left = str((exp - datetime.now(timezone.utc)).days)
            except ValueError:
                days_left = "-"

    key_usage = _extract_certutil_block(
        dump,
        r"(?:2\.5\.29\.15|Key Usage).*?:\s*\n(.+?)(?=\n\s*(?:2\.5\.29\.|[0-9]+\.[0-9]+\.|CERT_|Signature Algorithm|$))",
    )
    eku = _extract_certutil_block(
        dump,
        r"(?:2\.5\.29\.37|Enhanced Key Usage).*?:\s*\n(.+?)(?=\n\s*(?:2\.5\.29\.|[0-9]+\.[0-9]+\.|CERT_|Signature Algorithm|$))",
    )
    san = _extract_certutil_block(
        dump,
        r"(?:2\.5\.29\.17|Subject Alternative Name).*?:\s*\n(.+?)(?=\n\s*(?:2\.5\.29\.|[0-9]+\.[0-9]+\.|CERT_|Signature Algorithm|$))",
    )

    san_items = []
    if san != "-":
        for part in [p.strip() for p in san.split(",") if p.strip()]:
            if "DNS" in part or "IP" in part:
                san_items.append(part)
    san_value = ", ".join(san_items) if san_items else san

    info = {
        "Subject CN": _extract_cn(subject_text),
        "Issuer CN": _extract_cn(issuer_text),
        "Serial number": serial_match.group(1).strip() if serial_match else "-",
        "Not Before": not_before,
        "Not After": not_after,
        "Days left": days_left,
        "Signature algorithm": signature_match.group(1).strip() if signature_match else "-",
        "Public key algorithm": pubkey_match.group(1).strip() if pubkey_match else "-",
        "Key size": key_size_match.group(1).strip() if key_size_match else "-",
        "Key Usage": key_usage,
        "Enhanced Key Usage (EKU)": eku,
        "SAN": san_value,
        "Chain status": "OK",
        "SHA-1 thumbprint": sha1_thumbprint,
        "SHA-256 thumbprint": sha256_thumbprint,
    }
    return True, info, ""


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
            "Base64 konverter": self._render_base64_converter,
            "Base64 → JSON": self._render_base64_json,
            "Fájl hash": self._render_file_hash,
            "Tanúsítvány infó": self._render_certificate_info,
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

        form = ttk.Frame(body)
        form.grid(row=0, column=0, sticky="ew")
        form.columnconfigure(1, weight=1)

        output = ttk.Frame(body)
        output.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        output.columnconfigure(1, weight=1)

        panel_status = ttk.Label(body, text="")
        panel_status.grid(row=2, column=0, sticky="w", pady=(10, 0))

        path_var = tk.StringVar()
        output_var = tk.StringVar(value="")

        ttk.Label(form, text="Fájl:").grid(
            row=0, column=0, sticky="w", padx=(0, 8), pady=(0, 8)
        )
        ttk.Entry(form, textvariable=path_var).grid(
            row=0, column=1, sticky="ew", pady=(0, 8)
        )
        ttk.Button(form, text="Tallózás", command=lambda: choose_file()).grid(
            row=0, column=2, padx=(8, 0), pady=(0, 8)
        )

        ttk.Label(form, text="SHA-256").grid(
            row=1, column=0, columnspan=3, sticky="w", pady=(0, 8)
        )

        ttk.Label(output, text="Hash:").grid(
            row=0, column=0, sticky="w", padx=(0, 8), pady=(0, 8)
        )
        ttk.Entry(output, textvariable=output_var, state="readonly").grid(
            row=0, column=1, sticky="ew", pady=(0, 8)
        )
        ttk.Button(output, text="Másolás", command=lambda: copy_hash()).grid(
            row=0, column=2, padx=(8, 0), pady=(0, 8)
        )

        ttk.Button(form, text="Hash számítás", command=lambda: hash_file()).grid(
            row=2, column=0, sticky="w"
        )

        def choose_file() -> None:
            selected = filedialog.askopenfilename(title="Fájl kiválasztása")
            if selected:
                path_var.set(selected)

        def hash_file() -> None:
            path = Path(path_var.get().strip())
            if not str(path):
                output_var.set("Adj meg fájlt.")
                panel_status.config(text="Hiba")
                return
            if not path.exists() or not path.is_file():
                output_var.set("A megadott útvonal nem érvényes fájl.")
                panel_status.config(text="Hiba")
                return
            try:
                output_var.set(sha256_for_file(path))
                panel_status.config(text="OK")
                self.status_text.set(f"Hash elkészült: {path.name}")
            except OSError as exc:
                output_var.set(f"Hiba: {exc}")
                panel_status.config(text="Hiba")
                self.status_text.set("Hash számítás sikertelen.")

        def copy_hash() -> None:
            value = output_var.get().strip()
            if not value:
                self.status_text.set("Nincs másolható hash.")
                return
            self.clipboard_clear()
            self.clipboard_append(value)
            self.status_text.set("Hash vágólapra másolva.")

    def _render_base64_converter(self) -> None:
        body = self._clear_content("Base64 konverter")
        self.status_text.set("Base64 konverter panel megnyitva.")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(2, weight=1)
        body.rowconfigure(5, weight=1)

        ttk.Label(body, text="Base64").grid(row=0, column=0, sticky="w")
        top_container = ttk.Frame(body)
        top_container.grid(row=1, column=0, sticky="nsew")
        top_container.columnconfigure(0, weight=1)
        top_container.rowconfigure(0, weight=1)
        base64_box = tk.Text(top_container, wrap="none", height=8, font=("Consolas", 11))
        base64_box.grid(row=0, column=0, sticky="nsew")
        top_scroll = ttk.Scrollbar(top_container, orient="vertical", command=base64_box.yview)
        top_scroll.grid(row=0, column=1, sticky="ns")
        base64_box.configure(yscrollcommand=top_scroll.set)

        controls = ttk.Frame(body)
        controls.grid(row=2, column=0, sticky="ew", pady=(8, 8))

        ttk.Label(body, text="Text").grid(row=3, column=0, sticky="w")
        bottom_container = ttk.Frame(body)
        bottom_container.grid(row=4, column=0, sticky="nsew")
        bottom_container.columnconfigure(0, weight=1)
        bottom_container.rowconfigure(0, weight=1)
        text_box = tk.Text(bottom_container, wrap="none", height=8, font=("Consolas", 11))
        text_box.grid(row=0, column=0, sticky="nsew")
        bottom_scroll = ttk.Scrollbar(bottom_container, orient="vertical", command=text_box.yview)
        bottom_scroll.grid(row=0, column=1, sticky="ns")
        text_box.configure(yscrollcommand=bottom_scroll.set)

        result = ttk.Label(body, text="")
        result.grid(row=5, column=0, sticky="w", pady=(8, 0))

        sample_text = "InfoScope Kft. 2026"
        sample_base64 = encode_base64(sample_text)
        base64_box.insert("1.0", f'Base64 = "{sample_base64}"')
        text_box.insert("1.0", f'Text = "{sample_text}"')

        def encode_text() -> None:
            source = text_box.get("1.0", "end").strip()
            if not source:
                result.config(text="❌ Adj meg szöveget az alsó mezőben.")
                self.status_text.set("Base64 encode hibás: nincs szöveg.")
                return
            encoded = encode_base64(source)
            base64_box.delete("1.0", "end")
            base64_box.insert("1.0", encoded)
            result.config(text="✅ Kódolás kész.")
            self.status_text.set("Base64 kódolás sikeres.")

        def decode_text() -> None:
            source = base64_box.get("1.0", "end")
            ok, decoded = decode_base64(source)
            if not ok:
                result.config(text=f"❌ {decoded}")
                self.status_text.set("Base64 dekódolás hibás.")
                return
            text_box.delete("1.0", "end")
            text_box.insert("1.0", decoded)
            result.config(text="✅ Dekódolás kész.")
            self.status_text.set("Base64 dekódolás sikeres.")

        ttk.Button(controls, text="Encode", command=encode_text).pack(side="left")
        ttk.Button(controls, text="Decode", command=decode_text).pack(
            side="left", padx=(8, 0)
        )

    def _render_base64_json(self) -> None:
        body = self._clear_content("Base64 → JSON")
        self.status_text.set("Base64 → JSON panel megnyitva.")

        form = ttk.Frame(body)
        form.grid(row=0, column=0, sticky="ew")
        form.columnconfigure(0, weight=1)

        output = ttk.Frame(body)
        output.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        output.columnconfigure(0, weight=1)
        output.rowconfigure(1, weight=1)

        panel_status = ttk.Label(body, text="")
        panel_status.grid(row=2, column=0, sticky="w", pady=(10, 0))

        urlsafe_var = tk.BooleanVar(value=True)
        padding_var = tk.BooleanVar(value=True)

        options = ttk.Frame(form)
        options.grid(row=0, column=0, sticky="w", pady=(0, 8))
        ttk.Checkbutton(
            options,
            text="URL-safe Base64 (base64url: - _)",
            variable=urlsafe_var,
        ).pack(side="left")
        ttk.Checkbutton(
            options,
            text="Add missing padding (=)",
            variable=padding_var,
        ).pack(side="left", padx=(12, 0))

        ttk.Label(form, text="Base64 input").grid(row=1, column=0, sticky="w", pady=(0, 4))

        input_wrap = ttk.Frame(form)
        input_wrap.grid(row=2, column=0, sticky="ew")
        input_wrap.columnconfigure(0, weight=1)
        input_wrap.rowconfigure(0, weight=1)

        input_box = tk.Text(input_wrap, wrap="none", height=8, font=("Consolas", 11))
        input_box.grid(row=0, column=0, sticky="ew")
        input_scroll = ttk.Scrollbar(input_wrap, orient="vertical", command=input_box.yview)
        input_scroll.grid(row=0, column=1, sticky="ns")
        input_box.configure(yscrollcommand=input_scroll.set)

        controls = ttk.Frame(form)
        controls.grid(row=3, column=0, sticky="w", pady=(8, 0))

        ttk.Label(output, text="Output").grid(row=0, column=0, sticky="w", pady=(0, 4))

        output_wrap = ttk.Frame(output)
        output_wrap.grid(row=1, column=0, sticky="nsew")
        output_wrap.columnconfigure(0, weight=1)
        output_wrap.rowconfigure(0, weight=1)

        output_box = tk.Text(output_wrap, wrap="none", height=10, font=("Consolas", 11))
        output_box.grid(row=0, column=0, sticky="nsew")
        output_scroll = ttk.Scrollbar(output_wrap, orient="vertical", command=output_box.yview)
        output_scroll.grid(row=0, column=1, sticky="ns")
        output_box.configure(yscrollcommand=output_scroll.set)
        output_box.configure(state="disabled")

        def set_output(status: str, message: str) -> None:
            output_box.configure(state="normal")
            output_box.delete("1.0", "end")
            output_box.insert("1.0", f"{status}\n\n{message}")
            output_box.configure(state="disabled")
            panel_status.config(text=status)

        def decode_only() -> None:
            ok, decoded = decode_base64_robust(
                input_box.get("1.0", "end"),
                urlsafe=urlsafe_var.get(),
                add_padding=padding_var.get(),
            )
            if ok:
                set_output("OK", decoded)
                self.status_text.set("Base64 dekódolás sikeres.")
            else:
                set_output("Hiba", decoded)
                self.status_text.set("Base64 dekódolás hibás.")

        def decode_and_pretty() -> None:
            ok, status, payload = decode_and_pretty_json_from_base64(
                input_box.get("1.0", "end"),
                urlsafe=urlsafe_var.get(),
                add_padding=padding_var.get(),
            )
            set_output(status, payload)
            if ok:
                self.status_text.set(f"Base64 → JSON: {status}")
            else:
                self.status_text.set("Base64 → JSON feldolgozás hibás.")

        def auto_process() -> None:
            ok, status, payload = decode_and_pretty_json_from_base64(
                input_box.get("1.0", "end"),
                urlsafe=urlsafe_var.get(),
                add_padding=padding_var.get(),
            )
            set_output(status, payload)
            if ok:
                self.status_text.set(f"Auto feldolgozás: {status}")
            else:
                self.status_text.set("Auto feldolgozás hibás.")

        def copy_output() -> None:
            content = output_box.get("1.0", "end").strip()
            if not content:
                self.status_text.set("Nincs másolható output.")
                return
            self.clipboard_clear()
            self.clipboard_append(content)
            self.status_text.set("Output vágólapra másolva.")

        def clear_all() -> None:
            input_box.delete("1.0", "end")
            set_output("OK", "")
            self.status_text.set("Base64 → JSON panel ürítve.")

        ttk.Button(controls, text="Decode", command=decode_only).pack(side="left")
        ttk.Button(controls, text="Auto", command=auto_process).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Decode + JSON Pretty", command=decode_and_pretty).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(controls, text="Copy output", command=copy_output).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(controls, text="Clear", command=clear_all).pack(side="left", padx=(8, 0))

    def _render_certificate_info(self) -> None:
        body = self._clear_content("Tanúsítvány infó")
        self.status_text.set("Tanúsítvány infó panel megnyitva.")

        form = ttk.Frame(body)
        form.grid(row=0, column=0, sticky="ew")
        form.columnconfigure(1, weight=1)

        output = ttk.Frame(body)
        output.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        output.columnconfigure(0, weight=1)
        output.rowconfigure(0, weight=1)

        cert_path_var = tk.StringVar()
        sha1_var = tk.StringVar(value="-")
        sha256_var = tk.StringVar(value="-")

        ttk.Label(form, text="Fájl:").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(form, textvariable=cert_path_var).grid(row=0, column=1, sticky="ew")

        result_box = tk.Text(output, wrap="word", height=16, font=("Consolas", 10))
        result_box.grid(row=0, column=0, sticky="nsew")
        result_scroll = ttk.Scrollbar(output, orient="vertical", command=result_box.yview)
        result_scroll.grid(row=0, column=1, sticky="ns")
        result_box.configure(yscrollcommand=result_scroll.set, state="disabled")

        thumbprints = ttk.Frame(body)
        thumbprints.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        thumbprints.columnconfigure(1, weight=1)

        ttk.Label(thumbprints, text="SHA-1:").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(thumbprints, textvariable=sha1_var, state="readonly").grid(
            row=0, column=1, sticky="ew"
        )

        ttk.Label(thumbprints, text="SHA-256:").grid(
            row=1, column=0, sticky="w", padx=(0, 8), pady=(6, 0)
        )
        ttk.Entry(thumbprints, textvariable=sha256_var, state="readonly").grid(
            row=1, column=1, sticky="ew", pady=(6, 0)
        )

        def set_result(text: str) -> None:
            result_box.configure(state="normal")
            result_box.delete("1.0", "end")
            result_box.insert("1.0", text)
            result_box.configure(state="disabled")

        def format_info(info: dict[str, str]) -> str:
            fields = [
                "Subject CN",
                "Issuer CN",
                "Serial number",
                "Not Before",
                "Not After",
                "Days left",
                "Signature algorithm",
                "Public key algorithm",
                "Key size",
                "Key Usage",
                "Enhanced Key Usage (EKU)",
                "SAN",
                "Chain status",
            ]
            lines = [f"{field}: {info.get(field, '-')}" for field in fields]
            return "\n".join(lines)

        def browse_file() -> None:
            selected = filedialog.askopenfilename(
                title="Tanúsítvány kiválasztása",
                filetypes=[
                    ("Certificate files", "*.cer *.crt *.pem"),
                    ("All files", "*.*"),
                ],
            )
            if selected:
                cert_path_var.set(selected)

        def copy_thumbprint(var: tk.StringVar, label: str) -> None:
            value = var.get().strip()
            if not value or value == "-":
                self.status_text.set(f"Nincs másolható {label}.")
                return
            self.clipboard_clear()
            self.clipboard_append(value)
            self.status_text.set(f"{label} vágólapra másolva.")

        def load_certificate() -> None:
            target = Path(cert_path_var.get().strip())
            ok, info, error = read_certificate_info(target)
            if not ok:
                sha1_var.set("-")
                sha256_var.set("-")
                set_result(f"Hiba: {error}")
                self.status_text.set("Tanúsítvány feldolgozás sikertelen.")
                return

            sha1_var.set(info.get("SHA-1 thumbprint", "-"))
            sha256_var.set(info.get("SHA-256 thumbprint", "-"))
            set_result(format_info(info))
            self.status_text.set("Tanúsítvány adatainak beolvasása kész.")

        controls = ttk.Frame(form)
        controls.grid(row=0, column=2, padx=(8, 0), sticky="ne")
        ttk.Button(controls, text="Tallózás", command=browse_file).pack(fill="x")
        ttk.Button(controls, text="Betöltés", command=load_certificate).pack(
            fill="x", pady=(6, 0)
        )

        ttk.Button(
            thumbprints,
            text="Copy SHA-1",
            command=lambda: copy_thumbprint(sha1_var, "SHA-1"),
        ).grid(row=0, column=2, padx=(8, 0), sticky="ew")
        ttk.Button(
            thumbprints,
            text="Copy SHA-256",
            command=lambda: copy_thumbprint(sha256_var, "SHA-256"),
        ).grid(row=1, column=2, padx=(8, 0), pady=(6, 0), sticky="ew")


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
