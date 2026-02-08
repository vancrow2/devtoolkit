# Developer Tool-kit

Windowsra csomagolható desktop alkalmazás Python + Tkinter alapokon.

## Mit kapsz most?

- Főablak oldalsó menüvel (tool-választó)
- Stabilabb kezelőfelület Listbox-alapú választással
- Állapotsor (status bar) a visszajelzésekhez
- Jegyzet modul (`.txt` mentés, hibakezeléssel)
- JSON ellenőrző és formázó
- Base64 konverter (encode/decode, formátumhiba jelzés)
- Base64 → JSON (dekódolás + JSON pretty/validálás)
- Fájl SHA-256 hash számító (chunk-olt olvasással)

## Futtatás helyben

```bash
python app.py
```

## Tesztek futtatása

```bash
python -m pytest -q
```

## Windows `.exe` build

1. Nyiss terminált a projektben.
2. (Ajánlott) hozz létre virtuális környezetet:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   ```
3. Futtasd:
   ```bash
   build_exe.bat
   ```
4. Az elkészült fájl: `dist\\DeveloperToolKit.exe`

## Bővítés

Új tool hozzáadása: készíts egy új `_render_*` metódust és add hozzá a `self.tools` szótárhoz.
