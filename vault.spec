# vault.spec  –  PyInstaller spec for the Vault Password Manager
# Run:  .venv\Scripts\pyinstaller vault.spec

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=[
        # cryptography hazmat backends
        'cryptography.hazmat.primitives.kdf.pbkdf2',
        'cryptography.hazmat.primitives.hashes',
        'cryptography.hazmat.backends.openssl',
        'cryptography.hazmat.backends.openssl.backend',
        'cryptography.fernet',
        # bcrypt
        'bcrypt',
        # customtkinter pulls in darkdetect
        'darkdetect',
        # stdlib used at runtime
        'sqlite3',
        'tkinter',
        'tkinter.messagebox',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='Vault',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # --windowed (no black terminal window)
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
