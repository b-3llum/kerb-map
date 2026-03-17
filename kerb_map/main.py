"""
Entry point for pipx / pip install.
Delegates everything to kerb_map.cli which contains the full CLI logic.
"""

def main():
    from kerb_map.cli import main as _main
    _main()

if __name__ == "__main__":
    main()
