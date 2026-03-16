import sys
import os
import importlib.util

def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, root)
    spec = importlib.util.spec_from_file_location(
        "kerb_map_cli",
        os.path.join(root, "kerb-map.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.main()

if __name__ == "__main__":
    main()
