"""Retired upstream bridge configurator. It must not configure or start capture."""
import sys

if __name__ == "__main__":
    print("The upstream bridge/Synapse configurator is retired in this fork. Use install_macos.py for a fresh cold-readonly package. Pairing, source capture and bridge installation require separate approval and are not provided here.", file=sys.stderr)
    sys.exit(2)
