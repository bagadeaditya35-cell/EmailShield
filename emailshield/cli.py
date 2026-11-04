"""Command line: python -m emailshield.cli scan <folder>"""
import sys

from . import db, ingest


def main(argv):
    if len(argv) < 2 or argv[0] != "scan":
        print("Usage: python -m emailshield.cli scan <folder-with-.eml-files>")
        return 2
    db.init()
    results = ingest.ingest_folder(argv[1])
    for r in results:
        if r["ok"]:
            tag = " (duplicate, skipped)" if r["duplicate"] else ""
            print(f"{r['file']:<28} {r['category']:<11} score={r['score']:<3}{tag}")
        else:
            print(f"{r['file']:<28} ERROR {r['error']}")
    print(f"\n{len(results)} file(s) processed.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
