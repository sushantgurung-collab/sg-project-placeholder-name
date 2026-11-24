"""
FASER Automated Packaging & Submission Validator.
Verifies project file structure, validates relative paths, and creates sg26581-project.zip.
"""

import os
import zipfile
import sys

REQUIRED_FILES = [
    "report-source/main.tex",
    "report-source/references.bib",
    "report-source/figures/f1_score_by_strategy.png",
    "report-source/figures/stress_matrix_heatmap.png",
    "code/project.ipynb",
    "code/data_loader.py",
    "code/dataset_curator.py",
    "code/prompts.py",
    "code/evaluator.py",
    "code/run_benchmarks.py",
    "code/plot_results.py",
    "data/original/raw_cves.json",
    "data/processed/dataset.json",
    "data/source_and_licence.txt",
    "results/metrics.csv",
    "README.md",
    "TODO.md",
]


def verify_files(root_dir: str) -> bool:
    """Verifies existence of all mandatory submission deliverables."""
    print("Checking repository files against university specifications...")
    missing = []
    for rel_path in REQUIRED_FILES:
        full_path = os.path.join(root_dir, rel_path)
        if not os.path.exists(full_path):
            missing.append(rel_path)
        else:
            print(f"  [OK] Found: {rel_path}")

    if missing:
        print("\n[ERROR] Missing required submission files:")
        for m in missing:
            print(f"  - {m}")
        return False

    print("\nAll required files verified successfully.")
    return True


def create_faser_zip(root_dir: str, zip_name: str = "sg26581-project.zip"):
    """Packages project directory into root ZIP file."""
    zip_path = os.path.join(root_dir, zip_name)
    print(f"\nBuilding archive: {zip_path}...")

    archive_folder_name = "sg26581-project"

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(root_dir):
            # Exclude virtual environments, git caches, and bytecode
            dirs[:] = [d for d in dirs if d not in [
                ".git", "__pycache__", ".venv", "venv", ".idea", ".vscode"]]

            for file in files:
                if file.endswith(".zip") or file.endswith(".pyc"):
                    continue

                abs_file_path = os.path.join(root, file)
                rel_file_path = os.path.relpath(abs_file_path, root_dir)
                archive_path = os.path.join(archive_folder_name, rel_file_path)

                zipf.write(abs_file_path, archive_path)
                print(f"  Added: {archive_path}")

    print(
        f"\nPackaging complete. FASER submission archive created at: {zip_path}")


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(script_dir)

    if verify_files(root_dir):
        create_faser_zip(root_dir)
        print("\nFinal verification complete. Archive is ready for FASER submission.")
    else:
        print("\nPackaging aborted due to missing files.")
        sys.exit(1)


if __name__ == "__main__":
    main()
