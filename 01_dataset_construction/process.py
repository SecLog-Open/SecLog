import os
import tarfile
import subprocess
from datetime import datetime
from pathlib import Path

def find_newest_tar_gz(path):
    """Return the most recently modified .tar.gz file in the directory."""
    newest_file = None
    newest_time = datetime.min
    for file in os.listdir(path):
        if file.endswith('.tar.gz'):
            file_path = os.path.join(path, file)
            file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
            if file_time > newest_time:
                newest_time = file_time
                newest_file = file_path
    return newest_file

def extract_and_count_lines(tar_path, extract_dir):
    """Report archive size; the extraction and line-counting block is inactive."""
    if not tar_path:
        return
    # Archive extraction is available in the block below the early return.
    # with tarfile.open(tar_path, 'r:gz') as tar:
    # tar.extractall(path=extract_dir)
    subprocess.run(['du', '-l', tar_path])
    return

    subprocess.run(['tar', 'xzvf', tar_path, '-C', extract_dir])
    
    sysdig_total = 0
    tshark_total = 0
    applog_total = 0

    malicious_count_applog = 0
    malicious_count_tshark = 0
    malicious_count_sysdig = 0

    # Count lines in the extracted files, grouped by log source.
    for root, dirs, files in os.walk(extract_dir):
        for file in files:
            file_path = os.path.join(root, file)
            # Use wc to count file lines.
            result = subprocess.run(['wc', '-l', file_path], stdout=subprocess.PIPE, text=True)
            lines = int(result.stdout.split()[0])
            if '/sysdig/' in file_path:
                sysdig_total += lines
                count_result = subprocess.run(['grep', '-o', '"malicious": true', file_path], stdout=subprocess.PIPE).stdout.count(b'\n')
                malicious_count_sysdig += count_result
            elif '/tshark/' in file_path:
                tshark_total += lines
                count_result = subprocess.run(['grep', '-o', '"malicious": true', file_path], stdout=subprocess.PIPE).stdout.count(b'\n')
                malicious_count_tshark += count_result
            elif '/applog/' in file_path:
                applog_total += lines
                count_result = subprocess.run(['grep', '-o', '\\*MALICIOUS\\*', file_path], stdout=subprocess.PIPE).stdout.count(b'\n')
                malicious_count_applog += count_result
            print(f"File: {file_path}, lines: {lines}, attack lines: {count_result}")

    print(f"Path: {tar_path}, Sysdig lines: {sysdig_total}, Tshark lines: {tshark_total}, Applog lines: {applog_total}")
    print(f"Applog '*MALICIOUS*' occurrences: {malicious_count_applog}")
    print(f"Tshark '\"malicious\": true' occurrences: {malicious_count_tshark}")
    print(f"Sysdig '\"malicious\": true' occurrences: {malicious_count_sysdig}")

def main():
    search_dir = str(Path(__file__).resolve().parent / "results")
    extract_dir = '/tmp/tar_temp'  # Temporary archive extraction directory.

    # Inspect each result directory and its subdirectories.
    for root, dirs, files in os.walk(search_dir):
        tar_path = find_newest_tar_gz(root)
        if tar_path:
            # Start with an empty extraction directory for each archive.
            if os.path.exists(extract_dir):
                subprocess.run(['rm', '-rf', extract_dir])
            os.makedirs(extract_dir, exist_ok=True)
            extract_and_count_lines(tar_path, extract_dir)

if __name__ == "__main__":
    main()
