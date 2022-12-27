import os
import re
import csv
import argparse
import logging
import hashlib
import PyPDF2
import ntpath

from PyPDF2.errors import PdfReadError
from urllib.parse import quote
from datetime import datetime

DATE_REGEX = re.compile("^\d{4}\.\d{2}\.\d{2}")
DOWN_BASE_PATH = (
    "https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/raw/master/"
)

processed_reports_list = []


def get_file_sha1_hash(path: str) -> str:
    hash_sha1 = hashlib.sha1()
    with open(path, "rb") as f:
        buf = f.read()
        hash_sha1.update(buf)
    return hash_sha1.hexdigest()


def index_report(path: str):
    checksum = get_file_sha1_hash(path)
    down_path = DOWN_BASE_PATH + quote(path)

    # Get the published date from the path name if possible
    published_raw = DATE_REGEX.match(os.path.basename(os.path.dirname(path)))
    pypdf = PyPDF2.PdfReader(open(path, "rb"), strict=False)

    if published_raw == None or (".00" in published_raw.group(0)):
        logging.debug(f"no published date for report: {path}")

        if pypdf.is_encrypted:
            pypdf.decrypt("")
        try:
            cdate = pypdf.metadata.creation_date
            if cdate != None:
                published = pypdf.metadata.creation_date.date()
            else:
                published = datetime.min.date()
        except (KeyError, ValueError, PdfReadError) as derr:
            logging.error(f"no date for report: {path} | {derr}")
            return
    else:
        logging.debug(published_raw)
        published = datetime.strptime(published_raw.group(0), "%Y.%m.%d").date()

    title = ntpath.basename(path).replace(".pdf", "").replace(".PDF", "")

    processed_reports_list.append((published, checksum, title, down_path))


def process_reports(path: str):
    # Recurse the given path to find PDF reports
    report_list = []

    for path, subdirs, files in os.walk(path):
        for filepath in files:
            full_path = os.path.join(path, filepath)
            if not filepath.endswith(".pdf"):
                continue
            try:
                PyPDF2.PdfReader(open(full_path, "rb"))
                rel_dir = os.path.relpath(path, os.getcwd())
                rel_file = os.path.join(rel_dir, filepath)
                report_list.append(rel_file)
            except Exception as perr:
                logging.debug(f"invalid or not a PDF file: {full_path} {perr}")
                continue
            logging.debug(f"processing {full_path}")

    for rep in report_list:
        logging.debug(f"processing {rep}")
        index_report(rep)

    with open("index.csv", "w", newline="") as csvfile:
        sorted_reports = sorted(processed_reports_list, key=lambda x: (x[0], x[1]))
        fieldnames = ["Published", "SHA-1", "Filename", "Download URL"]
        indexwriter = csv.writer(csvfile, dialect="excel")
        indexwriter.writerow(fieldnames)
        indexwriter.writerows(sorted_reports)


# ARGPARSE
arg_parser = argparse.ArgumentParser(description="Index documents in Repository")
arg_parser.add_argument(
    "-p", "--path", help="Path to the document repository", default=os.getcwd()
)
arg_parser.add_argument(
    "-d", "--debug", action="store_true", help="print debug messages"
)
args = arg_parser.parse_args()


def main():
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    process_reports(args.path)


if __name__ == "__main__":
    main()
