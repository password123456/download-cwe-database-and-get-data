__author__ = 'https://github.com/password123456/'
__date__ = '2024.03.15'
__version__ = '1.0.0'
__status__ = 'Production'

import os
import sys
import re
import json
import requests
import zipfile
import xml.etree.ElementTree as ET

import time

class Bcolors:
    Black = '\033[30m'
    Red = '\033[31m'
    Green = '\033[32m'
    Yellow = '\033[33m'
    Blue = '\033[34m'
    Magenta = '\033[35m'
    Cyan = '\033[36m'
    White = '\033[37m'
    Endc = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def download_file(url):
    file_name = url.split('/')[-1]
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
                             'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
               'Connection': 'keep-alive'}
    print(f'{Bcolors.Green}[+] Downloading:{Bcolors.Endc} {file_name}')
    r = requests.get(url, headers=headers, verify=True)
    if r.status_code == 200:
        download_file_length = r.headers.get('Content-Length')
        print(f'{Bcolors.Green}[+] Downloaded:{Bcolors.Endc} {file_name} / {(float(download_file_length) / (1024.0 * 1024.0)):.2f} MB')
        with open(file_name, 'wb') as f:
            f.write(r.content)
    else:
        message = (f'\n - {os.path.realpath(__file__)}\n'
                   f' - [FUNC]: {download_file.__name__}\n'
                   f' - [MSG]: HTTP status: {r.status_code} / {url}')
        print(f'{Bcolors.Yellow}[!] Error: {message} {Bcolors.Endc}\n\n')
        sys.exit(1)
    return file_name


def extract_zip(zip_file, extract_dir):
    with zipfile.ZipFile(zip_file, 'r') as zip_ref:
        print(f'{Bcolors.Green}[+] Extracting download file:{Bcolors.Endc} {zip_file}')
        zip_ref.extractall(extract_dir)

    extracted_files = zip_ref.namelist()
    xml_file_name = [file for file in extracted_files if file.endswith('.xml')][0]
    xml_file_path = os.path.join(extract_dir, xml_file_name)
    print(f'{Bcolors.Green}[+] CWE XML file path:{Bcolors.Endc} {xml_file_path}')
    return xml_file_path


def parse_cwe_xml(xml_file):
    tree = ET.parse(xml_file)
    namespaces = {'ns': 'http://cwe.mitre.org/cwe-7'}
    weakness_elements = tree.findall('.//ns:Weakness', namespaces)
    data = {}
    print(f'{Bcolors.Green}[+] Extracting keys from XML:{Bcolors.Endc} ID, Name, Description, Extended Description')
    print(' ----> Data parsing...', end='', flush=True)
    for weakness in weakness_elements:
        cwe_num = weakness.get('ID')
        name = weakness.get('Name')
        cwe_id = f'CWE-{cwe_num}'

        description_element = weakness.find('./ns:Description', namespaces)
        description = description_element.text if description_element is not None else None

        extended_description_element = weakness.find('./ns:Extended_Description', namespaces)
        if extended_description_element is not None:
            extended_description = ''.join(extended_description_element.itertext())
            extended_description = re.sub(r'\s+', ' ', extended_description)
        else:
            extended_description = None

        data[cwe_num] = {
            "Id:": cwe_id,
            "Name": name,
            "Description": description,
            "Extended_Description": extended_description
        }

    print(' Done')  # Print once parsing is completed
    return data


def parse_data_to_json(data):
    export_path = f'{os.path.dirname(os.path.realpath(__file__))}/cwe_lookup_table.json'
    with open(export_path, 'w') as json_file:
        json.dump(data, json_file, indent=4)
    print(f'{Bcolors.Green}[+] Successfully created JSON:{Bcolors.Endc} {export_path}')


def main():
    # Download CWE database
    download_filename = download_file('https://cwe.mitre.org/data/xml/cwec_latest.xml.zip')

    # Extract the downloaded file
    extracted_dir = f'{os.path.dirname(os.path.realpath(__file__))}/download'
    extracted_file_path = extract_zip(download_filename, extracted_dir)

    # Parse CWE database and convert format to JSON
    parse_data = parse_cwe_xml(extracted_file_path)

    # Parse data to JSON
    parse_data_to_json(parse_data)

    # Remove extracted files and directory
    os.remove(download_filename)
    os.remove(extracted_file_path)
    os.rmdir(extracted_dir)


if __name__ == "__main__":
    main()
