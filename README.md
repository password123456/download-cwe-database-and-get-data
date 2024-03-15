# download-cwe-database-and-get-data
![made-with-python][made-with-python]
![Python Versions][pyversion-button]
[![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Fpassword123456%2Fdownload-cwe-database-and-get-data%2F&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=hits&edge_flat=false)](https://hits.seeyoufarm.com)

[pyversion-button]: https://img.shields.io/pypi/pyversions/Markdown.svg
[made-with-python]: https://img.shields.io/badge/Made%20with-Python-1f425f.svg

- Download latest CWE database and open > parse data > convert to JSON format

## Step 1: download CWE database from cwe.mitre.org, if necessary
```bash
# wget https://cwe.mitre.org/data/xml/cwec_latest.xml.zip

- There are four types of databases, and you can choose one: XML Content, Published, Schema, Documentation.
- People usually prefer the XML Content type as it is the easiest to process for arbitrary data manipulation.
- As of March 15, 2024, the download path for the XML database is:
  https://cwe.mitre.org/data/xml/cwec_latest.xml.zip (Download URL may change.)
```

## Step 2: Extract the downloaded file
```bash
# unzip cwec_latest.xml.zip
```

## Step 3: Install xmlstarlet
```bash
# apt-get install xmlstarlet
```

## Step 4: get the key using xmlstarlet
-  ID, Name, Description
```bash 
# xmlstarlet sel -N ns=http://cwe.mitre.org/cwe-7 -t -m "//ns:Weakness" -v "concat(@ID, ',', @Name, ',', ns:Description, ',', ns:Extended_Description)" -n -n "cwec_v4.14.xml"
```

## Step 5: make simple shell script 
- cwe_parser.sh
```bash
#!/bin/bash

xml_file="cwec_v4.14.xml"
xmlns="http://cwe.mitre.org/cwe-7"

ids=$(xmlstarlet sel -N ns="$xmlns" -t -m "//ns:Weakness" -v "@ID" -n "$xml_file")
names=$(xmlstarlet sel -N ns="$xmlns" -t -m "//ns:Weakness" -v "@Name" -n "$xml_file")
descriptions=$(xmlstarlet sel -N ns="$xmlns" -t -m "//ns:Weakness" -v "ns:Description" -n "$xml_file")

echo "Extracted Data:"
echo "----------------------------------------"
for i in $(seq $(echo "$ids" | wc -l)); do
    id=$(echo "$ids" | sed -n "${i}p")
    name=$(echo "$names" | sed -n "${i}p")
    description=$(echo "$descriptions" | sed -n "${i}p")

    echo "1. ID: $id"
    echo "2. NAME: $name"
    echo "3. DESCRIPTION: $description"
    echo "----------------------------------------"
done > result.txt
```
- result.txt
```bash
# cat result.txt

ID: 1004
NAME: Sensitive Cookie Without 'HttpOnly' Flag
DESCRIPTION: The product uses a cookie to store sensitive information, but the cookie is not marked with the HttpOnly flag.
----------------------------------------
ID: 1007
NAME: Insufficient Visual Distinction of Homoglyphs Presented to User
DESCRIPTION: The product displays information or identifiers to a user, but the display mechanism does not make it easy for the user to dist
inguish between visually similar or identical glyphs (homoglyphs), which may cause the user to misinterpret a glyph and perform an unintende
d, insecure action.
----------------------------------------
ID: 102
NAME: Struts: Duplicate Validation Forms
DESCRIPTION: The product uses multiple validation forms with the same name, which might cause the Struts Validator to validate a form that t
he programmer does not expect.
----------------------------------------
```

## Step 6: Implementing Parsing in Python 
```
# python main.py

[+] Downloading: cwec_latest.xml.zip
[+] Downloaded: cwec_latest.xml.zip / 1.64 MB
[+] Extracting download file: cwec_latest.xml.zip
[+] CWE XML file path: /Users/jeonghyun.hwang/PycharmProjects/get_nvd_cve_cvss6_over/download/cwec_v4.14.xml
[+] Extracting keys from XML: ID, Name, Description, Extended Description
 ----> Data parsing... Done
[+] Successfully created JSON: /Users/jeonghyun.hwang/PycharmProjects/get_nvd_cve_cvss6_over/cwe_lookup_table.json
```
