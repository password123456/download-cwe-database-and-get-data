# download-cwe-database-and-get-data
![made-with-python][made-with-python]
![Python Versions][pyversion-button]
[![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Fpassword123456%2Fdownload-cwe-database-and-get-data%2F&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=hits&edge_flat=false)](https://hits.seeyoufarm.com)

[pyversion-button]: https://img.shields.io/pypi/pyversions/Markdown.svg
[made-with-python]: https://img.shields.io/badge/Made%20with-Python-1f425f.svg

- Download latest CWE database, open > read > parse data > convert to JSON format
- If you find this helpful, please the **"star"**:star2: to support further improvements.

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

## Step 4: Get the key using xmlstarlet
-  ID, Name, Description
```bash 
# xmlstarlet sel -N ns=http://cwe.mitre.org/cwe-7 -t -m "//ns:Weakness" -v "concat(@ID, ',', @Name, ',', ns:Description, ',', ns:Extended_Description)" -n -n "cwec_v4.14.xml"
```

## Step 5: Let's make simple shell script 
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

## Step 6: OK. Implementing Parsing in Python 
```python
# python main.py

[+] Downloading: cwec_latest.xml.zip
[+] Downloaded: cwec_latest.xml.zip / 1.64 MB
[+] Extracting download file: cwec_latest.xml.zip
[+] CWE XML file path: /code/cwe_parser/download/cwec_v4.14.xml
[+] Extracting keys from XML: ID, Name, Description, Extended Description
 ----> Data parsing... Done
[+] Successfully created JSON: /code/cwe_parser/cwe_lookup_table.json
```
- cwe_lookup_table.json
```json
{
    "1004": {
        "Id:": "CWE-1004",
        "Name": "Sensitive Cookie Without 'HttpOnly' Flag",
        "Description": "The product uses a cookie to store sensitive information, but the cookie is not marked with the HttpOnly flag.",
        "Extended_Description": "The HttpOnly flag directs compatible browsers to prevent client-side script from accessing cookies. Including the HttpOnly flag in the Set-Cookie HTTP response header helps mitigate the risk associated with Cross-Site Scripting (XSS) where an attacker's script code might attempt to read the contents of a cookie and exfiltrate information obtained. When set, browsers that support the flag will not reveal the contents of the cookie to a third party via client-side script executed via XSS."
    },
    "1007": {
        "Id:": "CWE-1007",
        "Name": "Insufficient Visual Distinction of Homoglyphs Presented to User",
        "Description": "The product displays information or identifiers to a user, but the display mechanism does not make it easy for the user to distinguish between visually similar or identical glyphs (homoglyphs), which may cause the user to misinterpret a glyph and perform an unintended, insecure action.",
        "Extended_Description": " Some glyphs, pictures, or icons can be semantically distinct to a program, while appearing very similar or identical to a human user. These are referred to as homoglyphs. For example, the lowercase \"l\" (ell) and uppercase \"I\" (eye) have different character codes, but these characters can be displayed in exactly the same way to a user, depending on the font. This can also occur between different character sets. For example, the Latin capital letter \"A\" and the Greek capital letter \"\u0391\" (Alpha) are treated as distinct by programs, but may be displayed in exactly the same way to a user. Accent marks may also cause letters to appear very similar, such as the Latin capital letter grave mark \"\u00c0\" and its equivalent \"\u00c1\" with the acute accent. Adversaries can exploit this visual similarity for attacks such as phishing, e.g. by providing a link to an attacker-controlled hostname that looks like a hostname that the victim trusts. In a different use of homoglyphs, an adversary may create a back door username that is visually similar to the username of a regular user, which then makes it more difficult for a system administrator to detect the malicious username while reviewing logs. "
    },
    "102": {
        "Id:": "CWE-102",
        "Name": "Struts: Duplicate Validation Forms",
        "Description": "The product uses multiple validation forms with the same name, which might cause the Struts Validator to validate a form that the programmer does not expect.",
        "Extended_Description": "If two validation forms have the same name, the Struts Validator arbitrarily chooses one of the forms to use for input validation and discards the other. This decision might not correspond to the programmer's expectations, possibly leading to resultant weaknesses. Moreover, it indicates that the validation logic is not up-to-date, and can indicate that other, more subtle validation errors are present."
    },
    "1021": {
        "Id:": "CWE-1021",
        "Name": "Improper Restriction of Rendered UI Layers or Frames",
        "Description": "The web application does not restrict or incorrectly restricts frame objects or UI layers that belong to another application or domain, which can lead to user confusion about which interface the user is interacting with.",
        "Extended_Description": "A web application is expected to place restrictions on whether it is allowed to be rendered within frames, iframes, objects, embed or applet elements. Without the restrictions, users can be tricked into interacting with the application when they were not intending to."
    },
    "1022": {
        "Id:": "CWE-1022",
        "Name": "Use of Web Link to Untrusted Target with window.opener Access",
        "Description": "The web application produces links to untrusted external sites outside of its sphere of control, but it does not properly prevent the external site from modifying  security-critical properties of the window.opener object, such as the location property.",
        "Extended_Description": "When a user clicks a link to an external site (\"target\"), the target=\"_blank\" attribute causes the target site's contents to be opened in a new window or tab, which runs in the same process as the original page. The window.opener object records information about the original page that offered the link. If an attacker can run script on the target page, then they could read or modify certain properties of the window.opener object, including the location property - even if the original and target site are not the same origin. An attacker can modify the location property to automatically redirect the user to a malicious site, e.g. as part of a phishing attack. Since this redirect happens in the original window/tab - which is not necessarily visible, since the browser is focusing the display on the new target page - the user might not notice any suspicious redirection."
    }
}
```

  
