# NetXMLTools
NetXML.py is an API that can parse the contents of a NetXML document. The NetXML standard is commonly used in wireless sniffing tools (e.g., kismet and airodump-ng) and stores information regarding any discovered wireless networks. The NetXML.py module creates major NetXML classes with an emphasis on type safety, serializability, and de-serializability. You can process a NetXML document using the iterparse function.

## Dependencies

Python (tested on Python 2.7 and 3.4)

## NetXML.py

An API to parse a NetXML document. The NetXML document is parsed and returned. You can read a document using:

`import NetXML`

`netxml = NetXML.iterparse(filename)`

## NetXML_MakeCSV.py

Create a CSV file from a NetXML file:

`python3.4 NetXML_MakeCSV.py Kismet-20150505-05-15-05-1.netxml`

## NetXML_Summary.py

Parses a NetXML file and prints a summary of encryption, channel count, and manufacturer count:

`python3.4 NetXML_Summary.py Kismet-20150505-05-15-05-1.netxml`
