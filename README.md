# NetXMLTools
NetXML.py is an API that can parse the contents of a NetXML document. The NetXML standard is commonly used in wireless sniffing tools (e.g., kismet and airodump-ng) and stores information regarding any discovered wireless networks. The NetXML.py module creates major NetXML classes with an emphasis on type safety, serializability, and de-serializability. You can process a NetXML document using the iterparse function.

## Dependencies

Python (tested on Python 2.7 and 3.5)

## NetXML.py

An API to parse a NetXML document. The NetXML document is parsed, all XML elements (tags) are populated into a selection of various Python objects and the parent NetXMLObject is returned. You can read a document using:

`import NetXML`

`netxml = NetXML.iterparse(filename)`

From here, you can iterate through each wireless network (e.g., infrastructure Access Point or ad-hoc probe network) and the associated wireless clients (e.g., laptops). You can iterature through the original NetXMLObject and access details about the wireless devices such as network addresses, network names and network channel. For example, the following code imports the NetXML API, reads the user supplied NetXML file given as a command line argument, iterates thrrough all contents and prints the BSSID (MAC address), ESSID (network name) and AP channel for each wireless network in the original NetXML file.

```python
import sys
import NetXML
netxml = NetXML.iterparse(sys.argv[1])
for wn in netxml:
   if isinstance(wn, NetXML.WirelessNetwork):
       print(wn.bssid, wn.ssid.essid, wn.channel)
```

## NetXML_MakeCSV.py

Create a CSV file from a NetXML file:

`python3.4 NetXML_MakeCSV.py Kismet-20150505-05-15-05-1.netxml`
