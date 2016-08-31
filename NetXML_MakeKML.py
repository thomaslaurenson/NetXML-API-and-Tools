# !/usr/bin/python

"""
Author:  Thomas Laurenson
Email:   thomas@thomaslaurenson.com
Website: thomaslaurenson.com
Date:    2016/08/31

Description:
Convert a NetXML file into a KML file using the NetXML.py API.

Copyright (c) 2016, Thomas Laurenson

###############################################################################
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
###############################################################################

>>> CHANGELOG:
    0.1.0       Base functionality
"""

__version__ = "0.1.0"

import os
import sys
import math
import collections
from xml.sax.saxutils import escape

import NetXML

################################################################################
if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser(description='''NetXML_MakeKML.py''')
    parser.add_argument("netxml_file",
                        help = "Target NetXML file (e.g. Kismet-20150506-08-23-31-1.netxml)")
    parser.add_argument("--known_macs",
                        action = 'store',
                        help = "Text file of known MACs/BSSIDs to ignore")
    args = parser.parse_args()

    # Fetch input NetXML file name
    fn = os.path.splitext(os.path.basename(args.netxml_file))[0] 
    print(">>> %s" % fn)
    
    # If requested remove specific MACs/BSSIDs from output KML file
    known_macs = list()
    if args.known_macs:
        with open(args.known-macs) as f:
            for l in f:
                l = l.strip()
                known_macs.append(l)

    # Parse NetXML file using NetXML.iterparse function
    netxml = NetXML.iterparse(args.netxml_file)
    
    # Classify WirelessNetworks based on encryption
    networks = collections.defaultdict(list)
    for wn in netxml:
        if isinstance(wn, NetXML.WirelessNetwork):
            if wn.ssid.wpa_version == "WPA+WPA2":
                 networks["WPA2"].append(wn)
            elif wn.ssid.wpa_version == "WPA2":
                 networks["WPA2"].append(wn)
            elif wn.ssid.wpa_version == "WPA":
                 networks["WPA"].append(wn)
            elif wn.ssid.privacy == None:
                 # Skip networks without knwon encryption
                 continue
            else:
                networks[wn.ssid.privacy].append(wn)
    
    # Print overview of networks to stdout
    print("  > {0:<12s}\t{1:<6s}".format("Encryption", "Count"))
    for k,v in networks.items():
        print("  > {0:<12s}\t{1:<6d}".format(k, len(networks[k])))
    
    # Setup an output KML file for each encryption type
    out_fn = fn + ".kml"
    f = open(out_fn, 'w')    
    
    # Print KML header, with dynamic file name
    f.write("<?xml version='1.0' encoding='UTF-8'?>\n")
    f.write("<kml xmlns='http://www.opengis.net/kml/2.2'>\n")
    f.write("  <Document>\n")
    
    # Define styles for KML document
    f.write("    <Style id='greenpin'>\n")
    f.write("      <IconStyle>\n")
    f.write("        <Icon>\n")
    f.write("          <href>http://maps.google.com/mapfiles/kml/pushpin/grn-pushpin.png</href>\n")
    f.write("        </Icon>\n")
    f.write("      </IconStyle>\n")
    f.write("    </Style>\n")
    f.write("    <Style id='yellowpin'>\n")
    f.write("      <IconStyle>\n")
    f.write("        <Icon>\n")
    f.write("          <href>http://maps.google.com/mapfiles/kml/pushpin/ylw-pushpin.png</href>\n")
    f.write("        </Icon>\n")
    f.write("      </IconStyle>\n")
    f.write("    </Style>\n")
    f.write("    <Style id='redpin'>\n")
    f.write("      <IconStyle>\n")
    f.write("        <Icon>\n")
    f.write("          <href>http://maps.google.com/mapfiles/kml/pushpin/red-pushpin.png</href>\n")
    f.write("        </Icon>\n")
    f.write("      </IconStyle>\n")
    f.write("    </Style>\n")
    f.write("    <Style id='whitepin'>\n")
    f.write("      <IconStyle>\n")
    f.write("        <Icon>\n")
    f.write("          <href>http://maps.google.com/mapfiles/kml/pushpin/wht-pushpin.png</href>\n")
    f.write("        </Icon>\n")
    f.write("      </IconStyle>\n")
    f.write("    </Style>\n")  
    
    f.write("    <name>%s</name>\n" % out_fn)
    f.write("    <description><![CDATA[]]></description>\n")        
      
    # Print WirelessNetworks in KML format to stdout
    for encryption in networks:

        # Start KML folder structure for each encryption type
        f.write("    <Folder>\n") 
        f.write("    <name>%s: %d networks</name>\n" % (encryption, 
                                                        len(networks[encryption])))

        # Loop through networks based on encryption type
        for network in networks[encryption]:
            
            # Filter knwon MACs/BSSID if requested
            if args.known_macs:
                if network.bssid in known_macs:
                    continue
            
            # First, determine encryption type, and map icon to use
            # GREEN = WPA2, YELLOW = WPA, RED = WEP, WHITE = OPEN
            if encryption == "WPA2":
                style = "#greenpin"
            elif encryption == "WPA":
                style = "#yellowpin"
            elif encryption == "WEP":
                style = "#redpin"    
            else:
                style = "#whitepin"     
                
            if network.ssid.essid:
                essid = escape(network.ssid.essid)
            else:
                essid = network.ssid.essid
                
            if network._gps:
                lat = network._gps.avg_lat
                lon = network._gps.avg_lon
            else:
                lat = 0.0
                lon = 0.0     
            
            # Create and print a placemark element for each network
            f.write("      <Placemark>\n")
            f.write("        <name>%s</name>\n" % essid)
            f.write("        <description><![CDATA[SSID: %s<br> MAC: %s<br> Manuf: %s<br> Type: %s<br> Channel: %s<br> Encryption: %s<br> Last time: %s<br> GPS: %s,%s]]></description>\n" % (essid, network.bssid, network.manuf, network.network_type, network.channel, ";".join(network.ssid.encryption), str(network.last_time), lat, lon))
            f.write("        <styleUrl>%s</styleUrl>\n" % style)
            f.write("        <Point>\n")
            f.write("          <coordinates>%s,%s,0.0</coordinates>\n" % (lon, lat))
            f.write("        </Point>\n")
            f.write("      </Placemark>\n")
            
        # Close KML Folder element
        f.write("    </Folder>\n")
      
    # Finally, close document and kml elements
    f.write("  </Document>\n")        
    f.write("</kml>\n")
    f.close()
