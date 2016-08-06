# !/usr/bin/python

"""
Author:  Thomas Laurenson
Email:   thomas@thomaslaurenson.com
Website: thomaslaurenson.com
Date:    2016/08/07

Description:
NetXML.py is an API that can parse the contents of a NetXML document. The
NetXML standard is commonly used in wireless sniffing tools (e.g., kismet and
airodump-ng) and stores information regarding any discovered wireless networks.
The NetXML.py module creates major NetXML classes with an emphasis on type
safety, serializability, and de-serializability. You can process a NetXML
document using the iterparse function.

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
import datetime
import xml.etree.ElementTree as ET

################################################################################
def _qsplit(tagname):
    """ Returns namespace and local tag name as a pair. """
    _typecheck(tagname, str)
    if tagname[0] == "{":
        i = tagname.rfind("}")
        return (tagname[1:i], tagname[i+1:])
    else:
        return (None, tagname)

def _typecheck(obj, classinfo):
    """ Check the Object type. """
    if not isinstance(obj, classinfo):
        _logger.info("obj = " + repr(obj))
        if isinstance(classinfo, tuple):
            raise TypeError("Expecting object to be one of the types %r." % (classinfo,))
        else:
            raise TypeError("Expecting object to be of type %r." % classinfo)

def _strcast(val):
    """ Convert value to string. """
    if val is None:
        return None
    return str(val)

def _intcast(val):
    """ Convert input string to integer. Preserves nulls. """
    if val is None:
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        if val[0] == "-":
            if val[1:].isdigit():
                return int(val)
        else:
            if val.isdigit():
                return int(val)
                
def _floatcast(val):
    """ Convert input string to float. Preserves nulls. """
    if val is None:
        return None
    if isinstance(val, float):
        return val
    if isinstance(val, str):
        # A proper float check should be performed here
        # we are assuming a str is being passed that can be cast
        return float(val)                

def _boolcast(val):
    """ Convert value to boolean object. """
    if val is None:
        return None
    elif val in [True, "True", "true"]:
        return True
    elif val in [False, "False", "false"]:
        return False

def _datecast(val):
    """ Convert string time value to datetime object. """
    if val is None:
        return None
    return datetime.datetime.strptime(val, "%a %b  %d %H:%M:%S %Y")
    
################################################################################
class NetXML(object):
    def __init__(self, **kwargs):
        self.name = kwargs.get("filename")
        self.kismet_version = kwargs.get("kismet-version")
        self.start_time = kwargs.get("start-time")
        self.card_source = None
        self._WirelessNetworks = []
        self._WirelessClients = []

    def __iter__(self):
        """ Yields all wireless networks (wn) and wireless clients (wc) """
        for wn in self._WirelessNetworks:
            yield wn
            for wc in wn:
                yield wc
        for wc in self._WirelessClients:
            yield wc

    def append(self, value):
        if isinstance(value, WirelessNetwork):
            self._WirelessNetworks.append(value)
        elif isinstance(value, WirelessClient):
            self._WirelessClients.append(value)
        else:
            raise TypeError("Expecting: WirelessNetwork or Wirelessclient; Got %r." % type(value))

################################################################################
class CardSource(object):
    def __init__(self, **kwargs):
        self.uuid = kwargs.get("uuid")
        for prop in self._all_properties:
            setattr(self, prop, kwargs.get(prop))

    _all_properties = set(["card_name",
                           "card_interface",
                           "card_type",
                           "card_packets",
                           "card_hop",
                           "card_channels"])

    def populate_from_Element(self, e):
        _typecheck(e, (ET.Element, ET.ElementTree))
        (ns, tn) = _qsplit(e.tag)
        assert tn in ["card-source"]
        for ce in e.findall("./*"):
            (cns, ctn) = _qsplit(ce.tag)
            if "-" in ctn:
                ctn = ctn.replace("-", "_")
            if ctn in self._all_properties:
                setattr(self, ctn, ce.text)

################################################################################
class WirelessNetwork(object):
    def __init__(self, **kwargs):
        self.netxml_type = "network"
        self.number = kwargs.get("number")
        self.network_type = kwargs.get("type")
        self.first_time = _datecast(kwargs.get("first-time"))
        self.last_time = _datecast(kwargs.get("last-time"))
        self._freqmhz = list()
        self._encryption = list()
        self._ssid = None
        self._packets = None
        self._snr = None
        self._gps = None
        self._WirelessClients = list()
        
        # Initialise WirelessNetwork attributes
        for prop in self._all_properties:
            setattr(self, prop, kwargs.get(prop))
        # Initialise SSID object
        for prop in SSIDObject._all_properties:
            setattr(self, prop, kwargs.get(prop))
        # Initialise Packets object
        for prop in PacketsObject._all_properties:
            setattr(self, prop, kwargs.get(prop))            
        # Initialise SnrInfo object
        for prop in SnrInfoObject._all_properties:
            setattr(self, prop, kwargs.get(prop))
        # Initialise GPS object
        for prop in GPSInfoObject._all_properties:
            setattr(self, prop, kwargs.get(prop))                        

    def __iter__(self):
        """ Yields all WirelessClients. """
        for f in self._WirelessClients:
            yield f

    _all_properties = set(["bssid",
                           "bsstimestamp",
                           "carrier",
                           "cdp_device",
                           "cdp_portid",
                           "channel",
                           "datasize",
                           "encoding",
                           "manuf",
                           "maxseenrate"])

    def populate_from_Element(self, e):
        # Populate object from ET element
        _typecheck(e, (ET.Element, ET.ElementTree))
        (ns, tn) = _qsplit(e.tag)
        assert tn in ["wireless-network"]
        for ce in e.findall("./*"):
            # Find all properties for Wireless Network
            (cns, ctn) = _qsplit(ce.tag)
            ctn = ctn.lower()
            if "-" in ctn:
                ctn = ctn.replace("-", "_")
            
            # Parse the SSID element and children
            if ctn == "ssid":
                ssid = SSIDObject(**e.attrib)
                ssid.populate_from_Element(ce)
                self._ssid = ssid            
                                
            # Parse the packets element and children
            elif ctn == "packets":
                packets = PacketsObject(**e.attrib)
                packets.populate_from_Element(ce)
                self._packets = packets                  
            
            # Parse the snr-info (signal) element and children
            elif ctn == "snr_info":
                snr = SnrInfoObject(**e.attrib)
                snr.populate_from_Element(ce)
                self._snr = snr                    
                
            # Parse the GPS element and children
            elif ctn == "gps_info":
                gps = GPSInfoObject(**e.attrib)
                gps.populate_from_Element(ce)
                self._gps = gps                   
                
            # Parse any attached Wireless Clients
            elif ctn == "wireless_client":
                #wc = WirelessClient(**e.attrib)
                # Above was removed, fetched network attributes, not client!
                wc = WirelessClient()
                wc.populate_from_Element(ce, self.number)
                self._WirelessClients.append(wc)
                                
            elif ctn == "freqmhz":
                self._freqmhz.append(ce.text)
            
            elif ctn in WirelessNetwork._all_properties:
                setattr(self, ctn, ce.text)
        
        # After looping all XML tags, if there is no SSID
        # object, create an empty one      
        if self.ssid == None:
            ssid = SSIDObject(**e.attrib)
            ssid.populate_empty_object()
            self._ssid = ssid

    # WirelessNetwork property getters and setters
    @property
    def bssid(self):
        return self._bssid

    @bssid.setter
    def bssid(self, value):
        self._bssid = _strcast(value)

    @property
    def bsstimestamp(self):
        return self._bsstimestamp

    @bsstimestamp.setter
    def bsstimestamp(self, value):
        self._bsstimestamp = _strcast(value)

    @property
    def carrier(self):
        return self._carrier

    @carrier.setter
    def carrier(self, value):
        self._carrier = _strcast(value)

    @property
    def cdp_device(self):
        return self._cdp_device

    @cdp_device.setter
    def cdp_device(self, value):
        self._cdp_device = _strcast(value)

    @property
    def cdp_portid(self):
        return self._cdp_portid

    @cdp_portid.setter
    def cdp_portid(self, value):
        self._cdp_portid = _strcast(value)

    @property
    def channel(self):
        return self._channel

    @channel.setter
    def channel(self, value):
        self._channel = _intcast(value)

    @property
    def datasize(self):
        return self._datasize

    @datasize.setter
    def datasize(self, value):
        self._datasize = _intcast(value)

    @property
    def encoding(self):
        return self._encoding

    @encoding.setter
    def encoding(self, value):
        self._encoding = _strcast(value)

    @property
    def first_time(self):
        return self._first_time

    @first_time.setter
    def first_time(self, value):
        if not value is None:
            _typecheck(value, datetime.datetime)
        self._first_time = value

    @property
    def freqmhz(self):
        return self._freqmhz

    @freqmhz.setter
    def freqmhz(self, value):
        freq = _strcast(value)
        self._freqmhz.append(freq)

    @property
    def last_time(self):
        return self._last_time

    @last_time.setter
    def last_time(self, value):
        if not value is None:
            _typecheck(value, datetime.datetime)
        self._last_time = value

    @property
    def manuf(self):
        return self._manuf

    @manuf.setter
    def manuf(self, value):
        self._manuf = _strcast(value)

    @property
    def maxseenrate(self):
        return self._maxseenrate

    @maxseenrate.setter
    def maxseenrate(self, value):
        self._maxseenrate = _intcast(value)

    @property
    def network_type(self):
        return self._network_type

    @network_type.setter
    def network_type(self, value):
        self._network_type = _strcast(value)

    @property
    def number(self):
        return self._number

    @number.setter
    def number(self, value):
        self._number = _intcast(value)

    @property
    def ssid(self):
        return self._ssid

    @ssid.setter
    def ssid(self, value):
        if not value is None:
            _typecheck(value, SSIDObject)
        self._ssid = value
        
################################################################################
class WirelessClient(object):
    def __init__(self, **kwargs):
        self.netxml_type = "client"
        # Initially, set attribute to None
        self.number = None
        self.type = None
        self.first_time = None
        self.last_time = None
        # Initialise client XML child elements
        self._ssid = None
        self._freqmhz = list()
        self._encryption = list()
        # Initially, set parent network number to None
        self.network_number = None        
        
        # Initialise WirelessClient attributes
        for prop in self._all_properties:
            setattr(self, prop, kwargs.get(prop))
        # Initialise SSID object
        for prop in SSIDObject._all_properties:
            setattr(self, prop, kwargs.get(prop))
        # Initialise Packets object
        for prop in PacketsObject._all_properties:
            setattr(self, prop, kwargs.get(prop))            
        # Initialise SnrInfo object
        for prop in SnrInfoObject._all_properties:
            setattr(self, prop, kwargs.get(prop))
        # Initialise GPS object
        for prop in GPSInfoObject._all_properties:
            setattr(self, prop, kwargs.get(prop))

    # All possible WirelessClient XML elements
    _all_properties = set(["client_mac",
                           "client_manuf",
                           "channel",
                           "maxseenrate",
                           "datasize",
                           "encoding",
                           "carrier"])
                           
    # All possible WirelessClient XML attributes
    _all_attributes = set(["number",
                           "type",
                           "first_time",
                           "last_time"])                                                       

    def populate_from_Element(self, e, number):
        # Populate a WirelessClient object from given ET element
        # Set parent network number to supplied number
        self.network_number = number
        # Check we have an ET element
        _typecheck(e, (ET.Element, ET.ElementTree))
        # Split XML tag and check we have a "wireless-client"
        (ns, tn) = _qsplit(e.tag)
        assert tn in ["wireless-client"]
        
        # Parse wireless-client attributes
        for attrib in e.attrib:
            if attrib in WirelessClient._all_attributes:
                if "-" in attrib:
                    attrib_fix = attrib.replace("-", "_")  
                    setattr(self, attrib_fix, e.get(attrib))
                else:
                    setattr(self, attrib, e.get(attrib))

        # Parse wireless-client XML tags
        for ce in e.findall("./*"):
            (cns, ctn) = _qsplit(ce.tag)
            ctn = ctn.lower()
            if "-" in ctn:
                ctn = ctn.replace("-", "_")
            
            # Parse the SSID element and children
            if ctn == "ssid":
                ssid = SSIDObject(**e.attrib)
                ssid.populate_from_Element(ce)
                self._ssid = ssid            
                                
            # Parse the packets element and children
            elif ctn == "packets":
                packets = PacketsObject(**e.attrib)
                packets.populate_from_Element(ce)
                self._packets = packets                  
            
            # Parse the snr-info (signal) element and children
            elif ctn == "snr_info":
                snr = SnrInfoObject(**e.attrib)
                snr.populate_from_Element(ce)
                self._snr = snr                    
                
            # Parse the GPS element and children
            elif ctn == "gps_info":
                gps = GPSInfoObject(**e.attrib)
                gps.populate_from_Element(ce)
                self._gps = gps
            
            # Parse client frequency, may be multiple, so append to list
            elif ctn == "freqmhz":
                self._freqmhz.append(ce.text)

            # Parse all remaining wireless-client properties
            elif ctn in WirelessClient._all_properties:
                setattr(self, ctn, ce.text)            

        # After looping all XML tags, if there is no SSID
        # object, create an empty one      
        if self._ssid == None:
            ssid = SSIDObject(**e.attrib)
            ssid.populate_empty_object()
            self._ssid = ssid
            
    # WirelessClient property getters and setters
    @property
    def carrier(self):
        return self._carrier

    @carrier.setter
    def carrier(self, value):
        self._carrier = _strcast(value)

    @property
    def cdp_device(self):
        return self._cdp_device

    @cdp_device.setter
    def cdp_device(self, value):
        self._cdp_device = _strcast(value)

    @property
    def cdp_portid(self):
        return self._cdp_portid

    @cdp_portid.setter
    def cdp_portid(self, value):
        self._cdp_portid = _strcast(value)

    @property
    def channel(self):
        return self._channel

    @channel.setter
    def channel(self, value):
        self._channel = _intcast(value)
        
    @property
    def client_mac(self):
        return self._client_mac

    @client_mac.setter
    def client_mac(self, value):
        self._client_mac = _strcast(value)  
        
    @property
    def client_manuf(self):
        return self._client_manuf

    @client_manuf.setter
    def client_manuf(self, value):
        self._client_manuf = _strcast(value)               

    @property
    def datasize(self):
        return self._datasize

    @datasize.setter
    def datasize(self, value):
        self._datasize = _intcast(value)

    @property
    def encoding(self):
        return self._encoding

    @encoding.setter
    def encoding(self, value):
        self._encoding = _strcast(value)

    @property
    def first_time(self):
        return self._first_time

    @first_time.setter
    def first_time(self, value):
        if not value is None:
            _typecheck(value, datetime.datetime)
        self._first_time = value

    @property
    def freqmhz(self):
        return self._freqmhz

    @freqmhz.setter
    def freqmhz(self, value):
        freq = _strcast(value)
        self._freqmhz.append(freq)

    @property
    def last_time(self):
        return self._last_time

    @last_time.setter
    def last_time(self, value):
        if not value is None:
            _typecheck(value, datetime.datetime)
        self._last_time = value

    @property
    def manuf(self):
        return self._manuf

    @manuf.setter
    def manuf(self, value):
        self._manuf = _strcast(value)

    @property
    def maxseenrate(self):
        return self._maxseenrate

    @maxseenrate.setter
    def maxseenrate(self, value):
        self._maxseenrate = _intcast(value)

    @property
    def network_type(self):
        return self._network_type

    @network_type.setter
    def network_type(self, value):
        self._network_type = _strcast(value)

    @property
    def number(self):
        return self._number

    @number.setter
    def number(self, value):
        self._number = _intcast(value)

    @property
    def ssid(self):
        return self._ssid

    @ssid.setter
    def ssid(self, value):
        if not value is None:
            _typecheck(value, SSIDObject)
        self._ssid = value            

################################################################################
class SSIDObject(object):
    def __init__(self, **kwargs):
        self.number = kwargs.get("number")
        self.first_time = _datecast(kwargs.get("first-time"))
        self.last_time = _datecast(kwargs.get("last-time"))
        
        # Encryption list (multiple may be provided)
        self._encryption = list()
        
        # Initialise SSID attributes
        for prop in self._all_properties:
            setattr(self, prop, kwargs.get(prop))
        
        # Make new encryption classifications
        self.privacy = None
        self.cipher = None
        self.authentication = None

    _all_properties = set(["beaconrate",
                           "cloaked",
                           "essid",
                           "frame_type",
                           "info",
                           "max_rate",
                           "packets",
                           "wpa_version",
                           "wps"])

    # SSID Population from ET element
    def populate_from_Element(self, e):
        _typecheck(e, (ET.Element, ET.ElementTree))
        (ns, tn) = _qsplit(e.tag)
        assert tn in ["SSID"]
        for ce in e.findall("./*"):
            (cns, ctn) = _qsplit(ce.tag)
            if "-" in ctn:
                ctn = ctn.replace("-", "_")
            if "type" in ctn:
                ctn = "frame_type"
            # Determine ESSID informaiton
            if ctn == "essid":
                # Determine if network is cloaked
                if "cloaked" not in ce.attrib:
                    self.cloaked = False
                else:
                    self.cloaked = ce.attrib["cloaked"]
                if ce.text == "":
                    self.essid = None
                else:
                    self.essid = ce.text
            # Sometimes ESSID is stored in SSID element
            elif ctn == "ssid":
                self.essid = ce.text
            elif ctn == "wpa_version":
                self.wpa_version = ce.text
            # Append encryption to be later parsed
            elif ctn == "encryption":
                self._encryption.append(ce.text)
            # Check if network has WPS enabled
            elif ctn == "wps":
                self.wps = ce.text
            # Populate all other elements
            elif ctn in self._all_properties:
                setattr(self, ctn, ce.text)
        
        # All encryption elements stored, no parse them
        self.determine_encryption()

    def determine_encryption(self):
        """ Determine encryption by parsing the list of encryption values. The
            privacy, cipher and auth are found and set. """
        # First, determine network privacy (OPEN, WEP, WPA, WPA2, WPA+WPA2)
        if not self.wpa_version:
            if any("WEP" in s for s in self.encryption):
                self.privacy = "WEP"
            elif any("None" in s for s in self.encryption):
                self.privacy = "OPEN"
            else:
                self.privacy = "UNKNOWN"
        else:         
            self.privacy = self.wpa_version
        
        if any("AES-OCB" in s for s in self.encryption):
            self.cipher = "AES-OCB"
            self.authentication = ""
        elif any("AES-CCM" in s for s in self.encryption):
            self.cipher = "AES-CCMP"
            self.authentication = "PSK"
        elif any("TKIP" in s for s in self.encryption):
            self.cipher = "TKIP"
            self.authentication = "PSK"
        elif any("PSK" in s for s in self.encryption):
            self.cipher = "TKIP"
            self.authentication = "PSK"            
        elif any("WEP" in s for s in self.encryption):
            self.cipher = "WEP"
            self.authentication = "NONE"
        elif any("None" in s for s in self.encryption):
            self.cipher = "OPEN"
            self.authentication = "NONE"
        else:
            self.cipher = "UNKNOWN"
            self.authentication = "UNKNOWN"
            
    def populate_empty_object(self):
        for prop in self._all_properties:
            prop = ""
        encryption = ""
        privacy = ""
        cipher = ""
        authentication = ""

    # SSID attribute getters and setters
    @property
    def authentication(self):
        return self._authentication

    @authentication.setter
    def authentication(self, value):
        self._authentication = _strcast(value)    
    
    @property
    def beaconrate(self):
        return self._beaconrate

    @beaconrate.setter
    def beaconrate(self, value):
        self._beaconrate = _intcast(value)
        
    @property
    def cipher(self):
        return self._cipher

    @cipher.setter
    def cipher(self, value):
        self._cipher = _strcast(value)         

    @property
    def cloaked(self):
        return self._cloaked

    @cloaked.setter
    def cloaked(self, value):
        self._cloaked = _boolcast(value)

    @property
    def encryption(self):
        return self._encryption

    @encryption.setter
    def encryption(self, value):
        crypt = _strcast(value)
        self._encryption.append(crypt)

    @property
    def essid(self):
        return self._essid

    @essid.setter
    def essid(self, value):
        self._essid = _strcast(value)

    @property
    def first_time(self):
        return self._first_time

    @first_time.setter
    def first_time(self, value):
        if not value is None:
            _typecheck(value, datetime.datetime)
        self._first_time = value

    @property
    def frame_type(self):
        return self._frame_type

    @frame_type.setter
    def frame_type(self, value):
        self._frame_type = _strcast(value)

    @property
    def info(self):
        return self._info

    @info.setter
    def info(self, value):
        self._info = _strcast(value)

    @property
    def last_time(self):
        return self._last_time

    @last_time.setter
    def last_time(self, value):
        if not value is None:
            _typecheck(value, datetime.datetime)
        self._last_time = value

    @property
    def max_rate(self):
        return self._max_rate

    @max_rate.setter
    def max_rate(self, value):
        self._max_rate = _floatcast(value)

    @property
    def packets(self):
        return self._packets

    @packets.setter
    def packets(self, value):
        self._packets = _intcast(value)
        
    @property
    def privacy(self):
        return self._privacy

    @privacy.setter
    def privacy(self, value):
        self._privacy = _strcast(value)        

##################################################################################
class PacketsObject(object):
    def __init__(self, **kwargs):
        """ Initialise Packets object attributes. """
        for prop in self._all_properties:
            setattr(self, prop, kwargs.get(prop))

    _all_properties = set(["llc",
                           "data",
                           "crypt",
                           "total",
                           "fragments",
                           "retries"])

    def populate_from_Element(self, e):
        _typecheck(e, (ET.Element, ET.ElementTree))
        (ns, tn) = _qsplit(e.tag)
        assert tn in ["packets"]
        for ce in e.findall("./*"):
            (cns, ctn) = _qsplit(ce.tag)
            # Make element lower case as some tags (e.g., LLC ) are in caps.
            ctn = ctn.lower()
            if ctn in self._all_properties:
                setattr(self, ctn, ce.text)

    @property
    def llc(self):
        return self._llc

    @llc.setter
    def llc(self, value):
        self._llc = _intcast(value)

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        self._data = _intcast(value)

    @property
    def crypt(self):
        return self._crypt

    @crypt.setter
    def crypt(self, value):
        self._crypt = _intcast(value)

    @property
    def total(self):
        return self._total

    @total.setter
    def total(self, value):
        self._total = _intcast(value)

    @property
    def fragments(self):
        return self._fragments

    @fragments.setter
    def fragments(self, value):
        self._fragments = _intcast(value)

    @property
    def retries(self):
        return self._retries

    @retries.setter
    def retries(self, value):
        self._retries = _intcast(value)

################################################################################
class SnrInfoObject(object):
    def __init__(self, **kwargs):
        """ Initialise SnrInfo object attributes. """
        for prop in self._all_properties:
            setattr(self, prop, kwargs.get(prop))

    _all_properties = set(["last_signal_dbm",
                           "last_noise_dbm",
                           "last_signal_rssi",
                           "last_noise_rssi",
                           "min_signal_dbm",
                           "min_noise_dbm",
                           "min_signal_rssi",
                           "min_noise_rssi",
                           "max_signal_dbm",
                           "max_noise_dbm",
                           "max_signal_rssi",
                           "max_noise_rssi"])

    def populate_from_Element(self, e):
        _typecheck(e, (ET.Element, ET.ElementTree))
        # Split into namespace and tagname
        (ns, tn) = _qsplit(e.tag)
        assert tn in ["snr-info"]
        # Look through direct-child elements for other properties
        for ce in e.findall("./*"):
            (cns, ctn) = _qsplit(ce.tag)
            if "-" in ctn:
                ctn = ctn.replace("-", "_")
            if ctn in self._all_properties:
                setattr(self, ctn, ce.text)

    @property
    def last_signal_dbm(self):
        return self._last_signal_dbm

    @last_signal_dbm.setter
    def last_signal_dbm(self, value):
        self._last_signal_dbm = _intcast(value)

    @property
    def last_noise_dbm(self):
        return self._last_noise_dbm

    @last_noise_dbm.setter
    def last_noise_dbm(self, value):
        self._last_noise_dbm = _intcast(value)

    @property
    def last_signal_rssi(self):
        return self._last_signal_rssi

    @last_signal_rssi.setter
    def last_signal_rssi(self, value):
        self._last_signal_rssi = _intcast(value)
    @property
    def last_noise_rssi(self):
        return self._last_noise_rssi

    @last_noise_rssi.setter
    def last_noise_rssi(self, value):
        self._last_noise_rssi = _intcast(value)

    @property
    def min_signal_dbm(self):
        return self._min_signal_dbm

    @min_signal_dbm.setter
    def min_signal_dbm(self, value):
        self._min_signal_dbm = _intcast(value)

    @property
    def min_noise_dbm(self):
        return self._min_noise_dbm

    @min_noise_dbm.setter
    def min_noise_dbm(self, value):
        self._min_noise_dbm = _intcast(value)

    @property
    def min_signal_rssi(self):
        return self._min_signal_rssi

    @min_signal_rssi.setter
    def min_signal_rssi(self, value):
        self._min_signal_rssi = _intcast(value)

    @property
    def min_noise_rssi(self):
        return self._min_noise_rssi

    @min_noise_rssi.setter
    def min_noise_rssi(self, value):
        self._min_noise_rssi = _intcast(value)

    @property
    def max_signal_dbm(self):
        return self._max_signal_dbm

    @max_signal_dbm.setter
    def max_signal_dbm(self, value):
        self._max_signal_dbm = _intcast(value)

    @property
    def max_noise_dbm(self):
        return self._max_noise_dbm

    @max_noise_dbm.setter
    def max_noise_dbm(self, value):
        self._max_noise_dbm = _intcast(value)

    @property
    def max_signal_rssi(self):
        return self._max_signal_rssi

    @max_signal_rssi.setter
    def max_signal_rssi(self, value):
        self._max_signal_rssi = _intcast(value)

    @property
    def max_noise_rssi(self):
        return self._max_noise_rssi

    @max_noise_rssi.setter
    def max_noise_rssi(self, value):
        self._max_noise_rssi = _intcast(value)
        
################################################################################
class GPSInfoObject(object):
    def __init__(self, **kwargs):
        """ Initialise GPSInfo object attributes. """
        for prop in self._all_properties:
            setattr(self, prop, kwargs.get(prop))

    _all_properties = set(["min_lat",
                           "min_lon",
                           "min_alt",
                           "min_spd",
                           "max_lat",
                           "max_lon",
                           "max_alt",
                           "max_spd",
                           "peak_lat",
                           "peak_lon",
                           "peak_alt",
                           "avg_lat",
                           "avg_lon",
                           "avg_alt"])

    def populate_from_Element(self, e):
        _typecheck(e, (ET.Element, ET.ElementTree))
        # Split into namespace and tagname
        (ns, tn) = _qsplit(e.tag)
        assert tn in ["gps-info"]
        # Look through direct-child elements for other properties
        for ce in e.findall("./*"):
            (cns, ctn) = _qsplit(ce.tag)
            if "-" in ctn:
                ctn = ctn.replace("-", "_")
            if ctn in self._all_properties:
                setattr(self, ctn, ce.text)

    @property
    def min_lon(self):
	    return self._min_lon

    @min_lon.setter
    def min_lon(self, value):
	    self._min_lon = _floatcast(value)

    @property
    def max_lat(self):
	    return self._max_lat

    @max_lat.setter
    def max_lat(self, value):
	    self._max_lat = _floatcast(value)

    @property
    def avg_alt(self):
	    return self._avg_alt

    @avg_alt.setter
    def avg_alt(self, value):
	    self._avg_alt = _floatcast(value)

    @property
    def min_spd(self):
	    return self._min_spd

    @min_spd.setter
    def min_spd(self, value):
	    self._min_spd = _floatcast(value)

    @property
    def peak_alt(self):
	    return self._peak_alt

    @peak_alt.setter
    def peak_alt(self, value):
	    self._peak_alt = _floatcast(value)

    @property
    def peak_lon(self):
	    return self._peak_lon

    @peak_lon.setter
    def peak_lon(self, value):
	    self._peak_lon = _floatcast(value)

    @property
    def max_alt(self):
	    return self._max_alt

    @max_alt.setter
    def max_alt(self, value):
	    self._max_alt = _floatcast(value)

    @property
    def max_lon(self):
	    return self._max_lon

    @max_lon.setter
    def max_lon(self, value):
	    self._max_lon = _floatcast(value)

    @property
    def min_lat(self):
	    return self._min_lat

    @min_lat.setter
    def min_lat(self, value):
	    self._min_lat = _floatcast(value)

    @property
    def avg_lon(self):
	    return self._avg_lon

    @avg_lon.setter
    def avg_lon(self, value):
	    self._avg_lon = _floatcast(value)

    @property
    def avg_lat(self):
	    return self._avg_lat

    @avg_lat.setter
    def avg_lat(self, value):
	    self._avg_lat = _floatcast(value)

    @property
    def max_spd(self):
	    return self._max_spd

    @max_spd.setter
    def max_spd(self, value):
	    self._max_spd = _floatcast(value)

    @property
    def peak_lat(self):
	    return self._peak_lat

    @peak_lat.setter
    def peak_lat(self, value):
	    self._peak_lat = _floatcast(value)

    @property
    def min_alt(self):
	    return self._min_alt

    @min_alt.setter
    def min_alt(self, value):
	    self._min_alt = _floatcast(value)        

################################################################################
class SeenCard(object):
    def __init__(self, **kwargs):
        """ Initialise SeenCard object attributes. """
        for prop in self._all_properties:
            setattr(self, prop, kwargs.get(prop))

    _all_properties = set(["seen_uuid",
                           "seen_time",
                           "seen_packets"])

    def populate_from_Element(self, e):
        _typecheck(e, (ET.Element, ET.ElementTree))
        # Split into namespace and tagname
        (ns, tn) = _qsplit(e.tag)
        assert tn in ["seen-card"]
        # Look through direct-child elements for other properties
        for ce in e.findall("./*"):
            (cns, ctn) = _qsplit(ce.tag)
            if "-" in ctn:
                ctn = ctn.replace("-", "_")
            if ctn in SeenCard._all_properties:
                setattr(self, ctn, ce.text)

    @property
    def seen_uuid(self):
        return self._seen_uuid

    @seen_uuid.setter
    def seen_uuid(self, value):
        self._seen_uuid = _strcast(value)

    @property
    def seen_time(self):
        return self._seen_time

    @seen_time.setter
    def seen_time(self, value):
        if not value is None:
            _typecheck(value, datetime.datetime)
        self._seen_time = value

    @property
    def seen_packets(self):
        return self._seen_packets

    @seen_packets.setter
    def seen_packets(self, value):
        self._seen_packets = _strcast(value)    

################################################################################
def iterparse(filename, events=("start","end"), **kwargs):
    """ Generator. Yields a stream of populated WirelessNetworks. """
    fh = None
    if filename.endswith(".netxml"):
        fh = open(filename, "rb")
    else:
        check = input(">>> Is this a NetXML file? [Y] to continue...")
        if check == "Y" or check == "y" or check == "Yes" or check == "yes":
            pass
        else:
            print(">>> Quitting...")
            quit()

    netxml = NetXML()

    for (ETevent, elem) in ET.iterparse(fh, events=("start-ns", "start", "end")):
        (ns, ln) = _qsplit(elem.tag)
        if ETevent == "start":
            pass
        elif ETevent == "end":
            if ln == "card-source":
                cs = CardSource(**elem.attrib)
                cs.populate_from_Element(elem)
                netxml.card_source = cs
            elif ln == "wireless-network":
                wn = WirelessNetwork(**elem.attrib)
                wn.populate_from_Element(elem)
                netxml.append(wn)
            elif ln == "":
                pass

    return netxml

################################################################################
if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser(description='''
NetXML.py is an API that can parse the contents of a NetXML document. The
NetXML standard is commonly used in wireless sniffing tools (e.g., kismet and
airodump-ng) and stores information regarding any discovered wireless networks.
The NetXML.py module creates major NetXML classes with an emphasis on type
safety, serializability, and de-serializability. You can process a NetXML
document using the iterparse function.''')
    parser.add_argument("netxml_file",
                        help = "Target NetXML file (e.g. Kismet-20150505-05-15-05-1.netxml)")
    args = parser.parse_args()
    print(">>> Input NetXML file: %s" % os.path.basename(args.netxml_file))

    # A simple example of parsing a NetXML file and printing network details
    netxml = iterparse(args.netxml_file)
    for w in netxml:
        if isinstance(w, WirelessNetwork) and w.ssid:
            print(w.number, w.bssid, w.ssid.essid, w.ssid.privacy)
