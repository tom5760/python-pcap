import ctypes
import ctypes.util

PCAP_ERRBUF_SIZE = 256

class pcap_addr(ctypes.Structure):
    # Need to forward-declare this since the "next" field refers to it
    pass

pcap_addr._fields_ = [
        ('next', ctypes.POINTER(pcap_addr)),
        ('addr', ctypes.c_void_p),
        ('netmask', ctypes.c_void_p),
        ('broadaddr', ctypes.c_void_p),
        ('dstaddr', ctypes.c_void_p),
]

class pcap_if(ctypes.Structure):
    # Need to forward-declare this since the "next" field refers to it
    pass

pcap_if._fields_ = [
        ('next', ctypes.POINTER(pcap_if)),
        ('name', ctypes.c_char_p),
        ('description', ctypes.c_char_p),
        ('addresses', ctypes.POINTER(pcap_addr)),
        ('flags', ctypes.c_int32),
]

class Interface(object):
    def __init__(self, iface):
        self.name = str(iface.name, 'utf-8')

        if iface.description is None:
            self.description = None
        else:
            self.description = str(iface.description, 'utf-8')

        self.addresses = self._get_addresses(iface.addresses.contents)

    def __str__(self):
        return '({0}: {1})'.format(self.name, self.description)

    def __repr__(self):
        return str(self)

    @staticmethod
    def _get_addresses(addrs):
        addresses = []
        while True:
            try:
                addresses.append('foo')
                addrs = addrs.next.contents
            except ValueError:
                break

class PcapError(Exception): pass

class Pcap(object):
    def __init__(self):
        self.library = _load_library()
        self.errbuf = self._make_errbuf()

    def find_all_devs(self):
        pcap_ifs_p = ctypes.POINTER(pcap_if)()

        rv = self.library.pcap_findalldevs(ctypes.byref(pcap_ifs_p),
                                           self.errbuf)
        if rv == -1:
            raise PcapError(self.errbuf.value)

        pcap_ifs = pcap_ifs_p.contents
        interfaces = []
        while True:
            try:
                interfaces.append(Interface(pcap_ifs))
                pcap_ifs = pcap_ifs.next.contents
            except ValueError:
                break

        self.library.pcap_freealldevs(pcap_ifs_p)
        return interfaces

    @staticmethod
    def _make_errbuf():
        buf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
        return buf

def _load_library():
    path = ctypes.util.find_library('pcap')
    library = ctypes.cdll.LoadLibrary(path)

    library.pcap_findalldevs.argtypes = (
            ctypes.POINTER(ctypes.POINTER(pcap_if)), ctypes.c_char_p)

    return library


if __name__ == '__main__':
    p = Pcap()
    print(p.find_all_devs())
