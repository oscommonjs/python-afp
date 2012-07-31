import site
site.addsitedir('/Library/Python/2.6/site-packages')

import dpkt
import struct
import socket

from collections import namedtuple

class DSIHeader( dpkt.Packet ):

    __hdr__ = (
        ('flags', 'B', 0x00),
        ('command', 'B', 0),
        ('requestID', 'H', 0),
        ('errorCode', 'I', 0),
        ('writeOffset', 'I', 0),
        ('totalDataLength', 'I', 32),
        ('reserved', 'I', 0),
    )

def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)
    
    return reduce(lambda x,y:x+y, lst)

class pascal_string( object ):
    def __init__( self, bytes, offset=0 ):
        self.length = struct.unpack_from('b', bytes, offset )[0]
        self.length_format = 'c' * int(self.length)
        self.content = ''.join( struct.unpack_from(self.length_format, bytes, offset + 1 ) )

    def __str__(self):
        return self.content

    def __len__(self):
        return self.length + 1

class DSIGetStatus( dpkt.Packet ):
    __hdr__ = (
        ('flags', 'B', 0x00),
        ('command', 'B', 3),
        ('requestID', 'H', 0),
        ('errorCode_writeOffset', 'I', 0),
        ('totalDataLength', 'I', 0),
        ('reserved', 'I', 0),
    )
    class StatusHeaderOffsetPrefix( dpkt.Packet ):
        # there's no easy way to unpack 'p', pascal string.
        __hdr__ = (
            ('machine_type_offset', 'H', 0),
            ('afp_version_count_offset', 'H', 0),
            ('uam_offset', 'H', 0),
            ('volume_icon_and_mask_offset', 'H', 0),
            ('flags', 'H', 0),
         )

    class StatusHeaderOffsetSegmentTwo( dpkt.Packet ):
        __hdr__ = (
            ('server_signature_offset', 'H', 0),
            ('network_address_count_offset', 'H', 0),
            ('directory_names_count_offset', 'H', 0),
            ('utf8_server_name_offset', 'H', 0),
         )

    def unpack( self, bytes ):
        super(DSIGetStatus, self).unpack( bytes )
        if self.errorCode_writeOffset == 0:
                # FPGetSrvrInfo is 16 bytes
            reply_bytes     = bytes[16:]
            reply_offset    = 0
            o = DSIGetStatus.StatusHeaderOffsetPrefix( reply_bytes[reply_offset:] )
                # StatusHeaderOffsetPrefix is 10 bytes
            reply_offset += 10
            for v in ['machine_type_offset', 'afp_version_count_offset', 'uam_offset', 'volume_icon_and_mask_offset', 'flags']:
                setattr( self, v, getattr( o, v ) )
            self.server_name = pascal_string( reply_bytes[reply_offset:] )

            reply_offset += len( self.server_name )
                # zero padding to make server_name even boundry
            if len(self.server_name) % 2 != 0:
                reply_offset += 1
 
                # StatusHeaderOffsetSegmentTwo is 8 bytes
            o2 = DSIGetStatus.StatusHeaderOffsetSegmentTwo( reply_bytes[reply_offset:] )
            for v in ['server_signature_offset', 'network_address_count_offset', 'directory_names_count_offset', 'utf8_server_name_offset']:
                setattr( self, v, getattr( o2, v ) )

            self.machine_type = str(pascal_string( reply_bytes, offset=self.machine_type_offset ))
            self.afp_version_count = struct.unpack_from( 'B', reply_bytes, self.afp_version_count_offset)[0]
            self.afp_versions = []
                # each AFP version that the server supports in packed format. For each supported version, there is one byte stating the number of bytes in the version string that follows.
            afp_start = self.afp_version_count_offset + 1
            for i in range( self.afp_version_count ):
                version = pascal_string( reply_bytes, offset=afp_start )
                self.afp_versions.append(  str(version) )
                afp_start += len( version )
            self.uam_count = struct.unpack_from( 'B', reply_bytes, self.uam_offset)[0]
            uam_start = self.uam_offset + 1
            self.uams = []
            for i in range( self.uam_count ):
                uam = pascal_string( reply_bytes, offset=uam_start )
                self.uams.append( str( uam ) )
                uam_start += len( uam )

            self.server_signature = ''.join( [ str( hex(i).replace('0x','') ) for i in struct.unpack_from( 'H' * 16, reply_bytes, self.server_signature_offset ) ] )

 
class FPGetSrvrInfo( dpkt.Packet ):
    __hdr__ = (
        ('CommandCode', 'B', 15),
        ('Pad', 'B', 0)
    )

class AFPServer(object):
    request_id = 0
    def __init__(self, server=('10.0.1.22', 548), source=('10.0.1.24', 0), timeout=None):
        self.sock = socket.create_connection( server, timeout, source )

    def connect(self):
        self.get_status()

    def get_status( self ):
        dsi_out = DSIGetStatus()
        fp_out  = FPGetSrvrInfo()
        self.sock.send( str( dsi_out) + str( fp_out ) )
        bytes = self.sock.recv( 4096 )
        if len( bytes ) != 0:
            dsi = DSIGetStatus( bytes )
            print dsi.__dict__

if __name__ == '__main__':
    try:
        afp = AFPServer()
        afp.connect()
    except:
        import traceback
        traceback.print_exc()