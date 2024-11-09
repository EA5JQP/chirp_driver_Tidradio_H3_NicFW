# Copyright 2012 Dan Smith <dsmith@danplanet.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import logging

# noinspection PyUnresolvedReferences
from chirp import chirp_common, directory, bitwise, memmap, errors, util
# noinspection PyUnresolvedReferences
from chirp.settings import InvalidValueError, RadioSetting, RadioSettingGroup, \
    RadioSettingValueBoolean, RadioSettingValueList, \
    RadioSettingValueInteger, RadioSettingValueString, \
    RadioSettings, RadioSettingSubGroup, RadioSettingValueFloat

LOG = logging.getLogger(__name__)

# Here is where we define the memory map for the radio. Since
# We often just know small bits of it, we can use #seekto to skip
# around as needed.


MEM_FORMAT = """

#seekto 0x0000;
struct {
    ul32 rxfreq;        // byte[4]  - RX Frequency in 10Hz units 32 bit unsigned little endian
    ul32 txfreq;        // byte[4]  - TX Frequency in 10Hz units 32 bit unsigned little endian
    ul16 rxtone;        // byte[2]  - RX Sub Tone CTCSS: 0.1Hz units,  DCS: codeword|0x8000[|0x4000 for reverse tone] . 16 bit unsigned little endian
    ul16 txtone;        // byte[2]  - TX Sub Tone (as rx sub tone)
    u8 txpower;         // byte[1]  - TX Power - 8 bit unsigned
    u16 group;          // byte[2]  - Group membership . each 4 bit nibble represents a group letter 0=No group, 1-15=group A-O
    u8 unused1:1,       // bit[1]   - Other bits are reserved
       unused2:2,       // bit[2]   - Other bits are reserved
       unused3:1,       // bit[1]   - Other bits are reserved 
       unused4:1,       // bit[1]   - Other bits are reserved 
       modulation:2,    // bit[2]   - Modulation - 0=Auto, 1=FM, 2=AM, 3=USB
       bandwidth:1;     // bit[1]   - Bandwith - 0=Wide, 1=Narrow
    u32 reserved;       // byte[4]  - Reserved
    char name[12];      // byte[12] - ASCII channel name, unused characters should be null (0)
    } memory[199]; 

struct {
    u16 magic;          // byte[2] = 0x9BCF (magic value)
    u8 squelch;         // byte[1] = squelch, 8 bit unsigned but only valid values are 0-9
    ul16 step;          // byte[2] = step, 16 bit unsigned little endian. 10Hz units
    u8 micgain;         // byte[1] = mic gain, 8 bit unsigned but only valid values are 0-31
    u8 lcd;             // byte[1] = LCD brightness, 8 bit unsigned, valid 0-28
    u8 subtonedev;      // byte[1] = Sub Tone deviation, 8 bit unsigned, valid 0-127
    u8 keytones;        // byte[1] = Key tones, bool
    u8 opmode;          // byte[1] = Operation mode, 0=VFO, 1=Channel, 2=Group
    u8 channel;         // byte[1] = current channel 0-199 the channel currently being used (0 and 1 are VFO-A and VFO-B, 2 is channel1, 3 is channel2 etc..)
    u8 lastchannel;     // byte[1] = Last channel 2-199 the last channel used in channel or group mode. 
    u8 group;           // byte[1] = current group 1-15
    u8 scanlinger;      // byte[1] = scan linger
    ul16 rxfilter;      // byte[2] = RX vhf/uhf filter transition frequency, 16 bit unsigned little endian 100kHz units
    ul16 txfilter;      // byte[2] = TX vhf/uhf filter transition frequency, 16 bit unsigned little endian 100kHz units
    u16 unknown_1;      // byte[2] = reserved?
    u16 unknown_2;      // byte[2] = reserved?
    u16 unknown_3;      // byte[2] = reserved?
    u16 unknown_4;      // byte[2] = reserved?
    u16 unknown_5;      // byte[2] = reserved?
    u16 unknown_6;      // byte[2] = reserved?
    u16 unknown_7;      // byte[2] = reserved?
    } settings;
    
"""

CMD_DISABLE_RADIO           = b'\x45' # w/  Ack
CMD_ENABLE_RADIO            = b'\x46' # w/  Ack
CMD_READ_EEPROM             = b'\x30' # w/  Ack
CMD_WRITE_EEPROM            = b'\x31' # w/  Ack
MAGIC_SETTINGS              = 0x9BCF

BLOCK_DATA_SIZE = 0x0020
INIT_ADDR_CHANNELS = 0x0040
INIT_ADDR_SETTINGS = 0x1900
BLOCK_CHANNEL = range(1,200)
BLOCK_SETTINGS = 200

CTCSS_TONES = [
    67.0, 69.3, 71.9, 74.4, 77.0, 79.7, 82.5, 85.4,
    88.5, 91.5, 94.8, 97.4, 100.0, 103.5, 107.2, 110.9,
    114.8, 118.8, 123.0, 127.3, 131.8, 136.5, 141.3, 146.2,
    151.4, 156.7, 159.8, 162.2, 165.5, 167.9, 171.3, 173.8,
    177.3, 179.9, 183.5, 186.2, 189.9, 192.8, 196.6, 199.5,
    203.5, 206.5, 210.7, 218.1, 225.7, 229.1, 233.6, 241.8,
    250.3, 254.1, 
]

GROUPS_LIST = ["None","A", "B", "C","D","E","F","G","H","I","J","K","L","M","N","O"]
MODULATION_LIST = ["Auto", "FM", "AM", "USB"]
BANDWIDTH_LIST = ["Wide", "Narrow"]
SQUELCH_LIST = ['Off' if x == 0 else f'{x}' for x in range(0, 10)]
OP_MODES = ["VFO", "Channel", "Group"]
MICGAIN_LIST = [f'{x}' for x in range(0, 32)]
LCDBRIGHT_LIST = [f'{x}' for x in range(0, 29)]
SUBTONEDEV_LIST = [f'{x}' for x in range(0, 128)]
SCANLINGER_LIST = [f'{x}' for x in range(10, 128)] 


def write_cmd(radio, cmd, check_ack=False):
    serial = radio.pipe
    serial.write(cmd)
    serial.timeout = 0.5
    if check_ack == True:
        ack = serial.read(1)
        if ack != cmd:
            LOG.debug("[ERR] Unable to communicate with nicFW -- there was no valid ACK for {} command ({} received).".format(cmd,ack))

def _do_status(radio, block):
    status = chirp_common.Status()
    status.msg = "Cloning"
    status.cur = block
    status.max = BLOCK_CHANNEL[-1]
    radio.status_fn(status)

def _enter_programming_mode(radio):
    write_cmd(radio, CMD_ENABLE_RADIO, check_ack=True)

def _exit_programming_mode(radio):
    write_cmd(radio, CMD_DISABLE_RADIO, check_ack=True)

def calc_checksum(bytes):
    checksum = 0

    for b in bytes:
        checksum += b

    return (checksum % 256).to_bytes(1,'little')

def _read_block(radio, block):
    serial = radio.pipe
    serial.timeout = 0.5
    serial.write(CMD_READ_EEPROM)
    serial.write([block])
    
    ack = serial.read(1)
    data = serial.read(BLOCK_DATA_SIZE)
    checksum_r = serial.read(1)
        
    if checksum_r != calc_checksum(data):
        LOG.debug("Received data checksum mismatch!")    
    # else:
    #     LOG.debug("Received checksum OK")    
    
    return data    

def _write_block(radio, block, data):
    checksum = calc_checksum(data)

    serial = radio.pipe
    serial.timeout = 0.5

    serial.write(CMD_WRITE_EEPROM)
    serial.write([block])
    serial.write(data)
    serial.write(checksum)
    LOG.debug("Bytes to write:{} checksum:{}".format(data,checksum))
    
    ack = serial.read(1)

    if ack == CMD_WRITE_EEPROM:
       LOG.debug("Received {} expected {} checksum mismatch while writing!".format(ack,CMD_WRITE_EEPROM))     
    
def do_download(radio):
    """This is your download channels function"""
    _enter_programming_mode(radio)

    data = b""
    data = bytearray()

    for i in range(1,BLOCK_SETTINGS+1):
        block = _read_block(radio, i)
        data.extend(block)
        LOG.info("Block: %i",i)
        LOG.info(util.hexprint(bytes(block)))
        _do_status(radio, i)
 
    _exit_programming_mode(radio)

    return memmap.MemoryMapBytes(bytes(data))

    
def get_group(group, index):
    # Define the group letters A-O (1-15)
    group_letters = "ABCDEFGHIJKLMNO"
    
    # Extract each nibble (4 bits) from the 16-bit integer
    nibbles = [
        (group >> 8) & 0xF,   # Second highest nibble
        (group >> 12) & 0xF,  # Highest nibble        
        (group & 0xF),           # Lowest nibble
        (group >> 4) & 0xF   # Third highest nibble
    ]
    
    # Map each nibble to a group letter if it is non-zero
    active_letters = [group_letters[nibble - 1] if nibble > 0 else "None" for nibble in nibbles]

    # LOG.debug(f"Extracted nibbles: {nibbles}")   
    # LOG.debug(f"Active letters: {active_letters}")

    return active_letters[index]

def set_group(groups):
    # Define the group letters A-O (1-15)
    group_letters = "ABCDEFGHIJKLMNO"
    
    # Convert each group letter to its corresponding nibble value (1-15), or 0 if "None"
    nibbles = [
        group_letters.index(group) + 1 if group in group_letters else 0
        for group in groups
    ]
    
    # Reorder the nibbles to match the original positions
    reordered_nibbles = [nibbles[1], nibbles[0], nibbles[3], nibbles[2]]
    
    # Combine the reordered nibbles into a single 16-bit integer
    u16 = (reordered_nibbles[0] << 12) | (reordered_nibbles[1] << 8) | (reordered_nibbles[2] << 4) | reordered_nibbles[3]
    
    return u16


    if val == 16665 or val == 0:
        return '', None, None
    elif val >= 12000:
        return 'DTCS', val - 12000, 'R'
    elif val >= 8000:
        return 'DTCS', val - 8000, 'N'
    else:
        return 'Tone', val / 10.0, None    

def _do_upload(radio):
    """This is your download settings function"""
    # _enter_programming_mode(radio)

    # data = radio.get_mmap()[0x1900:0x1900+BLOCK_DATA_SIZE]
    # LOG.debug("writemem sent data offset=0x%4.4x len=0x%4.4x:\n%s" %
    #               (0x1900, len(data), util.hexprint(data)))

    # _write_block(radio, BLOCK_SETTINGS, data)

    # for addr in range(0, 0x1920 + 20 + 20, BLOCK_DATA_SIZE):
    #     data = radio.get_mmap()[addr:addr+BLOCK_DATA_SIZE]
    #     LOG.debug("writemem sent data offset=0x%4.4x len=0x%4.4x:\n%s" %
    #               (addr, len(data), util.hexprint(data)))

    for i in range(1,BLOCK_SETTINGS + 1):
        addr = i * BLOCK_DATA_SIZE
        data = radio.get_mmap()[addr:addr+BLOCK_DATA_SIZE]
        LOG.debug("writemem sent data offset=0x%4.4x len=0x%4.4x:\n%s" %
            (addr, len(data), util.hexprint(data)))

    # _exit_programming_mode(radio)



@directory.register
class TidradioH3NicFwRadio(chirp_common.CloneModeRadio):
    VENDOR = "TIDRADIO"     # Replace this with your vendor
    MODEL = "H3 NicFW"  # Replace this with your model
    BAUD_RATE = 38400    # Replace this with your baud rate

    VALID_BANDS = [(10000000, 136000000),  # RX only (Air Band)
                   (136000000, 174000000),  # TX/RX (VHF)
                   (174000000, 240000000),  # TX/RX
                   (240000000, 320000000),  # TX/RX
                   (320000000, 400000000),  # TX/RX
                   (400000000, 480000000),  # TX/RX (UHF)
                   (480000000, 1300000000)]  # TX/RX
    


    # Return information about this radio's features, including
    # how many memories it has, what bands it supports, etc
    def get_features(self):
        rf = chirp_common.RadioFeatures()
        rf.has_bank = False
        rf.has_tuning_step = False
        rf.has_rx_dtcs = False
        rf.has_ctone = False
        rf.has_settings = True
        rf.has_comment = False

        rf.memory_bounds = (1, 198)
        rf.valid_characters = chirp_common.CHARSET_ASCII
        rf.valid_bands = self.VALID_BANDS
        rf.valid_modes = MODULATION_LIST
        rf.valid_duplexes = ["", "-", "+", "split", "off"]
        rf.valid_skips = ["N"]

        return rf
    
    def get_settings(self):
        _mem = self._memobj
        
        basic = RadioSettingGroup("basic", "Basic Settings")
        bandplan = RadioSettingGroup("bandplan", "Band Plan")

        group = RadioSettings(basic)

        rs = RadioSettingValueList(SQUELCH_LIST, current_index = _mem.settings.squelch)
        rset = RadioSetting("squelch", "Squelch Level", rs)
        basic.append(rset)

        step = float(_mem.settings.step / 100.0)
        rs = RadioSettingValueFloat(0.01, 500, step, resolution=0.01, precision=2)
        rset = RadioSetting("step", "Step Size", rs)
        basic.append(rset)

        rs = RadioSettingValueList(MICGAIN_LIST, current_index = _mem.settings.micgain)
        rset = RadioSetting("micgain", "Mic Gain", rs)
        basic.append(rset)

        rs = RadioSettingValueList(LCDBRIGHT_LIST, current_index = _mem.settings.lcd)
        rset = RadioSetting("lcd", "LCD Brightness", rs)
        basic.append(rset)

        rs = RadioSettingValueList(SUBTONEDEV_LIST, current_index = _mem.settings.subtonedev)
        rset = RadioSetting("subtonedev", "Sub Tone Deviation", rs)
        basic.append(rset)

        rs = RadioSettingValueBoolean(bool(_mem.settings.keytones))
        rset = RadioSetting("keytones", "Key Tones", rs)
        basic.append(rset)

        rs = RadioSettingValueList(OP_MODES, current_index = _mem.settings.opmode)
        rset = RadioSetting("opmode", "Operation Mode", rs)
        basic.append(rset)

        rs = RadioSettingValueList(SCANLINGER_LIST, current_index = _mem.settings.scanlinger)
        rset = RadioSetting("scanlinger", "Scan Tail", rs)
        basic.append(rset)

        rxfilter = float(_mem.settings.rxfilter) / 10
        rs = RadioSettingValueFloat(150, 400, rxfilter, resolution= 0.1, precision=1)
        rset = RadioSetting("rxfilter", "RX VHF/UHF Filter Transition Frequency", rs)
        basic.append(rset)

        txfilter = float(_mem.settings.txfilter) / 10
        rs = RadioSettingValueFloat(150, 400, txfilter, resolution= 0.1, precision=1)
        rset = RadioSetting("txfilter", "TX VHF/UHF Filter Transition Frequency", rs)
        basic.append(rset)

        return group
 
    # Do a download of the radio from the serial port
    def sync_in(self):
        self._mmap = do_download(self)
        self.process_mmap()

    # Do an upload of the radio to the serial port
    def sync_out(self):
        try:
            _do_upload(self)
        except errors.RadioError:
            raise
        except Exception as e:
            raise errors.RadioError("Failed to communicate with radio: %s" % e)

    # Convert the raw byte array into a memory object structure
    def process_mmap(self):
        self._memobj = bitwise.parse(MEM_FORMAT, self._mmap)
    
    # Return a raw representation of the memory object, which
    # is very helpful for development
    def get_raw_memory(self, number):
        return repr(self._memobj.memory[number])

    # Extract a high-level memory object from the low-level memory map
    # This is called to populate a memory in the UI
    def get_memory(self, number):
    
        # Create a high-level memory object to return to the UI
        mem = chirp_common.Memory()

        # Get a low-level memory object mapped to the image
        _mem = self._memobj.memory[number]   
        mem.number = number                 # Set the memory number

        LOG.info("Doing channel %i ",number)
    
        # We'll consider any blank (i.e. 0 MHz frequency) to be empty
        if _mem.get_raw()[0] == 0xff:
            mem.empty = True
            # LOG.info("Channel %i is empty! 1o",number)
            return mem
        
        # Convert your low-level frequency to Hertz
        mem.freq = int(_mem.rxfreq) * 10
        mem.name = str(_mem.name).rstrip()  # Set the alpha tag

        # Offset
        if int(_mem.rxfreq) == int(_mem.txfreq):
            mem.duplex = ""
            mem.offset = 0
        else:
            mem.duplex = int(_mem.rxfreq) > int(_mem.txfreq) and "-" or "+"
            mem.offset = abs(int(_mem.rxfreq) - int(_mem.txfreq)) * 10


        mem.mode = MODULATION_LIST[int(_mem.modulation)]  
        mem.skip = ""

        mem.tmode = ""
        rxtone = (_mem.rxtone)
        # txtone = _decode_tone(_mem.txtone)

        # chirp_common.split_tone_decode(mem, txtone, rxtone)
        
        mem.extra = RadioSettingGroup("Extra", "extra")


        rs = RadioSettingValueInteger(0, 255, _mem.txpower)
        rset = RadioSetting("txpower", "TX Power", rs)
        mem.extra.append(rset)

        rs = RadioSettingValueList(GROUPS_LIST, get_group(_mem.group,0))
        rset = RadioSetting("group1", "Grp Slot 1", rs)
        mem.extra.append(rset)
        
        rs = RadioSettingValueList(GROUPS_LIST, get_group(_mem.group,1))
        rset = RadioSetting("group2", "Grp Slot 2", rs)
        mem.extra.append(rset)

        rs = RadioSettingValueList(GROUPS_LIST, get_group(_mem.group,2))
        rset = RadioSetting("group3", "Grp Slot 3", rs)
        mem.extra.append(rset)
       
        rs = RadioSettingValueList(GROUPS_LIST, get_group(_mem.group,3))
        rset = RadioSetting("group4", "Grp Slot 4", rs)
        mem.extra.append(rset)

        bandwidth = "Narrow" if _mem.bandwidth  else "Wide"
        rs = RadioSettingValueList(BANDWIDTH_LIST, bandwidth)
        rset = RadioSetting("bandwidth", "Bandwidth", rs)
        mem.extra.append(rset)

        # rs = RadioSettingValueList(MODULATION_LIST, modulation)
        # rset = RadioSetting("modulation", "Modulation", rs)
        # mem.extra.append(rset)

        return mem

    # Store details about a high-level memory to the memory map
    # This is called when a user edits a memory in the UI
    def set_memory(self, mem):
        # Get a low-level memory object mapped to the image
        _mem = self._memobj.memory[mem.number]

        # if empty memory
        if mem.empty:
            _mem.set_raw("\xFF" * 22 + "\x20" * 10)
            return
        
        _mem.rxfreq = mem.freq / 10

        if mem.duplex == "split":
            _mem.txfreq = mem.offset / 10
        elif mem.duplex == "+":
            _mem.txfreq = (mem.freq + mem.offset) / 10
        elif mem.duplex == "-":
            _mem.txfreq = (mem.freq - mem.offset) / 10
        else:
            _mem.txfreq = mem.freq / 10

        _mem.name = mem.name.rstrip('\xFF').ljust(10, '\x20')

        _mem.txpower = mem.txpower 
        _mem.bandwidth = 1 if mem.bandwidth=="Narrow" else 0
        _mem.modulation = MODULATION_LIST.index(mem.modulation)
        _mem.group = set_group([mem.group1, mem.group2, mem.group3, mem.group4])

    def set_settings(self, settings):
        _settings = self._memobj.settings

        for element in settings:
            if not isinstance(element, RadioSetting):
                self.set_settings(element)
                continue
        
        # Basic Settings        

        # Squelch
        if element.get_name() == "squelch":
            _settings.squelch = SQUELCH_LIST.index(str(element.value))

        # Steps
        if element.get_name() == "steps":
            _settings.steps = float(element.value) * 100 

        # Mic Gain
        if element.get_name() == "micgain":
            _settings.micgain = MICGAIN_LIST.index(str(element.value))

        # LCD Brightness
        if element.get_name() == "lcd":
            _settings.lcd = LCDBRIGHT_LIST.index(str(element.value))        
         
        # Key tone
        if element.get_name() == "keytones":
            _settings.keytones = element.value and 1 or 0  

        # Operation Mode
        if element.get_name() == "opmode":
            _settings.opmode = OP_MODES.index(str(element.value))

        # Scan Linger
        if element.get_name() == "scanlinger":
            _settings.scanlinger = SCANLINGER_LIST.index(str(element.value))

        # RX VHF/UHF Filter Transition Frequency
        if element.get_name() == "rxfilter":
            _settings.rxfilter = float(element.value)
        
        # TX VHF/UHF Filter Transition Frequency
        if element.get_name() == "txfilter":
            _settings.txfilter = float(element.value)

        

