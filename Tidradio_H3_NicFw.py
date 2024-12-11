# Copyright 2024 Gonzalo EA5JQP <ea5jqp@proton.me>
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
    RadioSettings, RadioSettingValueFloat

LOG = logging.getLogger(__name__)

MEM_FORMAT = """

#seekto 0x0000;
struct {
    ul32 rxfreq;        // byte[4]  - RX Frequency in 10Hz units 32 bit unsigned little endian
    ul32 txfreq;        // byte[4]  - TX Frequency in 10Hz units 32 bit unsigned little endian
    ul16 rxtone;        // byte[2]  - RX Sub Tone CTCSS: 0.1Hz units,  DCS: codeword|0x8000[|0x4000 for reverse tone] . 16 bit unsigned little endian
    ul16 txtone;        // byte[2]  - TX Sub Tone (as rx sub tone)
    u8 txpower;         // byte[1]  - TX Power - 8 bit unsigned
    u16 group2:4,       // bit[4]   - Group membership. 0=No group, 1-15=group A-O
        group1:4,       // bit[4]   - Group membership. 0=No group, 1-15=group A-O
        group4:4,       // bit[4]   - Group membership. 0=No group, 1-15=group A-O
        group3:4;       // bit[4]   - Group membership. 0=No group, 1-15=group A-O
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
    #printoffset "thisis_0xC8";
    // Block 0xC8
    u16 magic;                  // byte[2] = 0x9BCF (magic value)
    u8 squelch;                 // byte[1] = squelch, 8 bit unsigned but only valid values are 0-9
    ul16 step;                  // byte[2] = step, 16 bit unsigned little endian. 10Hz units
    u8 micgain;                 // byte[1] = mic gain, 8 bit unsigned but only valid values are 0-31
    u8 lcd;                     // byte[1] = LCD brightness, 8 bit unsigned, valid 0-28
    u8 subtonedev;              // byte[1] = Sub Tone deviation, 8 bit unsigned, valid 0-127
    u8 keytones;                // byte[1] = Key tones, bool
    u8 opmode;                  // byte[1] = Operation mode, 0=VFO, 1=Channel, 2=Group
    u8 channel;                 // byte[1] = current channel 0-199 the channel currently being used (0 and 1 are VFO-A and VFO-B, 2 is channel1, 3 is channel2 etc..)
    u8 lastchannel;             // byte[1] = Last channel 2-199 the last channel used in channel or group mode. 
    u8 group;                   // byte[1] = current group 1-15
    u8 scanlinger;              // byte[1] = scan linger (0A = 10)
    ul16 rxfilter;              // byte[2] = RX vhf/uhf filter transition frequency, 16 bit unsigned little endian 100kHz units
    ul16 txfilter;              // byte[2] = TX vhf/uhf filter transition frequency, 16 bit unsigned little endian 100kHz units
    ul16 scansteps;             // byte[2] = The number of frequency steps the VFO scanner will scan before starting at the beginning again (1 - 9999) 
    u8 editchan;                // byte[1] = channel that's the target for editing
    u8 chanfunc;                // byte[1]
    u8 lcdtimeout;              // byte[1] = Period of inactivity (seconds) before the LCD backlight and keypad light turns off. 0=off, 1 - 200
    u8 tonemonitor;             // byte[1] = Controls if the radio will display the sub-tone of a received signal. If in "Clone" mode, it will set the TX CTCSS/DCS setting to match it. 0=off, 1=on, 2=clone
    ul16 reptone;               // byte[2] = in Hz
    u8 battstyle;               // byte[1] = 0=off, 1=icon, 2=percentage, 3=voltage
    u8 activevfo;               // byte[1] = 0=VFO-A, 1=VFO-B (single PTT mode only)
    u8 dualwatch;               // byte[1] = bool
    u8 counterlev;              // byte[1] = Sets the sensitivity of the frequency counter. The higher the value, the stronger a signal needs to be to activate the detection. (100-254)
    u8 activeplan;              // byte[1] = current band plan in use, 0xff = no matched plan
    u8 txmodview;               // byte[1] = bool, tx modulation meter enabled
    
    // Block 0xC9
    u8 voxlevel;                // byte[1] = VOX Sensitivity (Values: Off, 1-15)
    u8 voxtail;                 // byte[1] = Centisecond pause before VOX TX is dropped after TX modulation stops. (Values: 50-255)
    ul16 txtimeout;             // byte[2] = Maximum TX time in seconds (1-300)
    ul32 fmtunerfreq;           // byte[4] = 
    u8 fmtunerband;             // byte[1] = 
    u8 fmtunerpresentbank;      // byte[1] = 
    u8 fmtunersquelch;          // byte[1] = (bool)
    u8 fmtunermonitorht;        // byte[1] = 
    u8 rfgain;                  // byte[1] = Selects RX Gain sensitivity. 1 is least gain and 42 is max gain. AGC will use the automatic gain control. (0=AGC, 1-42)
    u8 squelchtail;             // byte[1] = Amount of time in deciseconds the squelch will remain open after a signal is lost. (1-20)
    u8 squelchtailelimination;  // byte[1] = Squelch tail elimination (0=off, 1=rx, 2=tx, 3=both)
    u8 dualptt;                 // byte[1] = bool
    u8 wakescreen;              // byte[1] = (0=Keys + RX, 1=Keys only, 2=Dimmer)
    u8 showscanfreq;            // byte[1] = Sets if the displayed frequency on the screen will update during scanning. Off, 1-25
    u8 rxexpander;              // byte[1] = Enables an audio processing feature that reduces static hiss with the trade-off being reduced audio quality (0=off, 1=1:2, 2=1:3, 3=1:4)    
    ul16 stepfm;                // byte[1] =
    ul16 stepam;                // byte[1] =
    ul16 stepusb;               // byte[1] =
    u8 scanhold;                // byte[1] =
    u8 vfodisable;              // byte[1] = bool
    u8 scopedisable;            // byte[1] =
    u8 counterdisable;          // byte[1] =
    u8 tunerdisable;            // byte[1] =
    u8 disabledmenus[9];        // menu numbers to disable
  
    // Block 0xCA
    u8 disabledmenusmagic;
    u8 affilters;
    u8 bton;
    u8 leftactive; 
    u8 rightactive;
    u8 rightinuse;
    u8 lastleftactive; 
    u8 lastrightactive;
    u8 keylck;
    u8 instantsave; 
    u8 hfModFilters; 
    u8 txdeviation;
} settings;

#seekto 0x1960;
ul32 fmpresetfreq[20];
u8 fmpresetband[20];

#seekto 0x19E2;
struct {
    ul32 startfreq;
    ul32 endfreq;
    u8 maxpower;
    u8 bandwidthbp:3,
       modulationbp:3,
       wrap:1,    
       txallowed:1;     
} bandplans[20];

#printoffset "thisis_0xD8"; // 6826
#seekto 0x1AE0; // 6880

 
struct{
    ul32 startscanfreq;
    ul16 numbersearches;
    u8 squelchscan;
    u8 squelchtailscan;
    ul16 stepscan;
    u8 scanhold;
    u8 scantail;
    u8 updatescan;
    u8 modulationscan; 

    } scanpresets[10];
"""


# 1 1 1 1 1 1 1 1
#               * = tx allowed
#             *   = wrap
#       * * *     = modulation
# * * *           = bandwith

    # u8 txallowed:1,
    #    wrap:1,
    #    modulation:3,    
    #    bandwidth:3; 

CMD_DISABLE_RADIO           = b'\x45' # w/  Ack
CMD_ENABLE_RADIO            = b'\x46' # w/  Ack
CMD_READ_EEPROM             = b'\x30' # w/  Ack
CMD_WRITE_EEPROM            = b'\x31' # w/  Ack
CMD_RESET_RADIO             = b'\x49' # wo/  Ack
CMD_END_REMOTE_SESSION      = b'\x4B' # w/  Ack

MAGIC_SETTINGS              = 0x9BCF
MAGIC_BANDPLAN              = 0x6DA4

BLOCK_DATA_SIZE = 0x0020
INIT_ADDR_CHANNELS = 0x0040
INIT_ADDR_SETTINGS = 0x1900
BLOCK_CHANNEL = range(1,200)
BLOCK_SETTINGS = 200
END_BLOCK = 221


# Basic Settings
GROUPS_LIST         = ["None","A", "B", "C","D","E","F","G","H","I","J","K","L","M","N","O"]
MODULATION_LIST     = ["Auto", "FM", "AM", "USB"]
BANDWIDTH_LIST      = ["Wide", "Narrow"]
SQUELCH_LIST        = ['Off' if x == 0 else f'{x}' for x in range(0, 10)]
OP_MODES            = ["VFO", "Channel", "Group"]
MICGAIN_LIST        = [f'{x}' for x in range(0, 32)]
LCDBRIGHT_LIST      = [f'{x}' for x in range(0, 29)]
SUBTONEDEV_LIST     = [f'{x}' for x in range(0, 128)]
SCANLINGER_LIST     = [f'{x}' for x in range(10, 128)]
POWERLEVEL_LIST     = ['N/T' if x == 0 else f'{x}' for x in range(0, 256)]
LCDTIMEOUT_LIST     = ['Off' if x == 0 else f'{x}' for x in range(0, 201)]
BATTSTYLE_LIST      = ["Off", "Icon", "Percentage", "Voltage"]
TONEMONITOR_LIST    = ["Off", "On", "Clone"]
ACTIVEVFO_LIST      = ["VFO-A", "VFO-B"]
WAKESCREEN_LIST     = ["Keys + RX", "Keys Only", "Dimmer"]
RXEXPANDER_LIST     = ["Off", "1:2", "1:3", "1:4"]
VOXLEVEL_LIST       = ['Off' if x == 0 else f'{x}' for x in range(0, 16)]
RFGAIN_LIST         = ['AGC' if x == 0 else f'{x}' for x in range(0, 43)]
SQUELCHTAIL_LIST    = ['Off' if x == 0 else f'{x}' for x in range(0, 21)]
SQUELCHTAILELIMINATION_LIST = ["Off", "Rx", "Tx", "Both"]
SHOWSCANFREQ_LIST   = ['Off' if x == 0 else f'{x}' for x in range(0, 26)]
SCANHOLD_LIST       = ['Off' if x == 0 else f'{x}' for x in range(0, 201)]
AFFILTERS_LIST      = ["All" ,"Band Pass Only" ,"De-Emphasis + High Pass" ,"High Pass Only" ,"De-Emphasis + Low Pass" ,"Low Pass Only" ,"De-Emphasis Only" ,"None"]
MODULATIONBP_LIST   = ["Ignore", "FM", "AM", "USB", "Enforce FM", "Enforce AM", "Enforce USB", "Enforce None"]
BANDWIDTHBP_LIST    = ["Ignore", "Wide", "Narrow", "Enforce Wide", "Enforce Narrow"]
MAXPOWERBP_LIST     = ['Ignore' if x == 0 else f'{x}' for x in range(0, 256)]
BANDFMTUNER_LIST    = ['West', 'Japan', 'World', 'Low VHF']
SQUELCHSCAN_LIST    = [f'{x}' for x in range(1, 10)]
MODULATIONSCAN_LIST = ["FM", "AM", "USB"]

def _do_status(radio, block):
    status = chirp_common.Status()
    status.msg = "Cloning"
    status.cur = block
    status.max = BLOCK_CHANNEL[-1]
    radio.status_fn(status)

def write_cmd(radio, cmd, check_ack=False):
    serial = radio.pipe
    serial.write(cmd)
    serial.timeout = 0.5
    if check_ack == True:
        ack = serial.read(1)
        if ack != cmd:
            LOG.debug("[ERR] Unable to communicate with nicFW -- there was no valid ACK for {} command ({} received).".format(cmd,ack))

def _enter_programming_mode(radio):
    write_cmd(radio, CMD_ENABLE_RADIO, check_ack=True)

def _exit_programming_mode(radio):
    write_cmd(radio, CMD_DISABLE_RADIO, check_ack= True)

def _reset_radio(radio):
    write_cmd(radio, CMD_RESET_RADIO, check_ack= False)

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

    if ack != CMD_WRITE_EEPROM:
       LOG.debug("Received {} expected {} checksum mismatch while writing!".format(ack,CMD_WRITE_EEPROM))     
    
def do_download(radio):
    """This is your download channels function"""
    _enter_programming_mode(radio)

    data = b""
    data = bytearray()

    for i in range(1,END_BLOCK):
        block = _read_block(radio, i)
        data.extend(block)
        LOG.info("Block: %i",i)
        LOG.info(util.hexprint(bytes(block)))
        _do_status(radio, i)
 
    _exit_programming_mode(radio)

    return memmap.MemoryMapBytes(bytes(data))

def _do_upload(radio):
    """This is your download settings function"""
    _enter_programming_mode(radio)

    LOG.debug("Uploading...")

    for i in range(1,END_BLOCK):
        addr = (i-1) * BLOCK_DATA_SIZE
        data = radio.get_mmap()[addr:addr+BLOCK_DATA_SIZE]
        _write_block(radio, i, data)
        _do_status(radio, addr)
        LOG.debug("writemem sent data offset=0x%4.4x len=0x%4.4x:\n%s" %
            (addr, len(data), util.hexprint(data)))

    _exit_programming_mode(radio)
    _reset_radio(radio)

def encode_tone(mode, value, polarity=None):
    # Handle CTCSS tone mode
    if mode == "Tone" and isinstance(value, (int, float)):
        tone_word = round(value * 10.0)  # Convert Hz to 0.1 Hz units
        if 0 <= tone_word <= 3000:
            return tone_word
    
    # Handle DCS tone mode
    elif mode == "DTCS" and isinstance(value, int) and 1 <= value <= 511:
        tone_word = 0x8000 | value  # Set the DCS flag
        if polarity == "I":         # Check if inverted polarity
            tone_word |= 0x4000     # Set the inversion flag
        return tone_word

    # Return 0 if mode is None or invalid
    return 0

def decode_tone(tone_word):
    # Check if the tone word is in the CTCSS range
    if 0 < tone_word <= 3000:
        # Return as CTCSS tone in Hz
        return "Tone", tone_word / 10.0, None

    # Check if the tone word is a DCS code
    elif tone_word & 0x8000:
        # Extract the DCS code (lower 9 bits)
        dcs_code = tone_word & 0x01FF
        # Check if the inversion flag is set for inverted polarity
        polarity = "R" if (tone_word & 0x4000) != 0 else "N"
        if 1 <= dcs_code <= 511:
            return "DTCS", dcs_code, polarity

    # Return None for invalid tone words
    return None, None, None

# helper function
def append_label(radio_setting, label, descr=""):
    if not hasattr(append_label, 'idx'):
        append_label.idx = 0

    val = RadioSettingValueString(len(descr), len(descr), descr)
    val.set_mutable(False)
    rs = RadioSetting("label" + str(append_label.idx), label, val)
    append_label.idx += 1
    radio_setting.append(rs)



@directory.register
class TH3NicFw(chirp_common.CloneModeRadio):
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
        rf.has_settings = True
        rf.has_bank = False
        rf.has_tuning_step = False
        rf.has_rx_dtcs = True
        rf.has_ctone = True
        rf.has_comment = False


        rf.memory_bounds = (1, 198)
        rf.valid_tmodes = ["", "Tone", "TSQL", "DTCS", "Cross"]
        rf.valid_cross_modes = ["Tone->Tone", "Tone->DTCS", "DTCS->Tone",
                                "->Tone", "->DTCS", "DTCS->", "DTCS->DTCS"]
        rf.valid_characters = chirp_common.CHARSET_ASCII
        rf.valid_bands = self.VALID_BANDS
        rf.valid_modes = MODULATION_LIST
        rf.valid_duplexes = ["", "-", "+", "split", "off"]
        rf.valid_skips = ["", "S"]
        rf.valid_name_length = 12
        rf.valid_power_levels = POWERLEVEL_LIST

        return rf
    
 
    # Do a download of the radio from the serial port
    def sync_in(self):
        try:
            self._mmap = do_download(self)
            self.process_mmap()
        except Exception as e:
            raise errors.RadioError("Failed to communicate with radio: %s" % e)
 
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

    def _get_mem(self, number):
        return self._memobj.memory[number]

    def get_memory(self, number):
        _mem = self._get_mem(number)
    
        # Create a high-level memory object to return to the UI
        mem = chirp_common.Memory()
        mem.number = number                 # Set the memory number

        # LOG.info("Doing channel %i ",number)
    
        # We'll consider any blank (i.e. 0 MHz frequency) to be empty
        if _mem.get_raw()[0] == 0xff:
            mem.empty = True
            # LOG.info("Channel %i is empty!",number)
            return mem
        
        # Convert your low-level frequency to Hertz
        mem.freq = int(_mem.rxfreq) * 10

        mem.power = POWERLEVEL_LIST[int(_mem.txpower)]

        # Channel name
        for char in _mem.name:
            if "\x00" in str(char) or "\xFF" in str(char):
                char = ""
            mem.name += str(char)
        mem.name = mem.name.rstrip()

        chirp_common.split_tone_decode(mem, decode_tone(_mem.txtone),
                                            decode_tone(_mem.rxtone))


        # Offset
        if int(_mem.rxfreq) == int(_mem.txfreq):
            mem.duplex = ""
            mem.offset = 0
        else:
            mem.duplex = int(_mem.rxfreq) > int(_mem.txfreq) and "-" or "+"
            mem.offset = abs(int(_mem.rxfreq) - int(_mem.txfreq)) * 10

        mem.mode = MODULATION_LIST[int(_mem.modulation)]  



        mem.extra = RadioSettingGroup("Extra", "extra")

        rs = RadioSettingValueInteger(0, 255, _mem.txpower)
        rset = RadioSetting("txpower", "TX Power", rs)
        mem.extra.append(rset)

        rs = RadioSettingValueList(GROUPS_LIST, current_index = _mem.group1)
        rset = RadioSetting("group1", "Grp Slot 1", rs)
        mem.extra.append(rset)
        
        rs = RadioSettingValueList(GROUPS_LIST, current_index = _mem.group2)
        rset = RadioSetting("group2", "Grp Slot 2", rs)
        mem.extra.append(rset)

        rs = RadioSettingValueList(GROUPS_LIST, current_index =_mem.group3)
        rset = RadioSetting("group3", "Grp Slot 3", rs)
        mem.extra.append(rset)
       
        rs = RadioSettingValueList(GROUPS_LIST, current_index = _mem.group4)
        rset = RadioSetting("group4", "Grp Slot 4", rs)
        mem.extra.append(rset)

        bandwidth = "Narrow" if _mem.bandwidth  else "Wide"
        rs = RadioSettingValueList(BANDWIDTH_LIST, bandwidth)
        rset = RadioSetting("bandwidth", "Bandwidth", rs)
        mem.extra.append(rset)

        msgs = self.validate_memory(mem)

        if msgs != []:
            LOG.info("Following warnings were generating while validating channels:")
            LOG.info(msgs)

        return mem
    
    def set_memory(self, mem):
        # Get a low-level memory object mapped to the image
        _mem = self._get_mem(mem.number)

        # if empty memory
        if mem.empty:
            _mem.set_raw("\xFF" * 22 + "\x20" * 10)
            return
        
        if mem.duplex == "split":
            _mem.txfreq = mem.offset / 10
        elif mem.duplex == "+":
            _mem.txfreq = (mem.freq + mem.offset) / 10
        elif mem.duplex == "-":
            _mem.txfreq = (mem.freq - mem.offset) / 10
        else:
            _mem.txfreq = mem.freq / 10

        _mem.name = mem.name.rstrip('\xFF').ljust(12, '\x20')

        ((txmode, txtone, txpol),
         (rxmode, rxtone, rxpol)) = chirp_common.split_tone_encode(mem)

        
        _mem.txtone = int(encode_tone(txmode, txtone, txpol))
        _mem.rxtone = int(encode_tone(rxmode, rxtone, rxpol))



        #extra
        for element in mem.extra:
            sname  = element.get_name()
            svalue = element.value.get_value()

            if sname == 'txpower':
                _mem.txpower = element.value

            if sname == 'bandwidth':
                _mem.bandwidth = 1 if element.value=="Narrow" else 0

            if sname == "modulation":
                _mem.modulation = MODULATION_LIST.index(svalue)

            if sname == "group1":
                _mem.group1 = GROUPS_LIST.index(svalue)

            if sname == "group2":
                _mem.group2 = GROUPS_LIST.index(svalue)

            if sname == "group3":
                _mem.group3 = GROUPS_LIST.index(svalue)

            if sname == "group4":
                _mem.group4 = GROUPS_LIST.index(svalue)


        return mem

    def set_settings(self, settings):
        _mem = self._memobj
        _settings = _mem.settings
        _bandplans = _mem.bandplans
        _scanpresets = _mem.scanpresets

        for element in settings:
            if not isinstance(element, RadioSetting):
                self.set_settings(element)
                continue
        
        # Basic Settings        

            # Squelch
            if element.get_name() == "squelch":
                _settings.squelch = SQUELCH_LIST.index(str(element.value))

            # Step
            if element.get_name() == "step":
                _settings.step = element.value * 100

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
                _settings.scanlinger = int(element.value)

            # RX VHF/UHF Filter Transition Frequency
            if element.get_name() == "rxfilter":
                _settings.rxfilter = int(element.value * 10)
            
            # TX VHF/UHF Filter Transition Frequency
            if element.get_name() == "txfilter":
                _settings.txfilter = int(element.value * 10) 

            # Scan Steps
            if element.get_name() == "scansteps":
                _settings.scansteps = int(element.value) 

            # LCD Timeout
            if element.get_name() == "lcdtimeout":
                _settings.lcdtimeout = LCDTIMEOUT_LIST.index(str(element.value))

            # Tone Monitor
            if element.get_name() == "tonemonitor":
                _settings.lcdtimeout = TONEMONITOR_LIST.index(str(element.value))
            
            # Rep Tone
            if element.get_name() == "reptone":
                _settings.reptone = float(element.value)
            
            # Frequency Counter Sensitivity
            if element.get_name() == "counterlev":
                _settings.counterlev = int(element.value)  

            # TX Modulation Meter Enabled
            if element.get_name() == "txmodview":
                _settings.txmodview = element.value and 1 or 0  
            
            # VOX Level
            if element.get_name() == "voxlevel":
                _settings.voxlevel = VOXLEVEL_LIST.index(str(element.value))

            # VOX Tail
            if element.get_name() == "voxtail":
                _settings.voxtail = int(element.value)  

            # TX Timeout
            if element.get_name() == "txtimeout":
                _settings.txtimeout = int(element.value)  

            # RF Sensitivity
            if element.get_name() == "rfgain":
                _settings.rfgain = RFGAIN_LIST.index(str(element.value))  

            # Squelch Tail          
            if element.get_name() == "squelchtail":
                _settings.squelchtail = int(element.value)  

            # Squelch Tail Elimination 
            if element.get_name() == "squelchtailelimination":
                _settings.squelchtailelimination = SQUELCHTAILELIMINATION_LIST.index(str(element.value))  

            # Dual PTT
            if element.get_name() == "dualptt":
                _settings.dualptt = element.value and 1 or 0         

            # Wake Screen
            if element.get_name() == "wakescreen":
                _settings.wakescreen = WAKESCREEN_LIST.index(str(element.value))                    
                      
            # Show Scan Frq              
            if element.get_name() == "showscanfreq":
                _settings.showscanfreq = SHOWSCANFREQ_LIST.index(str(element.value))                    
                
            # Rx Expander 
            if element.get_name() == "rxexpander":
                _settings.rxexpander = RXEXPANDER_LIST.index(str(element.value))                    
           
            # Step AM
            if element.get_name() == "stepam":
                _settings.stepam = element.value * 100 

            # Step FM
            if element.get_name() == "stepfm":
                _settings.stepfm = element.value * 100     

            # Step USB
            if element.get_name() == "stepusb":
                _settings.stepusb = element.value * 100  

            # Scan Hold Seconds                            
            if element.get_name() == "scanhold":
                _settings.scanhold = SCANHOLD_LIST.index(str(element.value))  

            # Bluetooth On
            if element.get_name() == "bton":
                _settings.bton = element.value and 1 or 0  

            # AF Filters
            if element.get_name() == "affilters":
                _settings.affilters = AFFILTERS_LIST.index(str(element.value))

        # Restrictions

            # VFO Disable
            if element.get_name() == "vfodisable":
                _settings.vfodisable = element.value and 1 or 0 

            # Frequency Scope Disable            
            if element.get_name() == "scopedisable":
                _settings.scopedisable = element.value and 1 or 0  

            # Frequency Counter Disable          
            if element.get_name() == "counterdisable":
                _settings.counterdisable = element.value and 1 or 0  

            # FM Tuner Disable            
            if element.get_name() == "tunerdisable":
                _settings.tunerdisable = element.value and 1 or 0  

                
        # Bandplan
            for i in range(0,20):
                _bandplan = _bandplans[i]    
                if element.get_name() == "startfreq_{}".format(i):
                    _bandplan.startfreq = int(element.value) * 100000
                if element.get_name() == "endfreq_{}".format(i):
                    _bandplan.endfreq = int(element.value) * 100000
                if element.get_name() == "maxpower_{}".format(i):
                    _bandplan.maxpower = MAXPOWERBP_LIST.index(str(element.value))
                if element.get_name() == "bandwidthbp_{}".format(i):
                    _bandplan.bandwidthbp = BANDWIDTHBP_LIST.index(str(element.value))
                if element.get_name() == "modulationbp_{}".format(i):
                    _bandplan.modulationbp = MODULATIONBP_LIST.index(str(element.value))
                if element.get_name() == "wrap_{}".format(i):
                    _bandplan.wrap = element.value and 1 or 0  
                if element.get_name() == "txallowed_{}".format(i):
                    _bandplan.txallowed = element.value and 1 or 0  

        # Scan Presets

            for i in range(0,10):
                _scanpreset = _scanpresets[i]
                if element.get_name() == "startscanfreq_{}".format(i):
                    _scanpreset.startscanfreq = int(element.value) * 100000
                if element.get_name() == "numbersearches_{}".format(i):
                    _scanpreset.numbersearches = int(element.value)                  
                if element.get_name() == "stepscan_{}".format(i):
                    _scanpreset.stepscan = int(element.value) * 100
                if element.get_name() == "squelchscan_{}".format(i):
                    _scanpreset.squelchscan = SQUELCHSCAN_LIST.index(str(element.value))
                if element.get_name() == "squelchtailscan_{}".format(i):
                    _scanpreset.squelchtailscan = int(element.value)  
                if element.get_name() == "scanhold_{}".format(i):
                    _scanpreset.scanhold = int(element.value)
                if element.get_name() == "scantail_{}".format(i):
                    _scanpreset.scantail = int(element.value)
                if element.get_name() == "updatescan_{}".format(i):
                    _scanpreset.updatescan = int(element.value)
                if element.get_name() == "modulationscan_{}".format(i):
                    _scanpreset.squelchscan = MODULATIONSCAN_LIST.index(str(element.value))


        # FM Tuner
            for i in range(0,20):  
                if element.get_name() == "fmfreq_{}".format(i):
                    _mem.fmpresetfreq[i] = int(element.value * 1000)
                if element.get_name() == "fmband_{}".format(i):
                    _mem.fmpresetband[i] = BANDFMTUNER_LIST.index(str(element.value))



    def get_settings(self):
        _mem = self._memobj
        
        basic = RadioSettingGroup("basic", "Basic Settings")
        fmtuner = RadioSettingGroup("fmtuner", "FM Tuner")
        bandplan = RadioSettingGroup("bandplan", "Band Plan")
        restrictions = RadioSettingGroup("restrictions", "Restrictions")
        scanpresetlist = RadioSettingGroup("scanpresetlist", "Scan Preset")

        group = RadioSettings(basic, bandplan, restrictions, fmtuner, scanpresetlist)
        
        # Basic Settings
        rs = RadioSettingValueList(SQUELCH_LIST, current_index = _mem.settings.squelch)
        rset = RadioSetting("squelch", "Squelch Level", rs)
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

        keytones = bool(_mem.settings.keytones)
        rs = RadioSettingValueBoolean(keytones)
        rset = RadioSetting("keytones", "Key Tones", rs)
        basic.append(rset)

        opmode = _mem.settings.opmode
        rs = RadioSettingValueList(OP_MODES, current_index = opmode)
        rset = RadioSetting("opmode", "Operation Mode", rs)
        basic.append(rset)

        scanlinger = int(_mem.settings.scanlinger)
        rs = RadioSettingValueInteger(10,127,scanlinger)
        rset = RadioSetting("scanlinger", "Scan Tail [10 - 127]", rs)
        basic.append(rset)

        rxfilter = float(_mem.settings.rxfilter) / 10
        rs = RadioSettingValueFloat(150, 400, rxfilter, resolution= 0.1, precision=1)
        rset = RadioSetting("rxfilter", "RX VHF/UHF Filter Transition Frequency", rs)
        basic.append(rset)

        txfilter = float(_mem.settings.txfilter) / 10
        rs = RadioSettingValueFloat(150, 400, txfilter, resolution= 0.1, precision=1)
        rset = RadioSetting("txfilter", "TX VHF/UHF Filter Transition Frequency", rs)
        basic.append(rset)

        scansteps = _mem.settings.scansteps
        rs = RadioSettingValueInteger(1,9999,int(scansteps))
        rset = RadioSetting("scansteps", "Scan Steps", rs)
        basic.append(rset)

        lcdtimeout = _mem.settings.lcdtimeout
        rs = RadioSettingValueList(LCDTIMEOUT_LIST, current_index = lcdtimeout)
        rset = RadioSetting("lcdtimeout", "LCD Timeout [sec]", rs)
        basic.append(rset)

        tonemonitor = _mem.settings.tonemonitor
        rs = RadioSettingValueList(TONEMONITOR_LIST, current_index = tonemonitor)
        rset = RadioSetting("tonemonitor", "Tone Monitor", rs)
        basic.append(rset)

        reptone = int(_mem.settings.reptone)
        rs = RadioSettingValueInteger(100, 5000, reptone)
        rset = RadioSetting("reptone", "Repeater Tone", rs)
        basic.append(rset)

        battstyle = _mem.settings.battstyle
        rs = RadioSettingValueList(BATTSTYLE_LIST, current_index = battstyle)
        rset = RadioSetting("battstyle", "Battery Style", rs)
        basic.append(rset)

        activevfo = _mem.settings.activevfo
        rs = RadioSettingValueList(ACTIVEVFO_LIST, current_index = activevfo)
        rset = RadioSetting("activevfo", "LCD Timeout [sec]", rs)
        basic.append(rset)

        dualwatch = bool(_mem.settings.dualwatch)
        rs = RadioSettingValueBoolean(dualwatch)
        rset = RadioSetting("dualwatch", "Dual Watch Enable", rs)
        basic.append(rset)

        counterlev = int(_mem.settings.counterlev)
        rs = RadioSettingValueInteger(100,254,counterlev)
        rset = RadioSetting("counterlev", "Frequency Scan Level [100 - 254]", rs)
        basic.append(rset)

        txmodview = bool(_mem.settings.txmodview)
        rs = RadioSettingValueBoolean(txmodview)
        rset = RadioSetting("txmodview", "TX Modulation Meter Enable", rs)
        basic.append(rset)

        voxlevel = int(_mem.settings.voxlevel)
        rs = RadioSettingValueList(VOXLEVEL_LIST, current_index = voxlevel)
        rset = RadioSetting("voxlevel", "VOX Level", rs)
        basic.append(rset)

        voxtail = int(_mem.settings.voxtail)
        rs = RadioSettingValueInteger(50,255,voxtail)
        rset = RadioSetting("voxtail", "VOX Tail [50-255]", rs)
        basic.append(rset)

        txtimeout = int(_mem.settings.txtimeout)
        rs = RadioSettingValueInteger(50,255,txtimeout)
        rset = RadioSetting("txtimeout", "TX Timeout [1-300]", rs)
        basic.append(rset)
        
        rfgain = int(_mem.settings.rfgain)
        rs = RadioSettingValueList(RFGAIN_LIST, current_index = rfgain)
        rset = RadioSetting("rfgain", "RX Gain Sensitivity", rs)
        basic.append(rset)
        
        squelchtail = int(_mem.settings.squelchtail)
        rs = RadioSettingValueList(SQUELCHTAIL_LIST, current_index = squelchtail)
        rset = RadioSetting("squelchtail", "Squelch Tail", rs)
        basic.append(rset)

        squelchtailelimination = int(_mem.settings.squelchtailelimination)
        rs = RadioSettingValueList(SQUELCHTAILELIMINATION_LIST, current_index = squelchtailelimination)
        rset = RadioSetting("squelchtailelimination", "Squelch Tail Elimination", rs)
        basic.append(rset)

        dualptt = bool(_mem.settings.dualptt)
        rs = RadioSettingValueBoolean(dualptt)
        rset = RadioSetting("dualptt", "VFO PTT Dual Mode Enable ", rs)
        basic.append(rset)

        wakescreen = int(_mem.settings.wakescreen)
        rs = RadioSettingValueList(WAKESCREEN_LIST, current_index = wakescreen)
        rset = RadioSetting("wakescreen", "Wake Screen Method", rs)
        basic.append(rset)

        rxexpander = int(_mem.settings.rxexpander)
        rs = RadioSettingValueList(RXEXPANDER_LIST, current_index = rxexpander)
        rset = RadioSetting("rxexpander", "RX Expander", rs)
        basic.append(rset)

        stepam = float(_mem.settings.stepam) / 100
        rs = RadioSettingValueFloat(0.01, 500, stepam, resolution=0.01, precision=2)
        rset = RadioSetting("stepam", "Step Size AM", rs)
        basic.append(rset)

        stepfm = float(_mem.settings.stepfm) / 100
        rs = RadioSettingValueFloat(0.01, 500, stepfm, resolution=0.01, precision=2)
        rset = RadioSetting("stepfm", "Step Size FM", rs)
        basic.append(rset)

        stepusb = float(_mem.settings.stepusb) / 100
        rs = RadioSettingValueFloat(0.01, 500, stepusb, resolution=0.01, precision=2)
        rset = RadioSetting("stepusb", "Step Size USB", rs)
        basic.append(rset)

        scanhold = int(_mem.settings.scanhold)
        rs = RadioSettingValueList(SCANHOLD_LIST, current_index = scanhold)
        rset = RadioSetting("scanhold", "Scan Hold Seconds", rs)
        basic.append(rset)

        bton = bool(_mem.settings.bton)
        rs = RadioSettingValueBoolean(bton)
        rset = RadioSetting("bton", "Bluetooth On ", rs)
        basic.append(rset)

        affilters = int(_mem.settings.affilters)
        rs = RadioSettingValueList(AFFILTERS_LIST, current_index = affilters)
        rset = RadioSetting("affilters", "AF Filters", rs)
        basic.append(rset)

        # FM Tuner
        for i in range(len(_mem.fmpresetfreq)):
            append_label(fmtuner, "_" * 30 + "FM Tuner Slot {}".format(i+1) + "_" * 274, "_" * 300)
            
            curr_fmfreq = int(_mem.fmpresetfreq[i]) / 1000.0
            if curr_fmfreq:
                rs = RadioSettingValueFloat(87, 108, curr_fmfreq, resolution=0.001, precision=3)
            else:
                rs = RadioSettingValueFloat(0, 108, curr_fmfreq, resolution=0.001, precision=3)
            rset = RadioSetting("fmfreq_{}".format(i), "Frequency", rs)
            fmtuner.append(rset)

            curr_fmband = int(_mem.fmpresetband[i])
            rs = RadioSettingValueList(BANDFMTUNER_LIST, current_index = curr_fmband)
            rset = RadioSetting("fmband_{}".format(i), "Band", rs)
            fmtuner.append(rset)

        append_label(fmtuner, "_" * 30 + "FM Tuner Settings" + "_" * 274, "_" * 300)

        fmtunersquelch = bool(_mem.settings.fmtunersquelch)
        rs = RadioSettingValueBoolean(fmtunersquelch)
        rset = RadioSetting("fmtunersquelch", "FM Tuner Squelch", rs)
        fmtuner.append(rset)

        fmtunermonitorht = int(_mem.settings.fmtunermonitorht)
        rs = RadioSettingValueBoolean(fmtunermonitorht)
        rset = RadioSetting("fmtunermonitorht", "HT Monitoring", rs)
        fmtuner.append(rset)


        # Band Plan
        for i in range(len(_mem.bandplans)):
            append_label(bandplan, "_" * 30 + "Band Plan Slot {}".format(i+1) + "_" * 274, "_" * 300)

            curr_bp = _mem.bandplans[i]

            startfreq = int(curr_bp.startfreq) / 100000
            if startfreq:
                rs = RadioSettingValueFloat(18, 1300, startfreq, resolution= 0.00001, precision=5)
            else:
                rs = RadioSettingValueFloat(0, 1300, startfreq, resolution= 0.00001, precision=5)
            rset = RadioSetting("startfreq_{}".format(i), "Start Frequency".format(i), rs)
            bandplan.append(rset)

            endfreq = int(curr_bp.endfreq) / 100000
            if endfreq:
                rs = RadioSettingValueFloat(18, 1300, endfreq, resolution= 0.00001, precision=5)
            else:
                rs = RadioSettingValueFloat(0, 1300, endfreq, resolution= 0.00001, precision=5)
            rset = RadioSetting("endfreq_{}".format(i), "End Frequency".format(i), rs)
            bandplan.append(rset)

            txallowed = bool(curr_bp.txallowed)
            rs = RadioSettingValueBoolean(txallowed)
            rset = RadioSetting("txallowed_{}".format(i), "TX Allowed".format(i), rs)
            bandplan.append(rset)

            modulationbp = int(curr_bp.modulationbp)
            rs = RadioSettingValueList(MODULATIONBP_LIST, current_index = modulationbp)
            rset = RadioSetting("modulationbp_{}".format(i), "Modulation".format(i), rs)
            bandplan.append(rset)

            bandwidthbp = int(curr_bp.bandwidthbp)
            rs = RadioSettingValueList(BANDWIDTHBP_LIST, current_index = bandwidthbp)
            rset = RadioSetting("bandwidthbp_{}".format(i), "Bandwidth".format(i), rs)
            bandplan.append(rset)

            maxpower = int(curr_bp.maxpower)
            rs = RadioSettingValueList(MAXPOWERBP_LIST, current_index = maxpower)
            rset = RadioSetting("maxpower_{}".format(i), "Max Power".format(i), rs)
            bandplan.append(rset)

        # Scan Presets

        for i in range(len(_mem.scanpresets)):
            
            append_label(scanpresetlist, "_" * 30 + "Scan Preset {}".format(i+1) + "_" * 274, "_" * 300)

            scanpreset = _mem.scanpresets[i]

            startscanfreq = int(scanpreset.startscanfreq) 
            if startscanfreq:
                rs = RadioSettingValueFloat(18, 1300, startscanfreq / 100000, resolution= 0.00001, precision=5)
            else:
                rs = RadioSettingValueFloat(0, 1300, startscanfreq / 100000, resolution= 0.00001, precision=5)
            rset = RadioSetting("startscanfreq_{}".format(i), "Start Frequency", rs)
            scanpresetlist.append(rset)

            numbersearches = int(scanpreset.numbersearches)
            rs = RadioSettingValueInteger(1, 65535, numbersearches)
            rset = RadioSetting("numbersearches_{}".format(i), "Number of step intervals", rs)
            scanpresetlist.append(rset)

            stepscan= int(scanpreset.stepscan)  
            if stepscan:
                rs = RadioSettingValueFloat(0.01, 500, stepscan / 100, resolution= 0.01, precision=2)
            else:
                rs = RadioSettingValueFloat(0, 500, stepscan / 100, resolution= 0.01, precision=2)
            rset = RadioSetting("stepscan_{}".format(i), "Step Frequency", rs)
            scanpresetlist.append(rset)

            endscanfreq = (startscanfreq + numbersearches * stepscan) / 100000
            rs = RadioSettingValueFloat(endscanfreq, endscanfreq, endscanfreq, resolution= 0.00001, precision=5)
            rs.set_mutable(False)
            rset = RadioSetting("endscanfreq_{}".format(i), "Stop Frequency", rs)
            scanpresetlist.append(rset)

            squelchscan = int(scanpreset.squelchscan)
            rs = RadioSettingValueList(SQUELCHSCAN_LIST, current_index =squelchscan)
            rset = RadioSetting("squelchscan_{}".format(i), "Squelch", rs)
            scanpresetlist.append(rset)

            squelchtailscan = int(scanpreset.squelchtailscan)
            rs = RadioSettingValueInteger(0, 20, squelchtailscan)
            rset = RadioSetting("squelchtailscan_{}".format(i), "Squelch Tail", rs)
            scanpresetlist.append(rset)

            scanhold= int(scanpreset.scanhold)
            rs = RadioSettingValueInteger(0, 200, scanhold)
            rset = RadioSetting("scanhold_{}".format(i), "Scan Hold", rs)
            scanpresetlist.append(rset)

            scantail= int(scanpreset.scantail)
            rs = RadioSettingValueInteger(10, 127, scantail)
            rset = RadioSetting("scantail_{}".format(i), "Scan Tail", rs)
            scanpresetlist.append(rset)

            updatescan= int(scanpreset.updatescan)
            rs = RadioSettingValueInteger(0, 25, updatescan)
            rset = RadioSetting("updatescan_{}".format(i), "Update Scan", rs)
            scanpresetlist.append(rset)

            modulationscan= int(scanpreset.modulationscan)
            rs = RadioSettingValueList(MODULATIONSCAN_LIST, current_index =modulationscan)
            rset = RadioSetting("modulationscan_{}".format(i), "Modulation", rs)
            scanpresetlist.append(rset)





        # Restrictions
        
        vfodisable = bool(_mem.settings.vfodisable)
        rs = RadioSettingValueBoolean(vfodisable)
        rset = RadioSetting("vfodisable", "VFO Disable", rs)
        restrictions.append(rset)

        scopedisable = bool(_mem.settings.scopedisable)
        rs = RadioSettingValueBoolean(scopedisable)
        rset = RadioSetting("scopedisable", "Scope Disable", rs)
        restrictions.append(rset)          

        counterdisable = bool(_mem.settings.counterdisable)
        rs = RadioSettingValueBoolean(counterdisable)
        rset = RadioSetting("counterdisable", "Frequency Counter Disable", rs)
        restrictions.append(rset)        

        tunerdisable = bool(_mem.settings.tunerdisable)
        rs = RadioSettingValueBoolean(tunerdisable)
        rset = RadioSetting("tunerdisable", "FM Tuner Disable", rs)
        restrictions.append(rset)          

        
        
        return group
    
