# SIMK41 / SIMK43 / SIM2K flash layout for Ghidra (PyGhidra)
# @author Dante
# @category OpenGK.SIMK4x
# @runtime PyGhidra
#
# C167CS-LM processor model. VERIFY THE ACTUAL CPU MARKING before using
# this profile on a different SIMK41 / SIMK43 / SIM2K board.
#
# Destructive initial-import script: running it immediately replaces
# every existing memory block. No preview or explicit transaction wrapper.
#
# References:
#   Infineon C167CS Derivatives User's Manual, ch. 3 (memory organization)
#   https://www.keil.com/dd/docs/datashts/infineon/c167cs_um.pdf
#   OpenGK 5WY19 board identification (SAK-C167CS-LM)
#   https://opengk.org/index.php?title=Siemens_5WY19_PCB_Components

# ASSUMPTION: The first 0xC000 file bytes are also accessible at logical
# CPU addresses 0x0000..0xBFFF. Retained from the original loader,
# excluding ranges occupied by C167CS on-chip resources.
# Verify this flash/boot mapping against the board's BUSCON/ADDRSEL setup.
MAP_LOW_FLASH_WINDOW = True

# Preserve the original policy: 0x0000..0x1FFF executable; 0x2000..0xBFFF
# non-executable (it may contain code, but do not auto-disassemble it blindly).
LOW_BOOT_CODE_LENGTH = 0x2000
LOW_FLASH_WINDOW_LENGTH = 0xC000


# Every 'size' is an actual byte count, not an inclusive final offset.
ECU_IDENTIFICATION_TABLE = [
    {
        'offset': 0x82014,
        'expected': [b'6621'],
        'ecu': {
            'name': 'SIMK43 8mbit',
            'flash_size_bytes': 0x100000,
            'bin_offset': 0,
            'bootloader2_section_address': 0x88000,
            'bootloader2_size_bytes': 0x8000,
            'calibration_section_address': 0x90000,
            'calibration_size_bytes': 0x10000,
            'program_section_address': 0xA0000,
            'program_size_bytes': 0x60000,
        },
    },
    {
        'offset': 0x10040,
        'expected': [b'ca66'],
        'ecu': {
            'name': 'SIMK43 2.0 4mbit',
            'flash_size_bytes': 0x80000,
            'bin_offset': -0x80000,
            'bootloader2_section_address': 0x88000,
            'bootloader2_size_bytes': 0x8000,
            'calibration_section_address': 0x90000,
            'calibration_size_bytes': 0x10000,
            'program_section_address': 0xA0000,
            'program_size_bytes': 0x60000,
        },
    },
    {
        'offset': 0x8040,
        'expected': [b'ca65401'],
        'ecu': {
            'name': 'SIMK43 V6 4mbit (5WY17)',
            'flash_size_bytes': 0x80000,
            'bin_offset': -0x80000,
            'bootloader2_section_address': None,
            'bootloader2_size_bytes': None,
            'calibration_section_address': 0x88000,
            'calibration_size_bytes': 0x8000,
            'program_section_address': 0x90000,
            'program_size_bytes': 0x70000,
        },
    },
    {
        'offset': 0x8040,
        'expected': [b'ca660', b'ca652', b'ca650'],
        'ecu': {
            'name': 'SIMK41 / V6 2mbit',
            'flash_size_bytes': 0x40000,
            'bin_offset': -0x40000,
            'bootloader2_section_address': None,
            'bootloader2_size_bytes': None,
            'calibration_section_address': 0x48000,
            'calibration_size_bytes': 0x8000,
            'program_section_address': 0x50000,
            'program_size_bytes': 0x30000,
        },
    },
    {
        'offset': 0x12040,
        'expected': [b'ca66'],
        'ecu': {
            'name': 'SIMK2K (Elantra)',
            'flash_size_bytes': 0x80000,
            'bin_offset': -0x80000,
            'bootloader2_section_address': 0x88000,
            'bootloader2_size_bytes': 0xA000,
            'calibration_section_address': 0x92000,
            'calibration_size_bytes': 0x12000,
            'program_section_address': 0xA4000,
            'program_size_bytes': 0x5C000,
        },
    },
]


def region(name, start, size, read=True, write=False, execute=False,
           file_offset=None, comment=''):
    """file_offset=None means uninitialized runtime memory, not ROM data."""
    return {
        'name': name,
        'start': start,
        'size': size,
        'read': read,
        'write': write,
        'execute': execute,
        'file_offset': file_offset,
        'comment': comment,
    }


def identify_ecu(file_bytes):
    """Fail closed: no guess, no implicit fallback, no ambiguous matches."""
    file_size = int(file_bytes.getSize())
    matches = []

    for entry in ECU_IDENTIFICATION_TABLE:
        ecu = entry['ecu']
        if file_size != ecu['flash_size_bytes']:
            continue

        for signature in entry['expected']:
            start = entry['offset']
            if start + len(signature) > file_size:
                continue
            observed = bytes(
                int(file_bytes.getOriginalByte(start + i)) & 0xFF
                for i in range(len(signature))
            )
            if observed == signature:
                matches.append(ecu)
                break

    if not matches:
        raise ValueError(
            'ECU not identified (file size 0x{:X}). No fallback mapping '
            'will be applied. Check the identification signature and size.'
            .format(file_size)
        )

    if len(matches) > 1:
        raise ValueError(
            'Ambiguous ECU identification: {}. Refusing to remap.'
            .format(', '.join(x['name'] for x in matches))
        )

    return matches[0]


def generate_c167cs_regions():
    # Applies to the ROM-less C167CS-LM, verified in the OpenGK 5WY19 ECU.
    # XRAM2/CAN2 are configurable on the C167CS: blocks describe possible
    # addressable resources, not proof that firmware enables each one.
    regions = []

    if MAP_LOW_FLASH_WINDOW:
        regions.append(region(
            'Flash_Low_Boot', 0x0000, LOW_BOOT_CODE_LENGTH,
            execute=True, file_offset=0,
            comment='Assumed low external-flash boot window; NOT on-chip ROM',
        ))
        if LOW_FLASH_WINDOW_LENGTH > LOW_BOOT_CODE_LENGTH:
            regions.append(region(
                'Flash_Low_Data', LOW_BOOT_CODE_LENGTH,
                LOW_FLASH_WINDOW_LENGTH - LOW_BOOT_CODE_LENGTH,
                file_offset=LOW_BOOT_CODE_LENGTH,
                comment='Assumed low external-flash window (verify EBC configuration)',
            ))

    regions.extend([
        region('XRAM2_6K', 0xC000, 0x1800, write=True,
               comment='XRAM2: C000-D7FF; D800-DFFF not usable as XRAM'),
        region('XRAM1_2K', 0xE000, 0x0800, write=True,
               comment='XRAM1: E000-E7FF'),
        region('CAN2', 0xEE00, 0x0100, write=True,
               comment='CAN2: EE00-EEFF (conditional XBUS peripheral)'),
        region('CAN1', 0xEF00, 0x0100, write=True,
               comment='CAN1: EF00-EFFF'),
        region('ESFR', 0xF000, 0x0200, write=True,
               comment='Extended SFR: F000-F1FF'),
        region('IRAM_3K', 0xF200, 0x0C00, write=True,
               comment='Internal RAM: F200-FDFF; includes PEC pointers'),
        region('SFR', 0xFE00, 0x0200, write=True,
               comment='Standard SFR: FE00-FFFF'),
    ])
    # D800-DFFF and E800-EDFF intentionally remain unmapped. Depending on
    # XBUS enable bits and EBC configuration, some addresses can behave as
    # external bus cycles; don't assign bytes from the flash file to them.
    return regions


def generate_ecu_regions(ecu):
    sections = (
        ('bootloader2', 'Bootloader_2', True, False),
        ('calibration', 'Calibration', False, True),
        ('program', 'Program', True, False),
    )
    regions = []
    for key, name, execute, write in sections:
        address = ecu.get(key + '_section_address')
        size = ecu.get(key + '_size_bytes')
        if address is None:
            if size is not None:
                raise ValueError('Missing address for {}'.format(key))
            continue
        if size is None:
            raise ValueError('Missing size for {}'.format(key))

        regions.append(region(
            name, address, size, write=write, execute=execute,
            file_offset=address + ecu['bin_offset'],
            comment='External flash {} section; ECU {}'.format(key, ecu['name']),
        ))

    return regions


def validate_regions(program, regions, file_size):
    """Validate all data BEFORE removing even one existing memory block."""
    max_address = int(program.getAddressFactory()
                          .getDefaultAddressSpace().getMaxAddress().getOffset())

    seen_names = set()
    previous = None
    for r in sorted(regions, key=lambda r: r['start']):
        start = r['start']
        size = r['size']
        end = start + size - 1
        offset = r['file_offset']

        if r['name'] in seen_names:
            raise ValueError('Duplicate block name: {}'.format(r['name']))
        seen_names.add(r['name'])
        if start < 0 or size <= 0 or end > max_address:
            raise ValueError('Invalid CPU range: {} 0x{:X}-0x{:X}'
                             .format(r['name'], start, end))
        if previous is not None and start <= previous['start'] + previous['size'] - 1:
            raise ValueError('Overlap: {} and {}'
                             .format(previous['name'], r['name']))
        if offset is not None and (offset < 0 or offset + size > file_size):
            raise ValueError('Out-of-file-range: {} file 0x{:X}+0x{:X} > 0x{:X}'
                             .format(r['name'], offset, size, file_size))
        previous = r


def create_region(memory, file_bytes, r, address_space):
    start = address_space.getAddress(r['start'])
    if r['file_offset'] is None:
        block = memory.createUninitializedBlock(
            r['name'], start, r['size'], False
        )
    else:
        block = memory.createInitializedBlock(
            r['name'], start, file_bytes, r['file_offset'], r['size'], False
        )
    block.setRead(r['read'])
    block.setWrite(r['write'])
    block.setExecute(r['execute'])
    if r['comment']:
        block.setComment(r['comment'])
    return block


def run_script():
    program = getState().getCurrentProgram()
    if program is None:
        raise RuntimeError('No program open')

    memory = program.getMemory()
    file_bytes_list = list(memory.getAllFileBytes())
    if len(file_bytes_list) != 1:
        raise ValueError(
            'Expected exactly one raw firmware FileBytes object; got {}. '
            'Select a fresh raw-binary import.'
            .format(len(file_bytes_list))
        )

    file_bytes = file_bytes_list[0]
    file_size = int(file_bytes.getSize())
    ecu = identify_ecu(file_bytes)
    regions = generate_c167cs_regions() + generate_ecu_regions(ecu)
    regions.sort(key=lambda r: r['start'])
    validate_regions(program, regions, file_size)

    print('Firmware: {} ({:d} bytes / 0x{:X})'
          .format(ecu['name'], file_size, file_size))
    print('Processor map: C167CS-LM (VERIFY physical MCU for this ECU)')
    print('Ghidra language: {}'.format(program.getLanguage().getLanguageID()))
    print('Source: {}'.format(file_bytes.getFilename()))
    print('LOW FLASH ALIAS ASSUMED: {}'.format(MAP_LOW_FLASH_WINDOW))
    print('\nProposed memory blocks (end is inclusive):')
    for r in regions:
        src = ('uninitialized' if r['file_offset'] is None else
               'file @ 0x{:X}'.format(r['file_offset']))
        perms = ''.join((
            'R' if r['read'] else '-',
            'W' if r['write'] else '-',
            'X' if r['execute'] else '-',
        ))
        print('  {:18s} 0x{:06X}-0x{:06X} {:3s} {:s}'
              .format(r['name'], r['start'],
                      r['start'] + r['size'] - 1, perms, src))

    previous_blocks = list(memory.getBlocks())
    print('\nReplacing {} existing memory blocks...'.format(len(previous_blocks)))
    for block in previous_blocks:
        memory.removeBlock(block, monitor)

    address_space = program.getAddressFactory().getDefaultAddressSpace()
    for r in regions:
        create_region(memory, file_bytes, r, address_space)

    print('\nApplied {} C167CS/SIMK memory blocks successfully.'
          .format(len(regions)))
    print('Review processor language, DPP/CSP assumptions and boot entry points '
          'before auto-analysis.')


run_script()
