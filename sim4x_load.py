#Load SIMK4x binaries
#@author Dante
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra

from ghidra.program.model.mem import MemoryBlock
from ghidra.program.model.mem import MemoryBlockType
from ghidra.program.model.mem import MemoryConflictException
from ghidra.program.model.address import Address
from ghidra.program.database.mem import FileBytes

MEMORY_REGIONS = [
	{
		'name': 'Internal_ROM',
		'start': toAddr(0x0000), # 0x0000 - 0x1fff
		'offset': 0,
		'size': 0x1fff,
		'read': True,
		'write': False,
		'execute': True,
	},
	{
		'name': 'External_Memory',
		'start': toAddr(0x2000), # 0x2000 - 0xD9FF
		'offset': 0x2000,
		'size': 0xB9FF,
		'read': True,
		'write': True,
		'execute': False,
	},
	{
		'name': 'XRAM',
		'start': toAddr(0xE000), # 0xE000 - 0xE7FF
		'offset': 0xE000,
		'size': 0x7FF,
		'read': True,
		'write': True,
		'execute': False,
	},
	{
		'name': 'CAN1',
		'start': toAddr(0xEF00),
		'offset': 0xEF00,
		'size': 0x100,
		'read': True,
		'write': True,
		'execute': False,
	},
	{
		'name': 'ESFR',
		'start': toAddr(0xF000),
		'offset': 0xF000,
		'size': 0x200,
		'read': True,
		'write': True,
		'execute': False,
	},
	{
		'name': 'Internal_RAM',
		'start': toAddr(0xF200), # according to datasheet this starts at 0xf600, and 0xf200-0xf600 is reserved but this proves to not be the case
		'offset': 0xF200,
		'size': 0x9FF, # used to be 0x5ff, see above
		'read': True,
		'write': True,
		'execute': False,
	},
	{
		'name': 'Internal_SFRs',
		'start': toAddr(0xFC00),
		'offset': 0xFC00,
		'size': 0x400,
		'read': True,
		'write': True,
		'execute': False,
	},
	{
		'name': 'Bootloader_2',
		'start': toAddr(0x88000),
		'offset': 0x8000,
		'size': 0x7fff,
		'read': True,
		'write': False,
		'execute': True,
	},
	{
		'name': 'Calibration',
		'start': toAddr(0x90000),
		'offset': 0x10000,
		'size': 0xFFFF,
		'read': True,
		'write': True,
		'execute': False,
	},
	{
		'name': 'Program',
		'start': toAddr(0xA0000),
		'offset': 0x20000,
		'size': 0x5FFFF,
		'read': True,
		'write': False,
		'execute': True,
	},
]

SIZE_2MBIT = 262143
SIZE_4MBIT = 524288

def create_memory_region (memory, name: str, start: Address, fileBytes: FileBytes, offset: int, size: int, read: bool, write: bool, execute: bool) -> MemoryBlock:
	block = memory.createInitializedBlock(name, start, fileBytes, offset, size, False)
	block.setRead(read)
	block.setWrite(write)
	block.setExecute(execute)

def compare_with_tolerance (value: int, desired: int, tolerance: int = 10) -> bool:
	return (abs(value-desired)<tolerance)

def run_script():
	state = getState()
	currentProgram = state.getCurrentProgram()
	memory = currentProgram.getMemory()

	fileBytes = memory.getAllFileBytes()

	if compare_with_tolerance(memory.getSize(), SIZE_4MBIT):
		print('4mbit binary detected, likely SIMK43')
	elif compare_with_tolerance(memory.getSize(), SIZE_2MBIT):
		print('2mbit binary detected, likely SIMK41')
	else:
		print('Binary size doesn\'t come close to either 2 or 4mbit. I\'m gonna proceed, but this is most likely an invalid SIMK4x bin')

	for block in memory.getBlocks():
		memory.removeBlock(block, monitor)

	for region in MEMORY_REGIONS:
		create_memory_region(memory, fileBytes=fileBytes[0], **region)

	print("Memory blocks have been re-created for the C166 firmware!")

run_script()