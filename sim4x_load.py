#Load SIMK4x binaries
@author Dante
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra

from ghidra.program.model.mem import MemoryBlock
from ghidra.program.model.mem import MemoryBlockType
from ghidra.program.model.mem import MemoryConflictException

def run_script():
	state = getState()
	currentProgram = state.getCurrentProgram()
	memory = currentProgram.getMemory()

	fileBytes = memory.getAllFileBytes()

	for block in memory.getBlocks():
		print(block.getName())
		memory.removeBlock(block, monitor)

	simk4x_internal_rom = memory.createInitializedBlock("Internal_ROM", toAddr(0x0000), fileBytes[0], 0, 0x1fff, False)
	simk4x_internal_rom.setRead(True)
	simk4x_internal_rom.setWrite(False)
	simk4x_internal_rom.setExecute(True)

	simk4x_external_memory = memory.createInitializedBlock("External_Memory", toAddr(0x2000), fileBytes[0], 0x2000, 0xD9FF, False)
	simk4x_internal_rom.setRead(True)
	simk4x_internal_rom.setWrite(True)
	simk4x_internal_rom.setExecute(False)

	simk4x_xram = memory.createInitializedBlock("XRAM", toAddr(0xC000), fileBytes[0], 0xC000, 0x1800, False)
	simk4x_xperhiphals = memory.createInitializedBlock("X_Periphals", toAddr(0xF000), fileBytes[0], 0xF000, 0x1800, False)

	simk4x_internal_ram = memory.createInitializedBlock("Internal_RAM", toAddr(0xFA00), fileBytes[0], 0xf9fe, 0x3ff, False)
	simk4x_internal_ram.setRead(True)
	simk4x_internal_ram.setWrite(True)
	simk4x_internal_ram.setExecute(False)

	simk4x_internal_SFRs = memory.createInitializedBlock("Internal_SFRs", toAddr(0xFE00), fileBytes[0], 0x41fe, 0x1ff, False)
	simk4x_internal_SFRs.setRead(True)
	simk4x_internal_SFRs.setWrite(True)
	simk4x_internal_SFRs.setExecute(False)

	simk4x_bootloader2 = memory.createInitializedBlock("Bootloader_2", toAddr(0x88000), fileBytes[0], 0x8000, 0x7fff, False)
	simk4x_bootloader2.setRead(True)
	simk4x_bootloader2.setWrite(False)
	simk4x_bootloader2.setExecute(True)


	simk4x_calibration = memory.createInitializedBlock("Calibration", toAddr(0x90000), fileBytes[0], 0x10000, 0xFFFF, False)
	simk4x_calibration.setRead(True)
	simk4x_calibration.setWrite(False)
	simk4x_calibration.setExecute(False)

	simk4x_program = memory.createInitializedBlock("Program", toAddr(0xA0000), fileBytes[0], 0x20000, 0x5ffff, False)
	simk4x_program.setRead(True)
	simk4x_program.setWrite(False)
	simk4x_program.setExecute(True)

	print("Memory blocks have been re-created for the C166 firmware!")

run_script()