
This is a short readme describing the layout of PyEmu.

PyContext.py: A module containing a class for defining a context to pass between modules in the emulator
PyCPU.py: The CPU class implements each instruction and is responsible for executing and maintaining state
PyDebug.py: A simple class to ease some debugging tasks
PyEmu.py: The user facing class that implements the public methods available for use.  Also is responsible for initiating the memory and cpu classes
PyInstruction.py: A helper class for providing abstracted access to the pydasm instruction structures
PyMemory.py: A module containing the memory managers responsible for fetching and storing memory
PyOS.py: A rough implementation of needed OS specific structures for process creation and control.

examples/
    idapyemu.py: A simple example of using PyEmu in IDA Pro
    idapyemu_memory_access.py: A simple example showing tracking of memory access
    idapyemu_path_enumeration.py: An example showing mnemonic hooking
    idapyemu_return_value.py: An example demonstrating return value enumeration
    idapyemu_test_case.py: A test case exercising many of the PyEmu methods
    pepyemu.py: A example of PE file PyEmu use
    pydbgpyemu.py: A example of PyDbg use

lib/
    pefile.py: Ero Carrera's pefile implementation
    pydasm.pyd: Ero Carrera's libdasm python wrapper
    ctypes/_ctypes.pyd: Ctypes library needed for PyOS.py