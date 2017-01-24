# Firmware tools

These are some simple tools to help you get started with reversing the Utimaco firmware.

 * extractcoff.py will extract the CS2-COFF/DLL file from inside an mtc module
 * parsecoff.py will load a CS2-COFF file and extract all functions in the func/ subdir

Inside the parsecoff.py file you can find several python classes for loading and manipulating CS2-COFF files.
