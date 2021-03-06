#0x3115
PLATFORMID=12565

PLATFORMOS=vxworks

MEMBASEADDR=0x1900   # address where wif or diskboot code will be loaded by canon firmware
RESTARTSTART=0x50000   # size of a free memory region for chdk
MEMISOSTART=0xA4D10   # ROM:FF810134 or ROM:FF8117A8
ROMBASEADDR=0xFF810000   # 0xFF810000 for S-, SD-, and G- series, 0xFFC00000 for A-series camera models

PLFLAGS=-DMEMBASEADDR=$(MEMBASEADDR) -DMEMISOSTART=$(MEMISOSTART) -DMEMISOSIZE=$(MEMISOSIZE)
PLFLAGS+=-DRESTARTSTART=$(RESTARTSTART)
