#include "stubs_asm.h"
#define NULL_SUB 0xFF04D3E0

// Override stubs_entry.S
NHSTUB(LEDDrive,                    0xFF04D06C)
NHSTUB(DeleteFile_Fut,              0xFF02163C)
NHSTUB(MakeDirectory_Fut,           0xFF02214C)
NHSTUB(PT_PlaySound,                0xFF076E60)
NHSTUB(kbd_pwr_off,                 NULL_SUB)
NHSTUB(kbd_pwr_on,                  NULL_SUB)
NHSTUB(reboot_fw_update,            0xFF3355D8)     //finsig: 0xff3355dc 64%

// These don't exist
NHSTUB(SetZoomActuatorSpeedPercent, NULL_SUB)
NHSTUB(UnsetZoomForMovie,           NULL_SUB)

// Additional
NHSTUB(GPS_UpdateData,              0xFF140C20)
NHSTUB(LockAndRefresh,              0xFF0A27EC)
NHSTUB(MakeAFScan,                  0xFF1BC964)
NHSTUB(ReadSDCard,                  0xFF19D880)
NHSTUB(UnlockAndRefresh,            0xFF0A2850)
NHSTUB(UpdateMBROnFlash,            0xFF06084C)
NHSTUB(closefastdir,                0xFF32FE3C)
NHSTUB(fclose,                      0xFF021748)
NHSTUB(fopen,                       0xFF021708)
NHSTUB(fread,                       0xFF0217F4)
NHSTUB(fwrite,                      0xFF021848)
NHSTUB(localtime,                   0x00685A2F4) //101a: ROM 0xff68ad48 copied to RAM
//NHSTUB(ufree,                       0xFF02574C) //not sure
