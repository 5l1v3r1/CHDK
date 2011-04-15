#include "lolevel.h"
#include "platform.h"
#include "core.h"

static long *nrflag = (long*)0x8450; // 0xFFD0F430

#include "../../../generic/capt_seq.c"

void __attribute__((naked,noinline)) sub_FFD0F3B8_my(){
 asm volatile(
                 "STMFD   SP!, {R0-R10,LR}\n"
                 "MOV     R6, #0\n"
                 "MOV     R4, R0\n"
                 "BL      sub_FFD0FEB8\n"
                 "MVN     R1, #0\n" // "MOV     R1, 0xFFFFFFFF\n"
                 "BL      sub_FFC173FC\n"
                 "MOV     R2, #4\n"
                 "ADD     R1, SP, #8\n"
                 "MOV     R0, #0x8A\n"
                 "BL      sub_FFC5819C\n"
                 "TST     R0, #1\n"
                 "MOVNE   R1, #0x218\n"
                 "LDRNE   R0, =0xFFD0F5CC\n"
                 "BLNE    sub_FFC0BDB8\n"
                 "LDR     R8, =0x18440\n"
                 "LDR     R5, =0x18394\n"
                 "LDRSH   R1, [R8,#0xE]\n"
                 "LDR     R0, [R5,#0x74]\n"
                 "BL      sub_FFCCD36C\n"
                 "BL      sub_FFC339C8\n"
                 "LDR     R2, =0x8454\n"
                 "ADD     R3, R4, #0x8C\n"
                 "STRH    R0, [R4,#0x88]\n"
                 "STRD    R2, [SP]\n"
                 "MOV     R1, R0\n"
                 "LDRH    R0, [R5,#0x4C]\n"
                 "LDRSH   R2, [R8,#0xC]\n"
                 "LDR     R3, =0x8450\n"
                 "BL      sub_FFD103A4\n"
                 "BL      wait_until_remote_button_is_released\n"
                 "BL      capt_seq_hook_set_nr\n"
                 "B       sub_FFD0F42C\n"
 );
}
///UP

void __attribute__((naked,noinline)) task_CaptSeqTask_my() //#fs
{
	asm volatile (
"                STMFD   SP!, {R3-R7,LR}\n"
"                LDR     R6, =0x52A8\n"
"loc_FFC49B40:\n"
"                LDR     R0, [R6,#8]\n"
"                MOV     R2, #0\n"
"                MOV     R1, SP\n"
"                BL      sub_FFC1764C\n"
"                TST     R0, #1\n"
"                BEQ     loc_FFC49B6C\n"
"                LDR     R1, =0x48E\n"
"                LDR     R0, =0xFFC49860\n"
"                BL      sub_FFC0BDB8\n" // assert
"                BL      sub_FFC0BB70\n" //exit
"                LDMFD   SP!, {R3-R7,PC}\n"
"loc_FFC49B6C:\n"
"                LDR     R0, [SP]\n"
"                LDR     R1, [R0]\n"

                ///?????????????????
                "LDR     R2, =0x1850\n"         // DEBUG: Save jumptable-target ...
                "STR     R1, [R2]\n"            // ...to some unused space. Read and displayed in GUI in core/gui.c
                //??????????????????

"                CMP     R1, #0x19\n"
"                ADDLS   PC, PC, R1,LSL#2\n"
"                B       loc_FFC49D80\n"
"                B       loc_FFC49BE8\n"
"                B       loc_FFC49BF0\n"
"                B       loc_FFC49C70\n"
"                B       loc_FFC49C84\n"
"                B       loc_FFC49C7C\n"
"                B       loc_FFC49C8C\n"
"                B       loc_FFC49C94\n"
"                B       loc_FFC49CA0\n"
"                B       loc_FFC49CF8\n"
"                B       loc_FFC49C84\n"
"                B       loc_FFC49D00\n"
"                B       loc_FFC49D08\n"
"                B       loc_FFC49D10\n"
"                B       loc_FFC49D18\n"
"                B       loc_FFC49D20\n"
"                B       loc_FFC49D2C\n"
"                B       loc_FFC49D34\n"
"                B       loc_FFC49D3C\n"
"                B       loc_FFC49D44\n"
"                B       loc_FFC49D50\n"
"                B       loc_FFC49D58\n"
"                B       loc_FFC49D60\n"
"                B       loc_FFC49D68\n"
"                B       loc_FFC49D70\n"
"                B       loc_FFC49D78\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49BE8:\n"
"                BL      sub_FFD0DF20\n"
                "BL      shooting_expo_param_override\n"
"                B       loc_FFC49C98\n"
"loc_FFC49BF0:\n"
"                LDR     R4, [R0,#0xC]\n"
"                LDR     R0, [R4,#8]\n"
"                ORR     R0, R0, #1\n"
"                STR     R0, [R4,#8]\n"
"                BL      sub_FFD0DF10\n"
"                MOV     R0, R4\n"
"                BL      sub_FFD0E2F8\n"
"                TST     R0, #1\n"
"                MOVNE   R2, R4\n"
"                MOVNE   R1, #1\n"
"                BNE     loc_FFC49CF0\n"
"                BL      sub_FFD2D318\n"
"                BL      sub_FFC5832C\n"
"                STR     R0, [R4,#0x14]\n"
"                MOV     R0, R4\n"
"                BL      sub_FFD0F2F0\n"
"                BL      sub_FFD0FD54\n"
"                MOV     R0, R4\n"
//"                BL      sub_FFD0F3B8\n"
                "BL      sub_FFD0F3B8_my\n"         //-------------->
                "BL      capt_seq_hook_raw_here\n"  //-------------->
"                MOV     R5, R0\n"
"                BL      sub_FFD10D34\n"
"                BL      sub_FFD10D70\n"
"                MOV     R2, R4\n"
"                MOV     R1, #1\n"
"                MOV     R0, R5\n"
"                BL      sub_FFC4831C\n"
"                BL      sub_FFD0F768\n"
"                CMP     R0, #0\n"
"                LDRNE   R0, [R4,#8]\n"
"                ORRNE   R0, R0, #0x2000\n"
"                STRNE   R0, [R4,#8]\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49C70:\n"
"                MOV     R0, #1\n"
"                BL      sub_FFD0E0B4\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49C7C:\n"
"                BL      sub_FFD0DB80\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49C84:\n"
"                BL      sub_FFD0DF00\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49C8C:\n"
"                BL      sub_FFD0DF08\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49C94:\n"
"                BL      sub_FFD0DFD4\n"
"loc_FFC49C98:\n"
"                BL      sub_FFC47F9C\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49CA0:\n"
"                LDR     R4, [R0,#0xC]\n"
"                BL      sub_FFD0DF10\n"
"                MOV     R0, R4\n"
"                BL      sub_FFD0E678\n"
"                TST     R0, #1\n"
"                MOV     R5, R0\n"
"                BNE     loc_FFC49CE0\n"
"                BL      sub_FFC5832C\n"
"                STR     R0, [R4,#0x14]\n"
"                MOV     R0, R4\n"
"                BL      sub_FFD0F2F0\n"
"                MOV     R0, R4\n"
"                BL      sub_FFD0F7C8\n"
"                MOV     R5, R0\n"
"                LDR     R0, [R4,#0x14]\n"
"                BL      sub_FFC58538\n"
"loc_FFC49CE0:\n"
"                BL      sub_FFD0DF00\n"
"                MOV     R2, R4\n"
"                MOV     R1, #9\n"
"                MOV     R0, R5\n"
"loc_FFC49CF0:\n"
"                BL      sub_FFC4831C\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49CF8:\n"
"                BL      sub_FFD0E034\n"
"                B       loc_FFC49C98\n"
"loc_FFC49D00:\n"
"                BL      sub_FFD0E8F4\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49D08:\n"
"                BL      sub_FFD0EADC\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49D10:\n"
"                BL      sub_FFD0EB6C\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49D18:\n"
"                BL      sub_FFD0EC20\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49D20:\n"
"                MOV     R0, #0\n"
"                BL      sub_FFD0EDC4\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49D2C:\n"
"                BL      sub_FFD0EF14\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49D34:\n"
"                BL      sub_FFD0EFA8\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49D3C:\n"
"                BL      sub_FFD0F070\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49D44:\n"
"                BL      sub_FFD0E1D0\n"
"                BL      sub_FFC149BC\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49D50:\n"
"                BL      sub_FFD0ECDC\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49D58:\n"
"                BL      sub_FFD0ED20\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49D60:\n"
"                BL      sub_FFD10D18\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49D68:\n"
"                BL      sub_FFD10D34\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49D70:\n"
"                BL      sub_FFD10D44\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49D78:\n"
"                BL      sub_FFD10D70\n"
"                B       loc_FFC49D8C\n"
"loc_FFC49D80:\n"
"                LDR     R1, =0x58E\n"
"                LDR     R0, =0xFFC49860\n"
"                BL      sub_FFC0BDB8\n" // assert
"loc_FFC49D8C:\n"
"                LDR     R0, [SP]\n"
"                LDR     R1, [R0,#4]\n"
"                LDR     R0, [R6,#4]\n"
"                BL      sub_FFC173C8\n"
"                LDR     R4, [SP]\n"
"                LDR     R0, [R4,#8]\n"
"                CMP     R0, #0\n"
"                LDREQ   R1, =0x10D\n"
"                LDREQ   R0, =0xFFC49860\n"
"                BLEQ    sub_FFC0BDB8\n" // assert
"                MOV     R0, #0\n"
"                STR     R0, [R4,#8]\n"
"                B       loc_FFC49B40\n"
    );
} //#fe
