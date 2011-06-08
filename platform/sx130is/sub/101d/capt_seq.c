#include "lolevel.h"
#include "platform.h"
#include "core.h"

//static long *nrflag = (long*)0xC910; // FFAB026C

static long *nrflag = (long*)0x5CB4;

#include "../../../generic/capt_seq.c"


int capt_seq_hook_set_nr_my(int orig)
{
 
	shutter_open_time=_time((void*)0); 

	// Firmware also tests for 3 and 7, meaning unknown, so we don't touch them
	if (orig!=NR_ON && orig!=NR_OFF)
		return orig;

	switch (core_get_noise_reduction_value()){
	case NOISE_REDUCTION_OFF:
		return NR_OFF;
	case NOISE_REDUCTION_ON:
		return NR_ON;
	case NOISE_REDUCTION_AUTO_CANON: // leave it alone
	default: // shut up compiler 
		return orig;
	};
}


/*----------------------------------------------------------------------
	capt_seq_task()
-----------------------------------------------------------------------*/
void __attribute__((naked,noinline)) capt_seq_task()
{
  // FF87B564
	asm volatile (
"		STMFD	SP!, {R3-R7,LR} \n"
"		LDR	R6, =0x2C6C \n"
"		LDR	R5, =0x38B44 \n"
"loc_FF87B570: \n"
"		LDR	R0, [R6,#4] \n"
"		MOV	R2, #0 \n"
"		MOV	R1, SP \n"
"		BL	sub_FF839B8C \n"
"		TST	R0, #1 \n"
"		BEQ	loc_FF87B59C \n"
"		LDR	R1, =0x43F \n"
"		LDR	R0, =0xFF87B07C \n" // "SsShootTask.c"
"		BL	_DebugAssert \n" 
"		BL	sub_FF81EB30 \n" // eventproc_export_ExitTask
"		LDMFD	SP!, {R3-R7,PC} \n"
"loc_FF87B59C: \n"
"		LDR	R0, [SP] \n"
"		LDR	R1, [R0] \n"
"		CMP	R1, #0x21 \n"
"		ADDLS	PC, PC,	R1,LSL#2 \n"
"		B	loc_FF87B794 \n"
"loc_FF87B5B0: \n"
"		B	loc_FF87B638 \n"
"loc_FF87B5B4: \n"
"		B	loc_FF87B640 \n"
"loc_FF87B5B8: \n"
"		B	loc_FF87B658 \n"
"loc_FF87B5BC: \n"
"		B	loc_FF87B66C \n"
"loc_FF87B5C0: \n"
"		B	loc_FF87B664 \n"
"loc_FF87B5C4: \n"
"		B	loc_FF87B674 \n"
"loc_FF87B5C8: \n"
"		B	loc_FF87B67C \n"
"loc_FF87B5CC: \n"
"		B	loc_FF87B688 \n"
"loc_FF87B5D0: \n"
"		B	loc_FF87B694 \n"
"loc_FF87B5D4: \n"
"		B	loc_FF87B66C \n"
"loc_FF87B5D8: \n"
"		B	loc_FF87B69C \n"
"loc_FF87B5DC: \n"
"		B	loc_FF87B6A8 \n"
"loc_FF87B5E0: \n"
"		B	loc_FF87B6B0 \n"
"loc_FF87B5E4: \n"
"		B	loc_FF87B6B8 \n"
"loc_FF87B5E8: \n"
"		B	loc_FF87B6C0 \n"
"loc_FF87B5EC: \n"
"		B	loc_FF87B6C8 \n"
"loc_FF87B5F0: \n"
"		B	loc_FF87B6D0 \n"
"loc_FF87B5F4: \n"
"		B	loc_FF87B6D8 \n"
"loc_FF87B5F8: \n"
"		B	loc_FF87B6E0 \n"
"loc_FF87B5FC: \n"
"		B	loc_FF87B6E8 \n"
"loc_FF87B600: \n"
"		B	loc_FF87B6F0 \n"
"loc_FF87B604: \n"
"		B	loc_FF87B6F8 \n"
"loc_FF87B608: \n"
"		B	loc_FF87B700 \n"
"loc_FF87B60C: \n"
"		B	loc_FF87B70C \n"
"loc_FF87B610: \n"
"		B	loc_FF87B714 \n"
"loc_FF87B614: \n"
"		B	loc_FF87B720 \n"
"loc_FF87B618: \n"
"		B	loc_FF87B728 \n"
"loc_FF87B61C: \n"
"		B	loc_FF87B730 \n"
"loc_FF87B620: \n"
"		B	loc_FF87B738 \n"
"loc_FF87B624: \n"
"		B	loc_FF87B740 \n"
"loc_FF87B628: \n"
"		B	loc_FF87B748 \n"
"loc_FF87B62C: \n"
"		B	loc_FF87B750 \n"
"loc_FF87B630: \n"
"		B	loc_FF87B75C \n"
"loc_FF87B634: \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B638: \n"
// jumptable FF87B5A8 entry 0
"		BL	sub_FF87BD1C \n"
"		BL	shooting_expo_param_override \n"	// Added ------------>
"		B	loc_FF87B680 \n"
"loc_FF87B640: \n"
// jumptable FF87B5A8 entry 1
"		LDRH	R1, [R5] \n"
"		SUB	R12, R1, #0x8200 \n"
"		SUBS	R12, R12, #0x2E \n"
"		LDRNE	R0, [R0,#0xC] \n"
//"		BLNE	sub_FF96E09C \n"
"		BLNE	sub_FF96E09C_my \n" // Patched ------------>
"		B	loc_FF87B7A0 \n"
"loc_FF87B658: \n"
// jumptable FF87B5A8 entry 2
"		MOV	R0, #1 \n"
"		BL	sub_FF87BFA8 \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B664: \n"
// jumptable FF87B5A8 entry 4
"		BL	sub_FF87B9CC \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B66C: \n"
// jumptable FF87B5A8 entries 3,9
"		BL	sub_FF87BCFC \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B674: \n"
// jumptable FF87B5A8 entry 5
"		BL	sub_FF87BD04 \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B67C: \n"
// jumptable FF87B5A8 entry 6
"		BL	sub_FF87BEBC \n"
"loc_FF87B680: \n"
"		BL	sub_FF879260 \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B688: \n"
// jumptable FF87B5A8 entry 7
"		LDR	R0, [R0,#0xC] \n"
"		BL	sub_FF96E20C \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B694: \n"
// jumptable FF87B5A8 entry 8
"		BL	sub_FF87BF20 \n"
"		B	loc_FF87B680 \n"
"loc_FF87B69C: \n"
// jumptable FF87B5A8 entry 10
"		LDR	R0, [R5,#0x4C] \n"
"		BL	sub_FF87C57C \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B6A8: \n"
// jumptable FF87B5A8 entry 11
"		BL	sub_FF87C8C8 \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B6B0: \n"
// jumptable FF87B5A8 entry 12
"		BL	sub_FF87C92C \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B6B8: \n"
// jumptable FF87B5A8 entry 13
"		BL	sub_FF96D5DC \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B6C0: \n"
// jumptable FF87B5A8 entry 14
"		BL	sub_FF96D7E8 \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B6C8: \n"
// jumptable FF87B5A8 entry 15
"		BL	sub_FF96D86C \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B6D0: \n"
// jumptable FF87B5A8 entry 16
"		BL	sub_FF96D958 \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B6D8: \n"
// jumptable FF87B5A8 entry 17
"		BL	sub_FF96DA28 \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B6E0: \n"
// jumptable FF87B5A8 entry 18
"		MOV	R0, #0 \n"
"		B	loc_FF87B704 \n"
"loc_FF87B6E8: \n"
// jumptable FF87B5A8 entry 19
"		BL	sub_FF96DE24 \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B6F0: \n"
// jumptable FF87B5A8 entry 20
"		BL  sub_FF96DEC8 \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B6F8: \n"
// jumptable FF87B5A8 entry 21
"		BL  sub_FF96DFA8 \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B700: \n"
// jumptable FF87B5A8 entry 22
"		MOV	R0, #1 \n"
"loc_FF87B704: \n"
"		BL	sub_FF96DCC4 \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B70C: \n"
// jumptable FF87B5A8 entry 23
"		BL	sub_FF87C178 \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B714: \n"
// jumptable FF87B5A8 entry 24
"		BL	sub_FF87C1A4 \n"
"		BL	sub_FF96EE48 \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B720: \n"
// jumptable FF87B5A8 entry 25
"		BL	sub_FF96DB9C \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B728: \n"
// jumptable FF87B5A8 entry 26
"		BL	sub_FF96DC34 \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B730: \n"
// jumptable FF87B5A8 entry 27
"		BL	sub_FF96EF18 \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B738: \n"
// jumptable FF87B5A8 entry 28
"		BL	sub_FF83790C \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B740: \n"
// jumptable FF87B5A8 entry 29
"		BL	sub_FF87E998 \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B748: \n"
// jumptable FF87B5A8 entry 30
"		BL	sub_FF87EA18 \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B750: \n"
// jumptable FF87B5A8 entry 31
"		BL	sub_FF87EA74 \n"
"		BL	sub_FF87EA34 \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B75C: \n"
// jumptable FF87B5A8 entry 32
"		MOV	R0, #1 \n"
"		BL	sub_FF96E990 \n"
"		MOV	R0, #1 \n"
"		BL	sub_FF96EAB4 \n"
"		LDRH	R0, [R5,#0x94] \n"
"		CMP	R0, #4 \n"
"		LDRNEH	R0, [R5] \n"
"		SUBNE	R12, R0, #0x4200 \n"
"		SUBNES	R12, R12, #0x2A \n"
"		BNE	loc_FF87B7A0 \n"
"		BL	sub_FF87EA18 \n"
"		BL	sub_FF87EF84 \n"
"		BL	sub_FF87EE94  \n"
"		B	loc_FF87B7A0 \n"
"loc_FF87B794: \n"
// jumptable FF87B5A8 default entry
"		LDR	R1, =0x591 \n"
"		LDR	R0, =0xFF87B07C \n" // "SsShootTask.c"
"		BL	_DebugAssert \n" 
"loc_FF87B7A0: \n"
// jumptable FF87B5A8 entry 33
"		LDR	R0, [SP] \n"
"		LDR	R1, [R0,#4] \n"
"		LDR	R0, [R6] \n"
"		BL	sub_FF8855D8 \n"
"		LDR	R4, [SP] \n"
"		LDR	R0, [R4,#8] \n"
"		CMP	R0, #0 \n"
"		LDREQ	R1, =0x115 \n"
"		LDREQ	R0, =0xFF87B07C \n" // "SsShootTask.c"
"		BLEQ	_DebugAssert \n" 
"		MOV	R0, #0 \n"
"		STR	R0, [R4,#8] \n"
"		B	loc_FF87B570 \n"
	);
}

void __attribute__((naked,noinline)) sub_FF96E09C_my(){
    asm volatile(
"		STMFD	SP!, {R3-R7,LR}\n"
"		MOV	R4, R0 \n"
"		MOV	R0, #0xC \n"
"		BL	sub_FF880578 \n"
"		TST	R0, #1 \n"
"		MOVNE	R2, R4 \n"
"		LDMNEFD	SP!, {R3-R7,LR} \n"
"		MOVNE	R1, #1 \n"
"		MOVNE	R0, #1 \n"
"		BNE	sub_FF879734 \n"
"		LDR	R0, [R4,#8] \n"
"		LDR	R5, =0x38B44 \n"
"		ORR	R0, R0,	#1 \n"
"		STR	R0, [R4,#8] \n"
"		LDRH	R0, [R5,#0x92] \n"
"		CMP	R0, #3 \n"
"		BEQ	loc_FF96E170 \n"
"		LDR	R0, [R4,#0xC] \n"
"		CMP	R0, #1 \n"
"		BLS	loc_FF96E13C \n"
"		LDRH	R0, [R5,#0x90] \n"
"		CMP	R0, #0 \n"
"		BNE	loc_FF96E170 \n"
"		LDRH	R0, [R5,#0x8C] \n"
"		CMP	R0, #2 \n"
"		BNE	loc_FF96E148 \n"
"		BL	sub_FF87C270 \n"
"		LDRH	R0, [R5,#0x92] \n"
"		CMP	R0, #3 \n"
"		BEQ	loc_FF96E170 \n"
"		LDR	R0, [R4,#0xC] \n"
"		CMP	R0, #1 \n"
"		BLS	loc_FF96E13C \n"
"		LDRH	R0, [R5,#0x90] \n"
"		CMP	R0, #0 \n"
"		BNE	loc_FF96E170 \n"
"		LDRH	R0, [R5,#0x8C] \n"
"		CMP	R0, #2 \n"
"		BEQ	loc_FF96E16C \n"
"		B	loc_FF96E148 \n"
"loc_FF96E13C: \n"
"		LDRH	R0, [R5,#0x90] \n"
"		CMP	R0, #0 \n"
"		BNE	loc_FF96E170 \n"
"loc_FF96E148: \n"
"		LDRH	R0, [R5,#0x8C] \n"
"		CMP	R0, #1 \n"
"		BNE	loc_FF96E170 \n"
"		LDR	R0, [R4,#0xC] \n"
"		CMP	R0, #1 \n"
"		BLS	loc_FF96E170 \n"
"		LDR	R0, [R4,#0x10] \n"
"		CMP	R0, #1 \n"
"		BNE	loc_FF96E170 \n"
"loc_FF96E16C: \n"
"		BL	sub_FF96EF50 \n"
"loc_FF96E170: \n"
"		BL	sub_FF96EF18 \n"
"		BL	sub_FF87BD0C \n"
"		MOV	R0, R4 \n"
"		BL	sub_FFAAFC84 \n" 		// before shot (G12) ?
"		TST	R0, #1 \n"
"		BNE	locret_FF96E208 \n"
"		MOV	R0, R4 \n"
"		BL	sub_FFAB0064 \n"
"		BL	sub_FF96E774 \n"		// after pre-flash, before shot (G12) ? 
"		MOV	R6, #1 \n"			
"		MOV	R0, #2 \n"
"		BL	sub_FF877954 \n"
"		LDRH	R0, [R5] \n"
"		SUB	R12, R0, #0x8200 \n"
"		SUBS	R12, R12, #0x2D \n"
"		BNE	loc_FF96E1F0 \n"
"		MOV	R2, #2 \n"
"		ADD	R0, R2,	#0x15C \n"
"		MOV	R1, SP \n"
"		STR	R6, [SP] \n"
"		BL	sub_FF88D7A0 \n"
"		TST	R0, #1 \n"
"		MOVNE	R1, #0xC3 \n"
//"		ADRNE	R0, aSscaptureseq_c \n" // "SsCaptureSeq.c"
"		LDRNE	R0, =0xFF96E27C \n"
"		BLNE	_DebugAssert \n"
"		LDRH	R0, [SP] \n"
"		CMP	R0, #1 \n"
"		MOVHI	R0, #0x1D \n"
"		STRHI	R6, [R4,#0xD4] \n"
"		BHI	loc_FF96E1F8 \n"
"		MOV	R0, #0 \n"
"		STR	R0, [R4,#0xD4] \n"
"loc_FF96E1F0: \n"
"		MOV	R0, R4 \n"
//"		BL	sub_FFAB04E8 \n"
"		BL	sub_FFAB04E8_my \n" // Patched ------------>
"		BL	capt_seq_hook_raw_here \n"	// Added ---------->
"loc_FF96E1F8: \n"
"		MOV	R1, R0 \n"
"		MOV	R0, R4 \n"
"		LDMFD	SP!, {R3-R7,LR} \n"
"		B	sub_FFAAFD88 \n"
"locret_FF96E208: \n"
"		LDMFD	SP!, {R3-R7,PC} \n"
	);	
}

void __attribute__((naked,noinline)) sub_FFAB04E8_my()
{
	asm volatile(
"		STMFD	SP!, {R2-R6,LR} \n"
"		MOV	R5, R0 \n"
"		BL	sub_FF96EC78 \n"
"		MOV	R1, #0xFFFFFFFF \n"
"		BL	sub_FF88560C \n"
"		LDR	R0, =0xFFAAFDF4 \n" 		// sub_FFAAFDF4
"		MOV	R1, R5 \n"
"		BL	sub_FF8B571C \n"
"		MOV	R0, R5 \n"
"		BL	sub_FFAAFD10 \n"
"		MOV	R0, R5 \n"
"		BL	sub_FFAB012C \n"
"		MOV	R4, R0 \n"
"		LDR	R1, =0xC918 \n"
"		MOV	R0, #0x8A \n"
"		MOV	R2, #4 \n"
"		BL	sub_FF88D7A0 \n"		// PT_GetPropertyCaseString
"		TST	R0, #1 \n"
"		LDRNE	R1, =0x1F6 \n"
//"		ADRNE	R0, aSsstandardcapt \n" // "SsStandardCaptureSeq.c"
"		LDRNE	R0, =0xFFAB0658 \n"
"		BLNE	_DebugAssert \n"
"		BL	sub_FF87E0F8 \n"
"		MOV	R0, R4 \n"

"		BL	wait_until_remote_button_is_released\n" // Added (not tested) -------->
"		BL	capt_seq_hook_set_nr_my \n"	// Added ------------->

"		B	sub_FFAB0544 \n"		// Return to firmware --------->
/*
"		CMP	R0, #1 \n"
"		MOV	R4, #0 \n"
"		BEQ	loc_FFAB0588 \n"
"		CMP	R0, #2 \n"
"		BEQ	loc_FFAB0598 \n"
"		CMP	R0, #3 \n"
"		BEQ	loc_FFAB05BC \n"
"		CMP	R0, #7 \n"
"		BNE	loc_FFAB05D8 \n"
"		MOV	R0, #0 \n"
"		BL	sub_FF8B574C \n"
"		MOV	R0, #4 \n"
"		STR	R0, [SP,#0x4] \n"
"loc_FFAB0578: \n"
"		ADD	R1, SP,	#0x4 \n"
"		MOV	R0, R5 \n"
"		BL	sub_FFAB034C \n"
"		B	loc_FFAB05B4 \n"
"loc_FFAB0588: \n"
"		MOV	R0, #1 \n"
"		BL	sub_FF8B574C \n"
"		STR	R4, [SP,#0x4] \n"
"		B	loc_FFAB0578 \n"
"loc_FFAB0598: \n"
"		MOV	R0, #1 \n"
"		BL	sub_FF8B574C \n"
"		MOV	R0, #1 \n"
"		STR	R0, [SP,#0x4] \n"
"		MOV	R0, R5 \n"
"		ADD	R1, SP,	#0x4 \n"
"		BL	sub_FFAB072C \n"
"loc_FFAB05B4: \n"
"		MOV	R6, R0 \n"
"		B	loc_FFAB05E4 \n"
"loc_FFAB05BC: \n"
"		MOV	R0, #1 \n"
"		BL	sub_FF8B574C \n"
"		ADD	R1, SP,	#0x4 \n"
"		MOV	R0, R5 \n"
"		STR	R4, [SP,#0x4] \n"
"		BL	sub_FFAB03C8 \n"
"		B	loc_FFAB05B4 \n"
"loc_FFAB05D8: \n"
"		MOV	R1, #0x22C \n"
//"		ADR	R0, aSsstandardcapt \n" // "SsStandardCaptureSeq.c"
"		LDR	R0, =0xFFAB0658 \n"
"		BL	_DebugAssert \n"
"loc_FFAB05E4: \n"
"		TST	R6, #1 \n"
"		MOVNE	R0, R6 \n"
"		BNE	locret_FFAB063C \n"
"		MOV	R1, #0 \n"
//"		ADR	R0, unk_FFAB02F8 \n"
"		LDR	R0, =0xFFAB02F8 \n"
"		BL	sub_FF8B571C \n"
"		MOV	R0, R5 \n"
"		BL	sub_FFAB01BC \n"
"		BL	sub_FF96EC78 \n"
"		MOV	R3, #0x244 \n"
"		STR	R3, [SP] \n"
"		LDR	R2, =0x3A98 \n"
//"		ADR	R3, aSsstandardcapt  \n"// "SsStandardCaptureSeq.c"
"		LDR	R3, =0xFFAB0658 \n"
"		MOV	R1, #4 \n"
"		BL	sub_FF8808DC \n"
"		CMP	R0, #0 \n"
"		MOVNE	R1, #0x244 \n"
//"		ADRNE	R0, aSsstandardcapt \n" // "SsStandardCaptureSeq.c"
"		LDRNE	R0, =0xFFAB0658 \n"
"		BLNE	_DebugAssert \n"
"		LDRH	R0, [SP,#0x4] \n"
"		STRH	R0, [R5,#0x14] \n"
"		MOV	R0, #0 \n"
"locret_FFAB063C: \n"
"		LDMFD	SP!, {R2-R6,PC} \n"
*/
	); 
}

/*----------------------------------------------------------------------
	exp_drv_task()
-----------------------------------------------------------------------*/
void __attribute__((naked,noinline)) exp_drv_task()
{
	// FF8BFA94
	asm volatile(
"		STMFD	SP!, {R4-R8,LR} \n"
"		SUB	SP, SP,	#0x20 \n"
"		LDR	R8, =0xBB8 \n"
"		LDR	R7, =0x43F8 \n"
"		LDR	R5, =0x544E0 \n"
"		MOV	R0, #0 \n"
"		ADD	R6, SP,	#0x10 \n"
"		STR	R0, [SP,#0xC] \n"
"loc_FF8BFAB4: \n"
"		LDR	R0, [R7,#0x20] \n"
"		MOV	R2, #0 \n"
"		ADD	R1, SP,	#0x1C \n"
"		BL	sub_FF839B8C \n"
"		LDR	R0, [SP,#0xC] \n"
"		CMP	R0, #1 \n"
"		BNE	loc_FF8BFB00 \n"
"		LDR	R0, [SP,#0x1C] \n"
"		LDR	R0, [R0] \n"
"		CMP	R0, #0x14 \n"
"		CMPNE	R0, #0x15 \n"
"		CMPNE	R0, #0x16 \n"
"		CMPNE	R0, #0x17 \n"
"		BEQ	loc_FF8BFC64 \n"
"		CMP	R0, #0x29 \n"
"		BEQ	loc_FF8BFBEC \n"
"		ADD	R1, SP,	#0xC \n"
"		MOV	R0, #0 \n"
"		BL	sub_FF8BFA44 \n"
"loc_FF8BFB00: \n"
"		LDR	R0, [SP,#0x1C] \n"
"		LDR	R1, [R0] \n"
"		CMP	R1, #0x2F \n"
"		BNE	loc_FF8BFB30 \n"
"		LDR	R0, [SP,#0x1C] \n"
"		BL	sub_FF8C0E38 \n"
"		LDR	R0, [R7,#0x1C] \n"
"		MOV	R1, #1 \n"
"		BL	sub_FF8855D8 \n"
"		BL	sub_FF81EB30 \n"
"		ADD	SP, SP,	#0x20 \n"
"		LDMFD	SP!, {R4-R8,PC} \n"
"loc_FF8BFB30: \n"
"		CMP	R1, #0x2E \n"
"		BNE	loc_FF8BFB4C \n"
"		LDR	R2, [R0,#0x8C]! \n"
"		LDR	R1, [R0,#4] \n"
"		MOV	R0, R1 \n"
"		BLX	R2 \n"
"		B	loc_FF8C0120 \n"
"loc_FF8BFB4C: \n"
"		CMP	R1, #0x27 \n"
"		BNE	loc_FF8BFB9C \n"
"		LDR	R0, [R7,#0x1C] \n"
"		MOV	R1, #0x80 \n"
"		BL	sub_FF88560C \n"
"		LDR	R0, =0xFF8BB8F4 \n"
"		MOV	R1, #0x80 \n"
"		BL	sub_FF961628 \n"
"		LDR	R0, [R7,#0x1C] \n"
"		MOV	R2, R8 \n"
"		MOV	R1, #0x80 \n"
"		BL	sub_FF885518 \n"
"		TST	R0, #1 \n"
"		LDRNE	R1, =0x1089 \n"
"		BNE	loc_FF8BFC58 \n"
"loc_FF8BFB88: \n"
"		LDR	R1, [SP,#0x1C] \n"
"		LDR	R0, [R1,#0x90] \n"
"		LDR	R1, [R1,#0x8C] \n"
"		BLX	R1 \n"
"		B	loc_FF8C0120 \n"
"loc_FF8BFB9C: \n"
"		CMP	R1, #0x28 \n"
"		BNE	loc_FF8BFBE4 \n"
"		ADD	R1, SP,	#0xC \n"
"		BL	sub_FF8BFA44 \n"
"		LDR	R0, [R7,#0x1C] \n"
"		MOV	R1, #0x100 \n"
"		BL	sub_FF88560C \n"
"		LDR	R0, =0xFF8BB904 \n"
"		MOV	R1, #0x100 \n"
"		BL	sub_FF962058 \n"
"		LDR	R0, [R7,#0x1C] \n"
"		MOV	R2, R8 \n"
"		MOV	R1, #0x100 \n"
"		BL	sub_FF885518 \n"
"		TST	R0, #1 \n"
"		BEQ	loc_FF8BFB88 \n"
"		LDR	R1, =0x1093 \n"
"		B	loc_FF8BFC58 \n"
"loc_FF8BFBE4: \n"
"		CMP	R1, #0x29 \n"
"		BNE	loc_FF8BFBFC \n"
"loc_FF8BFBEC: \n"
"		LDR	R0, [SP,#0x1C] \n"
"		ADD	R1, SP,	#0xC \n"
"		BL	sub_FF8BFA44 \n"
"		B	loc_FF8BFB88 \n"
"loc_FF8BFBFC: \n"
"		CMP	R1, #0x2C \n"
"		BNE	loc_FF8BFC14 \n"
"		BL	sub_FF8AE190 \n"
"		BL	sub_FF8AED9C \n"
"		BL	sub_FF8AE908 \n"
"		B	loc_FF8BFB88 \n"
"loc_FF8BFC14: \n"
"		CMP	R1, #0x2D \n"
"		BNE	loc_FF8BFC64 \n"
"		LDR	R0, [R7,#0x1C] \n"
"		MOV	R1, #4 \n"
"		BL	sub_FF88560C \n"
"		LDR	R1, =0xFF8BB924 \n"
"		LDR	R0, =0xFFFFF400 \n"
"		MOV	R2, #4 \n"
"		BL	sub_FF8ADC0C \n"
"		BL	sub_FF8ADE94 \n"
"		LDR	R0, [R7,#0x1C] \n"
"		MOV	R2, R8 \n"
"		MOV	R1, #4 \n"
"		BL	sub_FF885434 \n"
"		TST	R0, #1 \n"
"		BEQ	loc_FF8BFB88 \n"
"		LDR	R1, =0x10BB \n"
"loc_FF8BFC58: \n"
"		LDR	R0, =0xFF8BBFAC \n"	// "ExpDrv.c"
"		BL	_DebugAssert \n"
"		B	loc_FF8BFB88 \n"
"loc_FF8BFC64: \n"
"		LDR	R0, [SP,#0x1C] \n"
"		MOV	R4, #1 \n"
"		LDR	R1, [R0] \n"
"		CMP	R1, #0x12 \n"
"		CMPNE	R1, #0x13 \n"
"		BNE	loc_FF8BFCD4 \n"
"		LDR	R1, [R0,#0x7C] \n"
"		ADD	R1, R1,	R1,LSL#1 \n"
"		ADD	R1, R0,	R1,LSL#2 \n"
"		SUB	R1, R1,	#8 \n"
"		LDMIA	R1, {R2-R4} \n"
"		STMIA	R6, {R2-R4} \n"
"		BL	sub_FF8BE1CC \n"
"		LDR	R0, [SP,#0x1C] \n"
"		LDR	R1, [R0,#0x7C] \n"
"		LDR	R3, [R0,#0x8C] \n"
"		LDR	R2, [R0,#0x90] \n"
"		ADD	R0, R0,	#4 \n"
"		BLX	R3 \n"
"		LDR	R0, [SP,#0x1C] \n"
"		BL	sub_FF8C1244 \n"
"		LDR	R0, [SP,#0x1C] \n"
"		LDR	R1, [R0,#0x7C] \n"
"		LDR	R3, [R0,#0x94] \n"
"		LDR	R2, [R0,#0x98] \n"
"		ADD	R0, R0,	#4 \n"
"		BLX	R3 \n"
"		B	loc_FF8C005C \n"
"loc_FF8BFCD4: \n"
"		CMP	R1, #0x14 \n"
"		CMPNE	R1, #0x15 \n"
"		CMPNE	R1, #0x16 \n"
"		CMPNE	R1, #0x17 \n"
"		BNE	loc_FF8BFD8C \n"
"		ADD	R3, SP,	#0xC \n"
"		MOV	R2, SP \n"
"		ADD	R1, SP,	#0x10 \n"
"		BL	sub_FF8BE438 \n"
"		CMP	R0, #1 \n"
"		MOV	R4, R0 \n"
"		CMPNE	R4, #5 \n"
"		BNE	loc_FF8BFD28 \n"
"		LDR	R0, [SP,#0x1C] \n"
"		MOV	R2, R4 \n"
"		LDR	R1, [R0,#0x7C]! \n"
"		LDR	R12, [R0,#0x10]! \n"
"		LDR	R3, [R0,#4] \n"
"		MOV	R0, SP \n"
"		BLX	R12 \n"
"		B	loc_FF8BFD60 \n"
"loc_FF8BFD28: \n"
"		LDR	R0, [SP,#0x1C] \n"
"		CMP	R4, #2 \n"
"		LDR	R3, [R0,#0x90] \n"
"		CMPNE	R4, #6 \n"
"		BNE	loc_FF8BFD74 \n"
"		LDR	R12, [R0,#0x8C] \n"
"		MOV	R0, SP \n"
"		MOV	R2, R4 \n"
"		MOV	R1, #1 \n"
"		BLX	R12 \n"
"		LDR	R0, [SP,#0x1C] \n"
"		MOV	R2, SP \n"
"		ADD	R1, SP,	#0x10 \n"
"		BL	sub_FF8BF790 \n"
"loc_FF8BFD60: \n"
"		LDR	R0, [SP,#0x1C] \n"
"		LDR	R2, [SP,#0xC] \n"
"		MOV	R1, R4 \n"
"		BL	sub_FF8BF9E4 \n"
"		B	loc_FF8C005C \n"
"loc_FF8BFD74: \n"
"		LDR	R1, [R0,#0x7C] \n"
"		LDR	R12, [R0,#0x8C] \n"
"		ADD	R0, R0,	#4 \n"
"		MOV	R2, R4 \n"
"		BLX	R12 \n"
"		B	loc_FF8C005C \n"
"loc_FF8BFD8C: \n"
"		CMP	R1, #0x23 \n"
"		CMPNE	R1, #0x24 \n"
"		BNE	loc_FF8BFDD8 \n"
"		LDR	R1, [R0,#0x7C] \n"
"		ADD	R1, R1,	R1,LSL#1 \n"
"		ADD	R1, R0,	R1,LSL#2 \n"
"		SUB	R1, R1,	#8 \n"
"		LDMIA	R1, {R2-R4} \n"
"		STMIA	R6, {R2-R4} \n"
"		BL	sub_FF8BD250 \n"
"		LDR	R0, [SP,#0x1C] \n"
"		LDR	R1, [R0,#0x7C] \n"
"		LDR	R3, [R0,#0x8C] \n"
"		LDR	R2, [R0,#0x90] \n"
"		ADD	R0, R0,	#4 \n"
"		BLX	R3 \n"
"		LDR	R0, [SP,#0x1C] \n"
"		BL	sub_FF8BD69C \n"
"		B	loc_FF8C005C \n"
"loc_FF8BFDD8: \n"
"		ADD	R1, R0,	#4 \n"
"		LDMIA	R1, {R2,R3,R12} \n"
"		STMIA	R6, {R2,R3,R12} \n"
"		LDR	R1, [R0] \n"
"		CMP	R1, #0x26 \n"
"		ADDLS	PC, PC,	R1,LSL#2 \n"
"		B	loc_FF8C003C \n"
"loc_FF8BFDF4: \n"
"		B	loc_FF8BFE90 \n"
"loc_FF8BFDF8: \n"
"		B	loc_FF8BFE90 \n"
"loc_FF8BFDFC: \n"
"		B	loc_FF8BFE98 \n"
"loc_FF8BFE00: \n"
"		B	loc_FF8BFEA0 \n"
"loc_FF8BFE04: \n"
"		B	loc_FF8BFEA0 \n"
"loc_FF8BFE08: \n"
"		B	loc_FF8BFEA0 \n"
"loc_FF8BFE0C: \n"
"		B	loc_FF8BFE90 \n"
"loc_FF8BFE10: \n"
"		B	loc_FF8BFE98 \n"
"loc_FF8BFE14: \n"
"		B	loc_FF8BFEA0 \n"
"loc_FF8BFE18: \n"
"		B	loc_FF8BFEA0 \n"
"loc_FF8BFE1C: \n"
"		B	loc_FF8BFEB8 \n"
"loc_FF8BFE20: \n"
"		B	loc_FF8BFEB8 \n"
"loc_FF8BFE24: \n"
"		B	loc_FF8C0028 \n"
"loc_FF8BFE28: \n"
"		B	loc_FF8C0030 \n"
"loc_FF8BFE2C: \n"
"		B	loc_FF8C0030 \n"
"loc_FF8BFE30: \n"
"		B	loc_FF8C0030 \n"
"loc_FF8BFE34: \n"
"		B	loc_FF8C0030 \n"
"loc_FF8BFE38: \n"
"		B	loc_FF8C0038 \n"
"loc_FF8BFE3C: \n"
"		B	loc_FF8C003C \n"
"loc_FF8BFE40: \n"
"		B	loc_FF8C003C \n"
"loc_FF8BFE44: \n"
"		B	loc_FF8C003C \n"
"loc_FF8BFE48: \n"
"		B	loc_FF8C003C \n"
"loc_FF8BFE4C: \n"
"		B	loc_FF8C003C \n"
"loc_FF8BFE50: \n"
"		B	loc_FF8C003C \n"
"loc_FF8BFE54: \n"
"		B	loc_FF8BFEA8 \n"
"loc_FF8BFE58: \n"
"		B	loc_FF8BFEB0 \n"
"loc_FF8BFE5C: \n"
"		B	loc_FF8BFEB0 \n"
"loc_FF8BFE60: \n"
"		B	loc_FF8BFEC4 \n"
"loc_FF8BFE64: \n"
"		B	loc_FF8BFEC4 \n"
"loc_FF8BFE68: \n"
"		B	loc_FF8BFECC \n"
"loc_FF8BFE6C: \n"
"		B	loc_FF8BFF04 \n"
"loc_FF8BFE70: \n"
"		B	loc_FF8BFF3C \n"
"loc_FF8BFE74: \n"
"		B	loc_FF8BFFD8 \n"
"loc_FF8BFE78: \n"
"		B	loc_FF8C0010 \n"
"loc_FF8BFE7C: \n"
"		B	loc_FF8C0010 \n"
"loc_FF8BFE80: \n"
"		B	loc_FF8C003C \n"
"loc_FF8BFE84: \n"
"		B	loc_FF8C003C \n"
"loc_FF8BFE88: \n"
"		B	loc_FF8C0018 \n"
"loc_FF8BFE8C: \n"
"		B	loc_FF8C0020 \n"
"loc_FF8BFE90: \n"
// jumptable FF8BFDEC entries 0,1,6
"		BL	sub_FF8BBE34 \n"
"		B	loc_FF8C003C \n"
"loc_FF8BFE98: \n"
// jumptable FF8BFDEC entries 2,7
"		BL	sub_FF8BC0D0 \n"
"		B	loc_FF8C003C \n"
"loc_FF8BFEA0: \n"
// jumptable FF8BFDEC entries 3-5,8,9
"		BL	sub_FF8BC2F8 \n"
"		B	loc_FF8C003C \n"
"loc_FF8BFEA8: \n"
// jumptable FF8BFDEC entry 24
"		BL	sub_FF8BC5D0 \n"
"		B	loc_FF8C003C \n"
"loc_FF8BFEB0: \n"
// jumptable FF8BFDEC entries 25,26
"		BL	sub_FF8BC7E8 \n"
"		B	loc_FF8C003C \n"
"loc_FF8BFEB8: \n"
// jumptable FF8BFDEC entries 10,11
//"		BL	sub_FF8BCB0C \n"
"		BL	sub_FF8BCB0C_my \n"			// Patched ---------->
"		MOV	R4, #0 \n"
"		B	loc_FF8C003C \n"
"loc_FF8BFEC4: \n"
// jumptable FF8BFDEC entries 27,28
"		BL	sub_FF8BCC54 \n"
"		B	loc_FF8C003C \n"
"loc_FF8BFECC: \n"
// jumptable FF8BFDEC entry 29
"		LDRH	R1, [R0,#4] \n"
"		STRH	R1, [SP,#0x10] \n"
"		LDRH	R1, [R5,#2] \n"
"		STRH	R1, [SP,#0x12] \n"
"		LDRH	R1, [R5,#4] \n"
"		STRH	R1, [SP,#0x14] \n"
"		LDRH	R1, [R5,#6] \n"
"		STRH	R1, [SP,#0x16] \n"
"		LDRH	R1, [R0,#0xC] \n"
"		STRH	R1, [SP,#0x18] \n"
"		LDRH	R1, [R5,#0xA] \n"
"		STRH	R1, [SP,#0x1A] \n"
"		BL	sub_FF8C0F3C \n"
"		B	loc_FF8C003C \n"
"loc_FF8BFF04: \n"
// jumptable FF8BFDEC entry 30
"		LDRH	R1, [R0,#4] \n"
"		STRH	R1, [SP,#0x10] \n"
"		LDRH	R1, [R5,#2] \n"
"		STRH	R1, [SP,#0x12] \n"
"		LDRH	R1, [R5,#4] \n"
"		STRH	R1, [SP,#0x14] \n"
"		LDRH	R1, [R5,#6] \n"
"		STRH	R1, [SP,#0x16] \n"
"		LDRH	R1, [R5,#8] \n"
"		STRH	R1, [SP,#0x18] \n"
"		LDRH	R1, [R5,#0xA] \n"
"		STRH	R1, [SP,#0x1A] \n"
"		BL	sub_FF8C1044 \n"
"		B	loc_FF8C003C \n"
"loc_FF8BFF3C: \n"
// jumptable FF8BFDEC entry 31
"		LDRH	R1, [R5] \n"
"		STRH	R1, [SP,#0x10] \n"
"		LDRH	R1, [R0,#6] \n"
"		STRH	R1, [SP,#0x12] \n"
"		LDRH	R1, [R5,#4] \n"
"		STRH	R1, [SP,#0x14] \n"
"		LDRH	R1, [R5,#6] \n"
"		STRH	R1, [SP,#0x16] \n"
"		LDRH	R1, [R5,#8] \n"
"		STRH	R1, [SP,#0x18] \n"
"		LDRH	R1, [R5,#0xA] \n"
"		STRH	R1, [SP,#0x1A] \n"
"		BL	sub_FF8C10F8 \n"
"		B	loc_FF8C003C \n"
"loc_FF8BFFD8: \n"
// jumptable FF8BFDEC entry 32
"		LDRH	R1, [R5] \n"
"		STRH	R1, [SP,#0x10] \n"
"		LDRH	R1, [R5,#2] \n"
"		STRH	R1, [SP,#0x12] \n"
"		LDRH	R1, [R5,#4] \n"
"		STRH	R1, [SP,#0x14] \n"
"		LDRH	R1, [R5,#6] \n"
"		STRH	R1, [SP,#0x16] \n"
"		LDRH	R1, [R0,#0xC] \n"
"		STRH	R1, [SP,#0x18] \n"
"		LDRH	R1, [R5,#0xA] \n"
"		STRH	R1, [SP,#0x1A] \n"
"		BL	sub_FF8C11A0 \n"
"		B	loc_FF8C003C \n"
"loc_FF8C0010: \n"
// jumptable FF8BFDEC entries 33,34
"		BL	sub_FF8BD028 \n"
"		B	loc_FF8C003C \n"
"loc_FF8C0018: \n"
// jumptable FF8BFDEC entry 37
"		BL	sub_FF8BD7A0 \n"
"		B	loc_FF8C003C \n"
"loc_FF8C0020: \n"
// jumptable FF8BFDEC entry 38
"		BL	sub_FF8BDA3C \n"
"		B	loc_FF8C003C \n"
"loc_FF8C0028: \n"
// jumptable FF8BFDEC entry 12
"		BL	sub_FF8BDC1C \n"
"		B	loc_FF8C003C \n"
"loc_FF8C0030: \n"
// jumptable FF8BFDEC entries 13-16
"		BL	sub_FF8BDDD8 \n"
"		B	loc_FF8C003C \n"
"loc_FF8C0038: \n"
// jumptable FF8BFDEC entry 17
"		BL	sub_FF8BDFC4 \n"
"loc_FF8C003C: \n"
// jumptable FF8BFDEC default entry
// jumptable FF8BFDEC entries 18-23,35,36
"		LDR	R0, [SP,#0x1C] \n"
"		LDR	R1, [R0,#0x7C] \n"
"		LDR	R3, [R0,#0x8C] \n"
"		LDR	R2, [R0,#0x90] \n"
"		ADD	R0, R0,	#4 \n"
"		BLX	R3 \n"
"		CMP	R4, #1 \n"
"		BNE	loc_FF8C00A4 \n"
"loc_FF8C005C: \n"
"		LDR	R0, [SP,#0x1C] \n"
"		MOV	R2, #0xC \n"
"		LDR	R1, [R0,#0x7C] \n"
"		ADD	R1, R1,	R1,LSL#1 \n"
"		ADD	R0, R0,	R1,LSL#2 \n"
"		SUB	R4, R0,	#8 \n"
"		LDR	R0, =0x544E0 \n"
"		ADD	R1, SP,	#0x10 \n"
"		BL	sub_FFB49F04 \n"
"		LDR	R0, =0x544EC \n"
"		MOV	R2, #0xC \n"
"		ADD	R1, SP,	#0x10 \n"
"		BL	sub_FFB49F04 \n"
"		LDR	R0, =0x544F8 \n"
"		MOV	R2, #0xC \n"
"		MOV	R1, R4 \n"
"		BL	sub_FFB49F04 \n"
"		B	loc_FF8C0120 \n"
"loc_FF8C00A4: \n"
"		LDR	R0, [SP,#0x1C] \n"
"		MOV	R3, #1 \n"
"		LDR	R0, [R0] \n"
"		CMP	R0, #0xB \n"
"		BNE	loc_FF8C00EC \n"
"		MOV	R2, #0 \n"
"		STRD	R2, [SP] \n"
"		MOV	R2, #1 \n"
"		MOV	R1, #1 \n"
"		MOV	R0, #0 \n"
"		BL	sub_FF8BBC14 \n"
"		MOV	R3, #1 \n"
"		MOV	R2, #0 \n"
"		STRD	R2, [SP] \n"
"		MOV	R2, #1 \n"
"		MOV	R1, #1 \n"
"		MOV	R0, #0 \n"
"		B	loc_FF8C011C \n"
"loc_FF8C00EC: \n"
"		MOV	R2, #1 \n"
"		STRD	R2, [SP] \n"
"		MOV	R3, #1 \n"
"		MOV	R1, #1 \n"
"		MOV	R0, #1 \n"
"		BL	sub_FF8BBC14 \n"
"		MOV	R3, #1 \n"
"		MOV	R2, #1 \n"
"		MOV	R1, #1 \n"
"		MOV	R0, #1 \n"
"		STR	R3, [SP] \n"
"		STR	R3, [SP,#0x4] \n"
"loc_FF8C011C: \n"
"		BL	sub_FF8BBD7C \n"
"loc_FF8C0120: \n"
"		LDR	R0, [SP,#0x1C] \n"
"		BL	sub_FF8C0E38 \n"
"		B	loc_FF8BFAB4 \n"
	);
}

void __attribute__((naked,noinline)) sub_FF8BCB0C_my()
{
	asm volatile (
"		STMFD	SP!, {R4-R8,LR} \n"
"		LDR	R7, =0x43F8 \n"
"		MOV	R4, R0 \n"
"		LDR	R0, [R7,#0x1C] \n"
"		MOV	R1, #0x3E \n"
"		BL	sub_FF88560C \n"
"		LDRSH	R0, [R4,#4] \n"
"		MOV	R2, #0 \n"
"		MOV	R1, #0 \n"
"		BL	sub_FF8BB978 \n"
"		MOV	R5, R0 \n"
"		LDRSH	R0, [R4,#6] \n"
"		BL	sub_FF8BBA88 \n"
"		LDRSH	R0, [R4,#8] \n"
"		BL	sub_FF8BBAE0 \n"
"		LDRSH	R0, [R4,#0xA] \n"
"		BL	sub_FF8BBB38 \n"
"		LDRSH	R0, [R4,#0xC] \n"
"		MOV	R1, #0 \n"
"		BL	sub_FF8BBB90 \n"
"		MOV	R6, R0 \n"
"		LDRSH	R0, [R4,#0xE] \n"
"		BL	sub_FF8C0EDC \n"
"		LDR	R0, [R4] \n"
"		LDR	R8, =0x544F8 \n"
"		CMP	R0, #0xB \n"
"		MOVEQ	R5, #0 \n"
"		MOVEQ	R6, #0 \n"
"		BEQ	loc_FF8BCBA8 \n"
"		CMP	R5, #1 \n"
"		BNE	loc_FF8BCBA8 \n"
"		LDRSH	R0, [R4,#4] \n"
"		LDR	R1, =0xFF8BB8E4 \n"
"		MOV	R2, #2 \n"
"		BL	sub_FF961974 \n"
"		STRH	R0, [R4,#4] \n"
"		MOV	R0, #0 \n"
"		STR	R0, [R7,#0x28] \n"
"		B	loc_FF8BCBB0 \n"
"loc_FF8BCBA8: \n"
"		LDRH	R0, [R8] \n"
"		STRH	R0, [R4,#4] \n"
"loc_FF8BCBB0: \n"
"		CMP	R6, #1 \n"
"		LDRNEH	R0, [R8,#8] \n"
"		BNE	loc_FF8BCBCC \n"
"		LDRSH	R0, [R4,#0xC] \n"
"		LDR	R1, =0xFF8BB968 \n"
"		MOV	R2, #0x20 \n"
"		BL	sub_FF8C0EF8 \n"
"loc_FF8BCBCC: \n"
"		STRH	R0, [R4,#0xC] \n"
"		LDRSH	R0, [R4,#6] \n"
//"		BL	sub_FF8ADF00 \n"
"		BL	sub_FF8ADF00_my \n"				// Patched ---------->
"		LDRSH	R0, [R4,#8] \n"
"		MOV	R1, #1 \n"
"		BL	sub_FF8AE650 \n"
"		MOV	R1, #0 \n"
"		ADD	R0, R4,	#8 \n"
"		BL	sub_FF8AE6D8 \n"
"		LDRSH	R0, [R4,#0xE] \n"
"		BL	sub_FF8B68D8 \n"
"		LDR	R4, =0xBB8 \n"
"		CMP	R5, #1 \n"
"		BNE	loc_FF8BCC24 \n"
"		LDR	R0, [R7,#0x1C] \n"
"		MOV	R2, R4 \n"
"		MOV	R1, #2 \n"
"		BL	sub_FF885518 \n"
"		TST	R0, #1 \n"
"		LDRNE	R1, =0x61E \n"
"		LDRNE	R0, =0xFF8BBFAC \n"	// "ExpDrv.c"
"		BLNE	_DebugAssert \n"
"loc_FF8BCC24: \n"
"		CMP	R6, #1 \n"
"		LDMNEFD	SP!, {R4-R8,PC} \n"
"		LDR	R0, [R7,#0x1C] \n"
"		MOV	R2, R4 \n"
"		MOV	R1, #0x20 \n"
"		BL	sub_FF885518 \n"
"		TST	R0, #1 \n"
"		LDRNE	R1, =0x623 \n"
//"		ADRNE	R0, aExpdrv_c \n"	// "ExpDrv.c"
"		LDRNE	R0, =0xFF8BBFAC \n"
"		LDMNEFD	SP!, {R4-R8,LR} \n"
"		BNE	_DebugAssert \n"
"		LDMFD	SP!, {R4-R8,PC}	 \n"
	);
}

void __attribute__((naked,noinline))sub_FF8ADF00_my() {

	asm volatile (
"		STMFD	SP!, {R4-R6,LR} \n"
"		LDR	R5, =0x40DC \n"
"		MOV	R4, R0 \n"
"		LDR	R0, [R5,#4] \n"
"		CMP	R0, #1 \n"
"		LDRNE	R1, =0x146 \n"
//"		ADRNE	R0, aShutter_c \n"	// "Shutter.c"
"		LDRNE	R0, =0xFF8ADD04 \n" 
"		BLNE	_DebugAssert \n"
"		CMN	R4, #0xC00 \n"
"		LDREQSH	R4, [R5,#2] \n"
"		CMN	R4, #0xC00 \n"
"		MOVEQ	R1, #0x14C \n"
//"		ADREQ	R0, aShutter_c \n"	// "Shutter.c"
"		LDREQ	R0, =0xFF8ADD04 \n" 
"		STRH	R4, [R5,#2] \n"
"		BLEQ	_DebugAssert \n"
"		MOV	R0, R4 \n"
//"		BL	sub_FFA0E804 \n"
"		BL	apex2us \n"				// Patched (call our own apex2us)
"		MOV	R4, R0 \n"
"		BL	sub_FF8F6B80 \n"
"		MOV	R0, R4 \n"
"		BL	sub_FF9030B0 \n"
"		TST	R0, #1 \n"
"		LDRNE	R1, =0x151 \n"
"		LDMNEFD	SP!, {R4-R6,LR} \n"
//"		ADRNE	R0, aShutter_c \n"	// "Shutter.c"
"		LDRNE	R0, =0xFF8ADD04 \n" 
"		BNE	_DebugAssert \n"
"		LDMFD	SP!, {R4-R6,PC} \n"
	);
}
