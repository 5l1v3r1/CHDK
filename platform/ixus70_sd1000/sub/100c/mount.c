void __attribute__((naked,noinline)) init_file_modules_task(){
 asm volatile(
                "STMFD   SP!, {R4,LR}\n" // found in sub_FF8242BC
                "BL      _Unmount_FileSystem\n" // + 
                "BL      sub_FF81C958\n"
                "SUBS    R4, R0, #0\n"
                "MOV     R0, #0x5000\n"
                "MOV     R1, #0\n"
                "ADD     R0, R0, #6\n"
                "BEQ     loc_FF8242DC\n"
                "BL      sub_FFB327AC\n"  
"loc_FF8242DC:\n"
                "BL      sub_FF81C984_my\n"  //------------->
                "MOV     R0, #0x5000\n"
                "CMP     R4, #0\n"
                "MOV     R1, R4\n"
                "ADD     R0, R0, #6\n"
                "LDMNEFD SP!, {R4,PC}\n"
                "LDMFD   SP!, {R4,LR}\n"
                "B       sub_FFB327AC\n" 
 );
}

void __attribute__((naked,noinline)) sub_FF81C984_my(){
 asm volatile(
                "STR     LR, [SP,#-4]!\n"
                "BL      Mount_FileSystem_my\n"   
    //          "BL      sub_FFA992B8\n" // original function
                "LDR     R3, =0x1E0C\n"
                "LDR     R2, [R3]\n"
                "CMP     R2, #0\n"
                "BNE     loc_FF81C9C0\n"
                "BL      sub_FF845FE0\n"
                "AND     R0, R0, #0xFF\n"
                "BL      sub_FFA688F8\n"
                "BL      sub_FF845FE0\n"
                "AND     R0, R0, #0xFF\n"
                "BL      sub_FFA7EE04\n"
                "BL      sub_FF845FF0\n"
                "AND     R0, R0, #0xFF\n"
                "BL      sub_FFA689E8\n"
"loc_FF81C9C0:\n"
                "LDR     R2, =0x1E08\n"
                "MOV     R3, #1\n"
                "STR     R3, [R2]\n"
                "LDR     PC, [SP],#4\n"
 );
}

void __attribute__((naked,noinline)) Mount_FileSystem_my(){
 asm volatile(
                "STMFD   SP!, {R4-R6,LR}\n"
                "MOV     R4, #0\n"
                "MOV     R5, R4\n"
                "LDR     R6, =0x8CB88\n"
                "MOV     R0, R5\n"
                "BL      sub_FFA98C94\n"
                "LDR     R0, [R6,#0x38]\n"
                "BL      sub_FFA98328\n"
                "CMP     R0, R4\n"
                "MOV     R1, R5\n"
                "MOV     R0, R5\n"
                "BNE     loc_FFA99300\n"
                "LDR     R3, =0xA0E8\n"
                "LDR     R2, =0xA0E0\n"
                "STR     R1, [R3]\n"
                "LDR     R3, =0xA0E4\n"
                "STR     R1, [R2]\n"
                "STR     R1, [R3]\n"
"loc_FFA99300:\n"
                "BL      sub_FFA98CE4\n"
                "MOV     R0, R5\n"
                "BL      sub_FFA99014_my\n"  //------------>
                "MOV     R4, R0\n"
                "MOV     R0, R5\n"
                "BL      sub_FFA9909C\n"
                "LDR     R1, [R6,#0x3C]\n"
                "AND     R2, R4, R0\n"
                "MOV     R0, R6\n"
                "BL      sub_FFA99268\n"
                "STR     R0, [R6,#0x40]\n"
                "LDMFD   SP!, {R4-R6,PC}\n"
 );
}

void __attribute__((naked,noinline)) sub_FFA99014_my(){
 asm volatile(
                "STMFD   SP!, {R4-R7,LR}\n"
                "LDR     R7, =0xA0E4\n"
                "LDR     R3, [R7]\n"
                "MOV     R4, R0\n"
                "CMP     R3, #0\n"
                "ADD     R3, R4, R4,LSL#1\n"
                "RSB     R3, R4, R3,LSL#3\n"
                "LDR     R6, =0x8CBC0\n"
                "MOV     R5, R3,LSL#2\n"
                "MOV     R1, R4\n"
                "BNE     loc_FFA99088\n"
                "LDR     R0, [R6,R5]\n"
                "BL      sub_FFA98D9C_my\n"  //----------------->
                "SUBS    R3, R0, #0\n"
                "MOV     R1, R4\n"
                "BEQ     loc_FFA99060\n"
                "LDR     R0, [R6,R5]\n"
                "BL      sub_FFA98EF0\n"
                "MOV     R3, R0\n"
"loc_FFA99060:\n"
                "CMP     R3, #0\n"
                "MOV     R0, R4\n"
                "BEQ     loc_FFA99074\n"
                "BL      sub_FFA98400\n"
                "MOV     R3, R0\n"
"loc_FFA99074:\n"
                "CMP     R3, #0\n"
                "MOV     R0, R3\n"
                "MOVNE   R3, #1\n"
                "STRNE   R3, [R7]\n"
                "LDMFD   SP!, {R4-R7,PC}\n"
"loc_FFA99088:\n"
               "MOV     R0, #1\n"
               "LDMFD   SP!, {R4-R7,PC}\n"
 );
}

void __attribute__((naked,noinline)) sub_FFA98D9C_my(){
 asm volatile(
                "STMFD   SP!, {R4-R8,LR}\n"
                "MOV     R5, R1\n"
                "MOV     R8, R5,LSL#1\n"
                "ADD     R3, R8, R5\n"
                "LDR     R2, =0x8CBC4\n"
                "SUB     SP, SP, #8\n"
                "RSB     R3, R5, R3,LSL#3\n"
                "LDR     R1, [R2,R3,LSL#2]\n"
                "MOV     R6, #0\n"
                "STR     R6, [SP]\n"
                "MOV     R7, R0\n"
                "STR     R6, [SP,#4]\n"
                "CMP     R1, #6\n"
                "LDRLS   PC, [PC,R1,LSL#2]\n"
                "B       loc_FFA98E9C\n"
                ".long loc_FFA98E40\n"
                ".long loc_FFA98DF4\n"
                ".long loc_FFA98DF4\n"
                ".long loc_FFA98DF4\n"
                ".long loc_FFA98DF4\n"
                ".long loc_FFA98E8C\n"
                ".long loc_FFA98DF4\n"
"loc_FFA98DF4:\n"
                "MOV     R0, #3\n"
                "MOV     R1, #0x200\n"
                "MOV     R2, #0\n"
                "BL      sub_FF81E2B0\n"
                "SUBS    R6, R0, #0\n"
                "BEQ     loc_FFA98ED4\n"
                "ADD     R12, R8, R5\n"
                "RSB     R12, R5, R12,LSL#3\n"
                "LDR     R4, =0x8CBD4\n"
                "MOV     R0, R7\n"
                "MOV     R1, #0\n"
                "MOV     R2, #1\n"
                "MOV     R3, R6\n"
                "MOV     LR, PC\n"
                "LDR     PC, [R4,R12,LSL#2]\n"
                "CMP     R0, #1\n"
                "BNE     loc_FFA98E48\n"
                "MOV     R0, #3\n"
                "BL      sub_FF81E380\n"
"loc_FFA98E40:\n"
                "MOV     R0, #0\n"
                "B       loc_FFA98ED4\n"
"loc_FFA98E48:\n"
                "MOV     R0, R7\n"
                "BL      sub_FFAAC8B4\n"
                "MOV     R1, R0\n"
                "ADD     R2, SP, #4\n"
                "MOV     R3, SP\n"
                "MOV     R0, R6\n"
                "STMFD   SP!, {R4-R11,LR}\n" // +
                "BL      mbr_read\n"    //-----------> 
                "LDMFD   SP!, {R4-R11,LR}\n" // +
     //         "BL      sub_FFA9852C\n" // original function
                "MOV     R4, R0\n"
                "MOV     R0, #3\n"
                "BL      sub_FF81E380\n"
                "CMP     R4, #0\n"
                "BNE     loc_FFA98EAC\n"
                "MOV     R0, R7\n"
                "STR     R4, [SP,#4]\n"
                "BL      sub_FFAAC8B4\n"
                "STR     R0, [SP]\n"
                "B       loc_FFA98EAC\n"
"loc_FFA98E8C:\n"
                "MOV     R3, #0\n"
                "MOV     R2, #0x40\n"
                "STMEA   SP, {R2,R3}\n"
                "B       loc_FFA98EAC\n"
"loc_FFA98E9C:\n"
                "MOV     R1, #0x358\n"
                "LDR     R0, =0xFFA98B84\n" // aMounter_c
                "ADD     R1, R1, #2\n"
                "BL      sub_FFB20628\n" // DebugAssert
"loc_FFA98EAC:\n"
                "LDR     R2, =0x8CB88\n"
                "ADD     R3, R8, R5\n"
                "LDMFD   SP, {R0,R12}\n"
                "RSB     R3, R5, R3,LSL#3\n"
                "MOV     R3, R3,LSL#2\n"
                "ADD     R1, R2, #0x48\n"
                "ADD     R2, R2, #0x44\n"
                "STR     R0, [R1,R3]\n"
                "STR     R12, [R2,R3]\n"
                "MOV     R0, #1\n"
"loc_FFA98ED4:\n"
                "ADD     SP, SP, #8\n"
                "LDMFD   SP!, {R4-R8,PC}\n"
 );
}
