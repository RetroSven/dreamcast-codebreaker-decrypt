#include <stdio.h> 

unsigned long seeds[16] = {
0xA53A8888,
	0xA1427921, 0xAC9528B1, 0xC5892354, 0x49671B12,
	0xACC56121, 0xACB5381E, 0x765436E1, 0x9F2C3E54,
	0x1133E312, 0xAC5E7894, 0xE9F208B1, 0x4E87DCFE,
	0x43174312, 0x1D7A6C99, 0x874224A2
};


unsigned int dword_40414C = 0x00 ;


//sub_4011C0
unsigned int decrypt_codebreaker(unsigned int adr) {
	unsigned int eax, ebx, ecx, edx,dl, esi, bl ;
	eax = adr ;
	ecx = eax ;
	bl = dword_40414C ;

	ecx = ecx >> 0x1C ;
	edx = seeds[ecx] ;

	if ( (bl&0x04) != 0 ) {
		ecx = eax ;
		ecx = ecx & 0x7FFFFFF ;
		eax = eax >> 0x1B ;
		ecx = ecx << 1 ;
		eax = eax & 0x01 ;
		eax = eax | ecx ;


	}

	if ( (bl&0x02) != 0 ) {
		ecx = eax ;
		ecx = ecx & 0x7FFFFFF ;
		eax = eax >> 0x1B ;
		ecx = ecx << 1 ;
		eax = eax & 0x01 ;
		ecx = ecx | eax ;
		eax = ecx ;
		ecx = ecx & 0x0FFFFF ;
		eax = eax >> 0x14 ;
		eax = eax & 0xFF ;
		ecx = ecx << 8 ;
		eax = eax | ecx ;

	}



	if ( (bl&0x01) != 0 ) {
		edx = edx >> 4 ;
	}

	edx = edx & 0x0FFFFFFF ;
	eax = eax ^ edx ;
	ecx = eax ;
	ecx = ecx & 0x0FF00000 ;
	if ( ecx != 0x7100000 ) {
		edx = eax ;
		edx = edx & 0x0F ;
		edx = edx + 6 ;
		dword_40414C = edx ;
	}
	//printf("%08X %08X %08X %08X\n", adr, eax, ecx, dword_40414C) ;
	return eax ;
}


int main (int argc, char** argv) {
	//dword_40414C is initialized to 0x06 at the beginning of every decryption set (could be a set of several codes)
	//This value can be changed after decrypting a code (seems to be some kind of rolling seed)
	//However, I have not found any codes that actually make use of this nor do I fully understand how/why it may be used.
	//It may relate to codes that reference multiple addresses.  For example the 05 code structure is as follows:
	//05xxxxxx dddddddd nnnnnnnn - Copy bytes code. Copy nnnnnnnn bytes from the address 8cxxxxxx to the address dddddddd. 
	//So perhaps if both 05xxxxxx and dddddddd are encrypted, then the dword_40414C changes from decrypting 05xxxxxx would be used to properly decrypt dddddddd.
	//However, I could not find any instances of that for any dreamcast codebreaker codes I found.

	char *address_string = argv[1] ;
	unsigned int address = 0 ;

	if ( argc < 2 ) {
		printf("Usage: %s address\ne.g. %s 154C1517\n", argv[0], argv[0]) ;
		return 1 ;
	}
	if ( address_string[0] == '0' && ( address_string[1] == 'x' || address_string[1] == 'X') ) {
		address_string = address_string + 2 ;
	}

	sscanf(address_string, "%X", &address) ;
	dword_40414C = 0x06 ;

	//154C1517 should decrypt to 01162472
	printf("%08X\n", decrypt_codebreaker(address)) ; 
	return 0 ;
}


//unsure what this is used for - reversed from decompiled dccrypt.exe
unsigned int dec2_unknown(unsigned int adr) {
	unsigned int eax, ebx, ecx, edx,dl, esi ;
	ecx = adr ;
	eax = 0x543700D0 ;
	ecx = eax + ecx ;
	eax = ecx ;
	eax = eax >> 0x1D ;
	ecx = ( ecx << 0x03)&0xFFFF ;	
	eax = eax | ecx ;
	ecx = 0xa53a8888 ;
	eax = eax ^ ecx ;
	//printf("%08X %08X %08X\n", adr, eax, ecx) ;
	return eax ;
}

//unsure what this is used for - reversed from decompiled dccrypt.exe
unsigned int dec_unknown(unsigned int adr) {
	unsigned int eax, ebx, ecx, edx,dl, esi ;

	
	eax = adr ;
	eax -= 0x10000000 ;
	dl = dword_40414C ;
	ecx = eax ;
	ecx = ecx >> 0x1C ;

//push esi

	esi = eax ;

	//use +1 here because the original code pointed to the second dword of master seed list as the beginning offset
	ecx = seeds[ecx+1] ;

	if ( (dl & 1) != 0 ) {
		ecx = ecx >> 4 ;
	}

	ecx = ecx & 0x0FFFFFFF ;
	eax = eax ^ ecx ;

	if ( (dl & 2) != 0 ) {
		ecx = eax ;
		eax = eax & 0x01 ;
		ecx = ecx >> 1 ;
		ecx = ecx & 0x7FFFFFF ;
		eax = (eax<<0x1B)&0xFFFF ;
		ecx = ecx | eax ;
		eax = ecx ;
		eax = eax & 0xFF ;
		ecx = ecx >> 8 ;
		eax = (eax << 0x14 ) & 0xFFFF ;
		ecx = ecx & 0xFFFFF ;
		eax = eax | ecx ;
	}

	if ( (dl & 4) != 0 ) {
		ecx = eax ;
		eax = eax & 0x01 ;
		ecx = ecx >> 1 ;
		ecx = ecx & 0x7FFFFFF ;
		eax = (eax << 0x1B) & 0xFFFF ;
		eax = eax | ecx ;
	}

	edx = esi ;
	ecx = esi ;
	edx = edx & 0xF0000000 ;
	ecx = ecx & 0xFF00000 ;
	edx = edx + 0x10000000 ;
	eax = eax | edx ;

	if ( ecx == 0x7100000 ) {
		esi = esi & 0x0F ;
		esi = esi + 6 ;
		dword_40414C = esi ;
	}

	//printf("%08X %08X %08X %08X\n", adr, eax, ecx, dword_40414C) ;

	return eax ;

}

