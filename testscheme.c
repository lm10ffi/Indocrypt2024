#include "bkem.h"
#include <time.h>
clock_t t,t1,t0,t2,t4,t44; 
     
int main(int argc, const char *argv[]) {

	FILE *param = fopen("a.param", "r");
	char buf[4096];
	fread(buf, 1, 4096, param);
    
    		//printf("\nSystem setup Key\n\n");

	bkem_global_params_t gps;
	setup_global_system(&gps, (const char*) buf, (argc > 1) ? atoi(argv[1]) : 2048);

		printf("Global System parameters: N = %d\n\n", gps->N);

		bkem_system_t sys;
	
		setup(&sys, gps);

		get_enc_key(sys,gps);
        	
          	//get_decryption_key(gps, sys, sys->PK);
          	     
        

    }
    
