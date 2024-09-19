#include <string.h>
#include <stdio.h>
#include <math.h>
#include <gmp.h>
#include "bkem.h"
#include <time.h>
clock_t setup_time, keygen_time, enc_time, trap_time, test_time, dec_time;
void setup_global_system(bkem_global_params_t *gps, const char *pstr, int N) {
    
    bkem_global_params_t params;
    params = pbc_malloc(sizeof(struct bkem_global_params_s));

    params->N = N;
    
    pairing_init_set_str(params->pairing, pstr);

    *gps = params;
}


void generateRandomArrays(int numArrays, int arrayLength, int randomArrays[Max_N][LogMax_N]) {
    srand(time(NULL));
    
    for (int i = 0; i < numArrays; i++) {
        for (int j = 0; j < arrayLength; j++) {
            randomArrays[i][j] = rand() % 2;
        }
    }
}


//  ____       _                    _    _                  _ _   _               
// / ___|  ___| |_ _   _ _ __      / \  | | __ _  ___  _ __(_) |_| |__  _ __ ___  
// \___ \ / _ \ __| | | | '_ \    / _ \ | |/ _` |/ _ \| '__| | __| '_ \| '_ ` _ \ 
//  ___) |  __/ |_| |_| | |_) |  / ___ \| | (_| | (_) | |  | | |_| | | | | | | | |
// |____/ \___|\__|\__,_| .__/  /_/   \_\_|\__, |\___/|_|  |_|\__|_| |_|_| |_| |_|
//                      |_|                |___/                                  
// 



void setup(bkem_system_t *sys, bkem_global_params_t gps) 
{
    setup_time = clock();
    
    // 
    bkem_system_t gbs;
    gbs = pbc_malloc(sizeof(struct bkem_system_s));
    gbs->PK = pbc_malloc(sizeof(struct pubkey_s));
    gbs->SEC = pbc_malloc(sizeof(struct bkem_secret_key_s));

    // ---------------------------------Choose random generator g --------------------------------------------
    element_init_G1(gbs->PK->g, gps->pairing);
    element_random(gbs->PK->g);
    

    //----------------------------------Choose another generator ghat=gg--------------------------------------
    element_init_G2(gbs->SEC->gg, gps->pairing);
    element_random(gbs->SEC->gg);
    
    // ---------------------------------Choose random generator w_1 --------------------------------------------
    element_init_G1(gbs->PK->w1, gps->pairing);
    element_random(gbs->PK->w1);
    
    // ---------------------------------Choose random generator w_2 --------------------------------------------
    element_init_G1(gbs->PK->w2, gps->pairing);
    element_random(gbs->PK->w2);
    
    // ---------------------------------Choose random generator what=ww --------------------------------------------
    element_init_G1(gbs->PK->ww, gps->pairing);
    element_random(gbs->PK->ww);

    // ---------------------------------random alpha in Zn ---------------------------------------------------
    element_t alpha;
    element_init_Zr(alpha, gps->pairing);
    element_random(alpha);

    // ---------------------------------random beta in Zn-----------------------------------------------------
    element_t beta;
    element_init_Zr(beta, gps->pairing);
    element_random(beta);

    // ---------------------------------random xhat in Zn ----------------------------------------------------
    element_t xhat;
    element_init_Zr(xhat, gps->pairing);
    element_random(xhat);
    //element_printf("size_of group element= %d in bytes\n\n", sizeof(gbs->PK->g));
    
    // ---------------------------------random yhat in Zn ----------------------------------------------------
    element_t yhat;
    element_init_Zr(yhat, gps->pairing);
    element_random(yhat);
    
     // ---------------------------------random psi in Zn ----------------------------------------------------
    element_init_Zr(gbs->SEC->psi, gps->pairing);
    element_random(gbs->SEC->psi);
  
    /*
    element_printf("alpha = %B\n", alpha);
    element_printf("beta = %B\n", beta);
    element_printf("xhat = %B\n", xhat);
    element_printf("yhat = %B\n\n", yhat);
    */	

   // -------------------------------Compute the component of MPK ---------------------------------------------
   gbs->PK->mpk_i = pbc_malloc(8 * sizeof(element_t));
   int size_of_MPK=(Max_N+LogMax_N+8) * sizeof(element_t);		// 
   //element_printf("size_of_MPK = %d in bytes\n\n", size_of_MPK);
    
   // element_printf("Compute the component of MPK\n");
	
    //-----------------------------Set the first element to g--------------------------------------------------
    element_init_G1(gbs->PK->mpk_i[0], gps->pairing);
    element_set(gbs->PK->mpk_i[0],gbs->PK->g);
    //element_printf("g = %B\n\n", gbs->PK->mpk_i[0]);
    
    
    //-------------------------------Set the first element to Omega=e(g,ghat)^{alpha.beta}--------------------------------
    element_t t1,t2,t3;   
    element_init_GT(gbs->PK->mpk_i[1], gps->pairing);
    element_init_Zr(t1, gps->pairing);
    element_mul(t1,alpha,beta);
    pairing_apply(gbs->PK->mpk_i[1], gbs->PK->g, gbs->SEC->gg,gps->pairing);
    element_pow_zn(gbs->PK->mpk_i[1], gbs->PK->mpk_i[1], t1);
    //element_printf("Omega = %B\n\n", gbs->PK->mpk_i[1]);
    
    //-------------------------------Set the first element to zeta=e(g,ghat)^{alpha.(beta-1)}--------------------------------  
    element_init_GT(gbs->PK->mpk_i[2], gps->pairing);
    element_init_Zr(t2, gps->pairing);
    element_init_Zr(t3, gps->pairing);
    element_mul(t2,alpha,beta);
    element_sub(t3,t2,alpha);
    pairing_apply(gbs->PK->mpk_i[2], gbs->PK->g, gbs->SEC->gg,gps->pairing);
    element_pow_zn(gbs->PK->mpk_i[2], gbs->PK->mpk_i[2], t3);
    //element_printf("Zeta = %B\n\n", gbs->PK->mpk_i[2]);
    
    //-------------------------------Set the first element to Xhat=(ghat)^xhat-------------------------------------
    //element_init_G2(gbs->PK->mpk_i[3], gps->pairing);
    //element_pow_zn(gbs->PK->mpk_i[3], gbs->MSK->gg, xhat);
    //element_printf("Xhat = %B\n\n", gbs->PK->mpk_i[3]);
    
    //------------------------------Set the first element to Yhat=(ghat)^yhat----------------------------------------
    //element_init_G2(gbs->PK->mpk_i[4], gps->pairing);
    //element_pow_zn(gbs->PK->mpk_i[4], gbs->MSK->gg, yhat);
    //element_printf("Yhat = %B\n\n", gbs->PK->mpk_i[4]);
    
    //---------------------------------Computes T_i and TT_i------------------------------------------------------------------
    for (int j = 0; j < LogMax_N; ++j) 
    {
	element_init_Zr(gbs->SEC->t[j], gps->pairing);
    	element_random(gbs->SEC->t[j]);
    	//element_printf("t[%d] = %B\n\n", j, gbs->MSK->t[j]);
    	element_init_G1(gbs->PK->T[j], gps->pairing);
    	element_init_G2(gbs->SEC->TT[j], gps->pairing);
    	element_pow_zn(gbs->PK->T[j], gbs->PK->g, gbs->SEC->t[j]);
    	element_pow_zn(gbs->SEC->TT[j], gbs->SEC->gg, gbs->SEC->t[j]);
  	//element_printf("T[%d] = %B\n\n", j, gbs->PK->T[j]);
     	//element_printf("TT[%d] = %B\n\n", j, gbs->SEC->TT[j]);
    }
    
    //---------------------------------Computes Z_i and ZZ_i------------------------------------------------------------------
    for (int j = 0; j < Max_N; ++j) 
    {
	element_init_Zr(gbs->SEC->z[j], gps->pairing);
    	element_random(gbs->SEC->z[j]);
    	//element_printf("z[%d] = %B\n\n", j, gbs->SEC->z[j]);
    	element_init_G1(gbs->PK->Z[j], gps->pairing);
    	element_init_G2(gbs->SEC->ZZ[j], gps->pairing);
    	element_pow_zn(gbs->PK->Z[j], gbs->PK->g, gbs->SEC->z[j]);
    	element_pow_zn(gbs->SEC->ZZ[j], gbs->SEC->gg, gbs->SEC->z[j]);
  	//element_printf("Z[%d] = %B\n\n", j, gbs->PK->Z[j]);
     	//element_printf("ZZ[%d] = %B\n\n", j, gbs->SEC->ZZ[j]);
    }
    
    
   //================================Master Secret-key==============================================================
    //element_printf("Compute the component of MSK\n");
    
    //-------------------------------Set the first element to ghat_1=(ghat)^alpha--------------------------------------
    element_init_G2(gbs->SEC->gg_1, gps->pairing);
    element_pow_zn(gbs->SEC->gg_1, gbs->SEC->gg, alpha);
    //element_printf("ghat_1 = %B\n\n", gbs->SEC->gg_1);
   
    setup_time = clock() - setup_time;
    double time_taken0 = ((double)setup_time)/CLOCKS_PER_SEC; // in seconds 
    //printf("Setup took %f seconds to execute \n\n", time_taken0);  
   
    
    //int size_of_MSK=3 * sizeof(element_t);
    //element_printf("size_of_MSK = %d in bytes\n\n", size_of_MSK);
    
    //-----------------------------Set the element PSI to g^{psi}--------------------------------------------------
    element_init_G1(gbs->PK->PSI, gps->pairing);
    element_pow_zn(gbs->PK->PSI,gbs->PK->g,gbs->SEC->psi);
    //element_printf("PSI = %B\n\n", gbs->PK->PSI);
   
  
 
//  _  __           ____                 _    _                  _ _   _               
// | |/ /___ _   _ / ___| ___ _ __      / \  | | __ _  ___  _ __(_) |_| |__  _ __ ___  
// | ' // _ \ | | | |  _ / _ \ '_ \    / _ \ | |/ _` |/ _ \| '__| | __| '_ \| '_ ` _ \ 
// | . \  __/ |_| | |_| |  __/ | | |  / ___ \| | (_| | (_) | |  | | |_| | | | | | | | |
// |_|\_\___|\__, |\____|\___|_| |_| /_/   \_\_|\__, |\___/|_|  |_|\__|_| |_|_| |_| |_|
//           |___/                              |___/                                  
//	

// -----------To Compute private keys of users--------------------------------------------------------

    keygen_time = clock();
    int user=7;
    element_t d, d1,e1;
    
    int hash_value[Max_N][LogMax_N];
    generateRandomArrays(Max_N, LogMax_N, hash_value);
    /*for (int i = 0; i < Max_N; i++) 				// For printing the hash values of each users
    {
    	printf("The hash value of %d-user: ", i);
    	for (int j = 0; j < LogMax_N; j++) {
        	printf("%d", hash_value[i][j]);
    	}
    	printf("\n");
    }*/
   
    element_t Hat_F_user;
    element_init_G2(Hat_F_user, gps->pairing);
    element_set(Hat_F_user,gbs->SEC->ZZ[user]);    		
    for(int j=0;j<LogMax_N;j++)
    {
    	if(hash_value[user][j]==1)
    	{
    		//element_printf("z[%d] = %B\n\n", j,gbs->PK->z[j]);
    		element_mul(Hat_F_user,Hat_F_user,gbs->SEC->TT[j]);
    	}    		
    }
    //element_printf("Hat_F_user = %B\n\n", Hat_F_user);
        
   
    
  //------------------------ Compute the private keys SK_j_i -----------------------------------------------------
    
    element_t r_user, Hat_F_user1,sk_1,sk_0; 
    element_init_G2(gbs->SEC->sk[user][0], gps->pairing);
    element_init_Zr(r_user, gps->pairing);
    element_random(r_user);
    element_init_G2(Hat_F_user1, gps->pairing);
    element_pow_zn(Hat_F_user1,Hat_F_user, r_user);
    element_mul(gbs->SEC->sk[user][0],gbs->SEC->gg_1, Hat_F_user1);
    //element_printf("The 1st component of secret-key d[%d][0] = %B\n\n", user, gbs->SEC->sk[user][0]);

   
    
    element_init_G2(gbs->SEC->sk[user][1], gps->pairing);
    element_pow_zn(gbs->SEC->sk[user][1],gbs->SEC->gg, r_user);
    //element_printf("The 2nd component of secret-key d[%d][1] = %B\n\n", user, gbs->SEC->sk[user][1]);
    
    element_init_Zr(gbs->SEC->x_i[user], gps->pairing);
    element_random(gbs->SEC->x_i[user]);
    //element_printf("The 3rd component of secret-key d[%d][3] = %B\n\n", user, gbs->SEC->x_i[user]);
    
/*    keygen_time = clock() - keygen_time;
    double time_taken1 = ((double)keygen_time)/CLOCKS_PER_SEC; // in seconds 
    printf("KeyGen took %f seconds to execute \n\n", time_taken1); 
*/ 

    trap_time = clock(); 
    element_t trap_temp1, trap_temp2, trap_temp3;  
    element_init_G1(trap_temp1, gps->pairing);
    element_random(trap_temp1);
    element_pow_zn(trap_temp1, trap_temp1, gbs->SEC->x_i[user]);
    element_init_G1(trap_temp2, gps->pairing);
    int broad=5;
    element_init_Zr(gbs->SEC->x_i[broad], gps->pairing);
    element_random(gbs->SEC->x_i[broad]);
    element_pow_zn(trap_temp2, gbs->PK->ww, gbs->SEC->x_i[broad]); 
    element_init_GT(trap_temp3, gps->pairing);
    pairing_apply(trap_temp3, trap_temp1, trap_temp2,gps->pairing);
    
    element_init_Zr(gbs->PK->td[user], gps->pairing);
    element_random(gbs->PK->td[user]);
   
    trap_time = clock() - trap_time; 
    double time_taken2 = ((double)trap_time)/(CLOCKS_PER_SEC); // in seconds 
    printf("Trap algorithm took %f seconds for %d-th user \n\n", time_taken2, user);
    
    
    

    *sys = gbs;
    element_clear(alpha);
    element_clear(beta);
    element_clear(xhat);
    element_clear(yhat);  
    
    //----------------------------Key Gen is done ----------------
}



//  _____                             _        _    _                  _ _   _               
// | ____|_ __   ___ _ __ _   _ _ __ | |_     / \  | | __ _  ___  _ __(_) |_| |__  _ __ ___  
// |  _| | '_ \ / __| '__| | | | '_ \| __|   / _ \ | |/ _` |/ _ \| '__| | __| '_ \| '_ ` _ \ 
// | |___| | | | (__| |  | |_| | |_) | |_   / ___ \| | (_| | (_) | |  | | |_| | | | | | | | |
// |_____|_| |_|\___|_|   \__, | .__/ \__| /_/   \_\_|\__, |\___/|_|  |_|\__|_| |_|_| |_| |_|
//                        |___/|_|                    |___/                                  
// 


//=================================Encryption =============================================

void get_enc_key( bkem_system_t gbs, bkem_global_params_t gps) 
{
     enc_time=clock();
     element_t temp1,temp2;
     element_init_Zr(gbs->SEC->s, gps->pairing);
     element_random(gbs->SEC->s);	//element_printf("C_0= %B\n\n", gbs->C_0);
     element_init_GT(gbs->M, gps->pairing);
     element_random(gbs->M);		//Assign the broadcasting message 
     //element_printf("The message which I want to broadcast= %B\n\n", gbs->M);
     element_init_GT(temp1, gps->pairing);
     element_pow_zn(temp1, gbs->PK->mpk_i[1], gbs->SEC->s);
     element_init_GT(gbs->C_0, gps->pairing);		// Initialize the 1st ciphertext component
     element_mul(gbs->C_0, gbs->M, temp1);		//Calculate the 1st ciphertext component
     //element_printf("C_0= %B\n\n", gbs->C_0);
     element_init_GT(gbs->C_1, gps->pairing);		// Initialize the 2nd ciphertext component
     element_pow_zn(gbs->C_1, gbs->PK->mpk_i[2], gbs->SEC->s);	//Calculate the 2nd ciphertext component
     //element_printf("C_1= %B\n\n", gbs->C_1);
     element_init_G1(gbs->C_2, gps->pairing);		// Initialize the 2nd ciphertext component
     element_pow_zn(gbs->C_2, gbs->PK->g, gbs->SEC->s);		//Calculate the 2nd ciphertext component
     //element_printf("C_2= %B\n\n", gbs->C_2);
     
    int hash_value[Max_N][LogMax_N];
    generateRandomArrays(Max_N, LogMax_N, hash_value);
    /*for (int i = 0; i < Subs_Num; i++) {
    	printf("The hash value of %d-user: ", i);
    	for (int j = 0; j < LogMax_N; j++) {
        	printf("%d", hash_value[i][j]);
    	}
    	printf("\n");
    }*/
  

   		
    for(int i=0;i<Subs_Num; i++)
    {
    	element_init_G1(gbs->Hat_F[i], gps->pairing);
    	element_set(gbs->Hat_F[i],gbs->PK->Z[i]);
    	for(int j=0;j<LogMax_N;j++)
    	{
    		if(hash_value[i][j]==1)
    		{
    		//element_printf("z[%d] = %B\n\n", j,gbs->PK->z[j]);
    		element_mul(gbs->Hat_F[i],gbs->Hat_F[i],gbs->PK->T[j]);
    		}    		
    	}	
    	//element_printf("Hat_F[%d] = %B\n\n", i,gbs->Hat_F[i]);
    	element_init_G1(gbs->C_3[i], gps->pairing);
    	element_pow_zn(gbs->C_3[i],gbs->Hat_F[i],gbs->SEC->s);
    	//element_printf("The 3rd component C_3[%d] = %B\n\n", i,gbs->C_3[i]);
    	
    	element_init_Zr(gbs->Q[i], gps->pairing);
    	element_random(gbs->Q[i]);
    	element_init_Zr(gbs->SEC->a_i[i], gps->pairing);
    	element_random(gbs->SEC->a_i[i]);
    	element_init_G1(gbs->B[i], gps->pairing);
    	element_pow_zn(gbs->B[i],gbs->PK->ww,gbs->SEC->a_i[i]);
    	//element_printf("The components B[%d] = %B\n\n", i,gbs->B[i]);
    }
    
    element_init_Zr(gbs->f_M, gps->pairing);
    element_random(gbs->f_M);
    element_init_Zr(gbs->f_tau, gps->pairing);
    element_random(gbs->f_tau);
    element_t temp_add,temp_pairing;
    element_init_Zr(temp_add, gps->pairing);
    element_add(temp_add,gbs->f_M,gbs->f_tau);
    element_init_G1(gbs->C_4, gps->pairing);		
    element_pow_zn(gbs->C_4, gbs->PK->PSI, temp_add);	
    //element_printf("C_4= %B\n\n", gbs->C_4);
    element_init_GT(gbs->C_5, gps->pairing);		
    element_init_GT(temp_pairing, gps->pairing);
    pairing_apply(temp_pairing, gbs->PK->g, gbs->SEC->gg,gps->pairing);
    element_pow_zn(gbs->C_5, temp_pairing, gbs->f_tau);		
    //element_printf("C_5= %B\n\n", gbs->C_5);
    
    element_init_Zr(gbs->PK->expo_h, gps->pairing);
    element_random(gbs->PK->expo_h);
    element_init_Zr(gbs->SEC->k, gps->pairing);
    element_random(gbs->SEC->k);
    
    
    element_t k_temp1;
    element_init_G1(k_temp1, gps->pairing);		
    element_pow_zn(k_temp1, gbs->PK->w1, gbs->PK->expo_h);
    element_mul(k_temp1, k_temp1, gbs->PK->w2);
    element_init_G1(gbs->K_1, gps->pairing);
    element_pow_zn(gbs->K_1, k_temp1, gbs->SEC->k);
    //element_printf("K_1= %B\n\n", gbs->K_1);
    
    enc_time = clock() - enc_time; 
    double time_taken2 = ((double)enc_time)/(CLOCKS_PER_SEC); // in seconds 
    //printf("Encryption algorithm took %f seconds to execute for %d users \n\n", time_taken2, Subs_Num); 
    
    
    
            	
}




//  ____                             _        _    _                  _ _   _               
// |  _ \  ___  ___ _ __ _   _ _ __ | |_     / \  | | __ _  ___  _ __(_) |_| |__  _ __ ___  
// | | | |/ _ \/ __| '__| | | | '_ \| __|   / _ \ | |/ _` |/ _ \| '__| | __| '_ \| '_ ` _ \ 
// | |_| |  __/ (__| |  | |_| | |_) | |_   / ___ \| | (_| | (_) | |  | | |_| | | | | | | | |
// |____/ \___|\___|_|   \__, | .__/ \__| /_/   \_\_|\__, |\___/|_|  |_|\__|_| |_|_| |_| |_|
//                       |___/|_|                    |___/                                  
// 





/*
void get_decryption_key(bkem_global_params_t gps, bkem_system_t gbs, pubkey_t PK)
 {
 	dec_time=clock();
 	int user=7;
 	//element_printf("The 1st component of secret-key d[%d][0] = %B\n\n", user, gbs->SK[user][0]);
 	//element_printf("The 1st component of secret-key d[%d][0] = %B\n\n", user, gbs->SK[user][1]);
 		
	element_t t1,t2,t3,t4,t5,t6,Guess_M;
 	element_init_GT(t1, gps->pairing);
 	element_div(t1,gbs->C_0, gbs->C_1);
 	element_init_GT(t2, gps->pairing); 	
 	pairing_apply(t2,gbs->C_3[user], gbs->SK[user][1],gps->pairing);
 	element_init_GT(t3, gps->pairing);
     	pairing_apply(t3,gbs->C_2, gbs->SK[user][0],gps->pairing);
     	element_init_GT(t4, gps->pairing);
     	element_div(t4, t2, t3);
     	element_init_GT(Guess_M, gps->pairing); 	
 	element_mul(Guess_M,t1, t4); 
 		
 	dec_time = clock() - dec_time; 
   	double time_taken3 = ((double)dec_time)/(CLOCKS_PER_SEC); // in seconds 
  	//printf("Decryption algorithm took %f seconds to execute for a subscribed user\n\n", time_taken3);
  	
  	//element_printf("The plaintext is %B\n\n",gbs->M);
 	//element_printf("The recover message is %B\n\n",Guess_M); 
 
}

*/

