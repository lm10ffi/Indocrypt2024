/**
 * @file BKEM.h
 * @brief General construction of the Boneh-Gentry-Waters 
 * broadcast key encapsulation scheme 
 *
 * BKEM is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * BKEM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with BKEM.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * Oliver Guenther
 * mail@oliverguenther.de
 *
 * 
 * BKEM.h
*/

#ifndef H_BKEM
#define H_BKEM

#include <string.h>
#include <pbc/pbc.h>

/**
  @typedef Global broadcast system parameters
 */
 
//#define MAX_m  16            // Max channels
//#define MAX_n  64            // Max subscriber
//#define MAX_SET MAX_n        // Here, Sets are  Users in Channel Sj
#define Max_N 2048		// Total Number of users	
#define LogMax_N 11		// Length of identity string or l= Log Max_n (base 2)
#define Subs_Num 512

 
typedef struct bkem_global_params_s {
	pairing_t pairing;
	int N;
	
}* bkem_global_params_t;

/**
 * @typedef Public Key
 * Contains generator g, 2B-2 elements g[i] and A elements v[i]
 */
typedef struct pubkey_s {
    element_t g; 		// 1st generator: g
    element_t w1; 		// 1st generator: w1
    element_t w2; 		// 1st generator: w2
    element_t ww; 		// another generator: what
    element_t *mpk_i;		// Another component for master public-key
    element_t T[LogMax_N]; 	// l=log N elements
    element_t Z[Max_N]; 	// N elements 
    element_t pk_user; 		// public key of each user pk_i
    element_t PSI;		// the element 'PSI' for AddSetup 
    element_t expo_h;
    
    element_t td[Max_N];
    
    
    
        
}* pubkey_t;

/**
* Variable for Secret key 
*/

typedef struct bkem_secret_key_s 
{
	/** Private key of user s */
	element_t gg; 		// another generator: ghat
	element_t gg_1; 	// another element: ghat^alpha
	element_t t[LogMax_N];	// l=log N elements for computing T_i
	element_t z[Max_N];	// N elements for computing Z_i
	element_t TT[LogMax_N]; // l=log N elements
	element_t ZZ[Max_N]; 	// N elements
	element_t x_i[Max_N];	 	// x_i for computing public key pk_i of each user
	element_t psi;		// the element 'psi' for AddSetup 
	element_t x_broad;
	element_t s;
	element_t tau;
	element_t k;
	element_t eta;
	element_t a_i[Max_N];
	
	
	element_t sk[Max_N][2];	//Secret key components of the user
	
}* bkem_secret_key_t;

/***
*
*
*/	
typedef struct
{
    int useri,channelj;  // User user_i  subscribe to chanel channel_j
} ID;


/**
 * @typedef broadcast system instance
 */
typedef struct bkem_system_s {
	pubkey_t PK;
	bkem_secret_key_t SEC;
	element_t M;
	element_t Hat_F[Max_N];
	element_t h[Max_N];
	element_t C_0;
	element_t C_1;
	element_t C_2;
	element_t C_3[Max_N];
	element_t hash_value[Max_N][LogMax_N];
	element_t C_4;
	element_t C_5;
	element_t Q[Max_N];
	element_t f_M;
	element_t f_tau;
	element_t B[Max_N];
	element_t K_1;	
	

}* bkem_system_t;


/**
 * @typedef Keypair (HDR, K) [A+1, 1] elements
 */


typedef struct header_s 
{
    element_t C_00;
  /*  element_t C_1_x[MAX_m];
    element_t C_2_x[MAX_m];
    element_t theta_x[MAX_m];
    element_t Gamma_x[MAX_m];
 */   
}* header_t;


typedef struct kpair_s {
    element_t *HR;
}* kpair_t;

typedef struct keypair_s {
    element_t *HDR;
    element_t K;
}* keypair_t;



/**
 * @brief Free a keypair_t
 */
void free_pubkey(pubkey_t pk, bkem_global_params_t gbs);


/**
 * @brief Free a bkem_system_t
 */
void free_bkem_system(bkem_system_t sys, bkem_global_params_t gbs);


/**
 * @brief Free a global_broadcast_params_t
 */
void free_global_params(bkem_global_params_t gbs);



/**
 * Setup global broadcast system parameters
 * @param[out] gps bkem_global_params_t pointer
 * @param[in] params Pairing Type paramters as string
 * @param[in] n number of users in the system
 */
void setup_global_system(bkem_global_params_t *gps, const char *params, int n);


/**
 * Setup broadcast key encapsulation system
 * @param[out] sys bkem_system_t pointer
 * @param[in] gps bkem_global_params_t pointer
 */
 
void setup(bkem_system_t *sys, bkem_global_params_t gps);


/**
 * Output encryption Keypair
 * @param[out] keypair pointer to encryption pair output
 * @param[in] S receiver array [indices of participating users]
 * @param[in] num_recip Number of elements in S
 * @param[in] sys Broadcast encryption parameters
 */
 
 
//void get_encryption_key(keypair_t *key, int *S, int num_recip, bkem_system_t sys, bkem_global_params_t gps);
//void grouptoken(keypair_t *key, int *S, int num_recip, bkem_system_t sys, bkem_global_params_t gps);

void get_enc_key(bkem_system_t sys, bkem_global_params_t gps);




/**
 * Output decryption Key
 * @param[out] K decryption key pointer
 * @param[in] gps global system parameters
 * @param[in] S receivers [indices of participating users]
 * @param[in] num_recip Number of elements in S
 * @param[in] i index of user
 * @param[in] d_i private key of user i
 * @param[in] HDR header
 * @param[in] PK public key
 */
 
 
void get_decryption_key(bkem_global_params_t gbs, bkem_system_t sys, pubkey_t PK);


#endif
