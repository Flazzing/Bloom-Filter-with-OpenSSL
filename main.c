#include <stdio.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

// ./enc -d dictionanry.txt -i sample_input2.txt
// ./enc -d dictionary.txt -i sample_input.txt

char *HexToBin(char *hexdec);
int binaryToDecimal(char *n);
int charHexToint(char *x, int max);
void  SetBit( int A[],  int k );
int GetBit( int A[], int k );

int main(int argc, char *argv[])
{
	const long bloom_max = 4070813;

	const int read_max_dec = 20;
	// file section variable
	int opt;
	int dictionary_opt = 0;
	int input_opt = 0;
	char buf[999], buf2[999];
	FILE *dictionary = NULL;
	char *filename;
	char *filename2;
	FILE *input_file = NULL;

	FILE *output3 = fopen("output3.txt", "w");
	FILE *output5 = fopen("output5.txt", "w");

	FILE *seq = fopen("seq.txt", "w");
	FILE *seq2 = fopen("seq2.txt", "w");
	
	long i = 0;
	long x = 0;
	int totalLine = 0;
	

	// variables to start filter bloom
	char sha1_data[SHA_DIGEST_LENGTH * 2];
	char sha2_data[SHA256_DIGEST_LENGTH * 2];
	char sha3_data[SHA384_DIGEST_LENGTH * 2];
	char sha5_data[SHA512_DIGEST_LENGTH * 2];
	char sha224_data[SHA224_DIGEST_LENGTH * 2];

	unsigned char sha1_hash[SHA_DIGEST_LENGTH];
	unsigned char sha2_hash[SHA256_DIGEST_LENGTH];
	unsigned char sha3_hash[SHA384_DIGEST_LENGTH];
	unsigned char sha5_hash[SHA512_DIGEST_LENGTH];

	unsigned char sha224_hash[SHA224_DIGEST_LENGTH];

	// alternative to implement sha
	SHA_CTX ctx;
	SHA256_CTX ctx2;

	// file write hash
	FILE *three_way_hash_file = fopen("3_way.txt", "w");
	FILE *five_way_hash_file = fopen("5_way.txt", "w");

	// file read hash
	FILE *three_way_hash_file_r = fopen("3_way.txt", "r");
	FILE *five_way_hash_file_r = fopen("5_way.txt", "r");

	printf("sha1: %d\n", SHA_DIGEST_LENGTH);
	printf("sha2: %d\n", SHA256_DIGEST_LENGTH);
	printf("sha3: %d\n", SHA384_DIGEST_LENGTH);
	printf("\n\n");

	int bloom1[999999];
	int bloom2[999999];

	for (i = 0; i < 999999; i++){
		bloom1[i] = 0;
		bloom2[i] = 0;
	}
      

	while ((opt = getopt(argc, argv, "d:i:o:")) != -1)
	{
		switch (opt)
		{
		case 'd':
			filename = optarg;
			dictionary = fopen(filename, "r");
			if (dictionary == NULL)
			{
				printf("dictionary file is error when reading. \n");
				return 1;
			}

			dictionary_opt = 1;
			break;

		case 'i':
			filename2 = optarg;
			input_file = fopen(filename2, "r");
			if (input_file == NULL)
			{
				printf("input file is error when reading. \n");
				return 1;
			}

			input_opt = 1;
			break;
		}
	}

	// https://stackoverflow.com/questions/9284420/how-to-use-sha1-hashing-in-c-programming
	// https://stackoverflow.com/questions/918676/generate-sha-hash-in-c-using-openssl-library

	printf("encryption begins\n");
	if (dictionary_opt == 1)
	{
		printf("This is the dictionary\n");
		while (fgets(buf, sizeof(buf), dictionary) != NULL)
		{
			buf[strlen(buf) - 1] = '\0';
		
			memset(sha1_data, 0x0, SHA_DIGEST_LENGTH * 2);
			memset(sha1_hash, 0x0, SHA_DIGEST_LENGTH);
			memset(sha2_data, 0x0, SHA256_DIGEST_LENGTH * 2);
			memset(sha2_hash, 0x0, SHA256_DIGEST_LENGTH);
			memset(sha3_data, 0x0, SHA384_DIGEST_LENGTH * 2);
			memset(sha3_hash, 0x0, SHA384_DIGEST_LENGTH);

			// encrypt sha3, sha2, sha1 3 way function

			SHA384(buf, strlen(buf), sha3_hash);
			for (i = 0; i < SHA384_DIGEST_LENGTH; i++)
			{
				sprintf((char *)&(sha3_data[i * 2]), "%02x", sha3_hash[i]);
			}

			printf("\n-----------------------------------------------------------------------------------\n");
			printf("this section is hash 3 bloom allocator and encryption");
			printf("\n-----------------------------------------------------------------------------------\n");
			printf("String is %s\n", buf);

			char temp[SHA384_DIGEST_LENGTH];
			strcpy(temp, sha3_data);   
			temp[6] = '\0'; //truncate to 20 bits for hex
			char *hex3 = HexToBin(temp);
			int x = binaryToDecimal(hex3);		
			//bloom1[ (x % bloom_max) ] = 1;
			SetBit(bloom1, (x % bloom_max));
	
			printf("384. temp %s \n", temp);
			printf("384. binary is %s \t dec is %d\n", hex3, x);
			printf("384. %d modulus by %d is %d. (note: set by 1)\n", x, bloom_max, (x % bloom_max));

			// sha 2 to bloom filter

			SHA256_Init(&ctx2);
			SHA256_Update(&ctx2, sha3_hash, strlen(sha3_hash));
			SHA256_Final(sha2_hash, &ctx2);

			for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
			{
				sprintf((char *)&(sha2_data[i * 2]), "%02x", sha2_hash[i]);
			}	
			temp[0] = '\0';
			strcpy(temp, sha2_data);  
			temp[6] = '\0'; //truncate to 20 bits for hex
			char *hex2 = HexToBin(temp);
			x = binaryToDecimal(hex2);
			//bloom1[ (x % bloom_max) ] = 1;
			SetBit(bloom1, (x % bloom_max));

			printf("256. temp %s \n", temp);
			printf("256. binary is %s \t dec is %d\n", hex2, x);
			printf("256. %d modulus by %d is %d. (note: set by 1)\n", x, bloom_max, (x % bloom_max));


			SHA1(sha2_hash, strlen(sha2_hash), sha1_hash);
			for (i = 0; i < SHA_DIGEST_LENGTH; i++)
			{
				sprintf((char *)&(sha1_data[i * 2]), "%02x", sha1_hash[i]);
			}

			temp[0] = '\0';
			strcpy(temp, sha1_data);  
			temp[6] = '\0'; //truncate to 20 bits for hex
			char *hex1 = HexToBin(temp);
			x = binaryToDecimal(hex1 );
			
			SetBit(bloom1, (x % bloom_max));
			//bloom1[ (x % bloom_max) ] = 1;

			
			printf("128. temp %s \n", temp);
			printf("128. binary is %s \t dec is %d\n", hex1, x);
			printf("128. %d modulus by %d is %d. (note: set by 1)\n", x, bloom_max, (x % bloom_max));
			
			printf("\n");
			totalLine++;


			printf("\n-----------------------------------------------------------------------------------\n");
			printf("this section is hash 5 bloom allocator and encryption");
			printf("\n-----------------------------------------------------------------------------------\n");
			printf("String is %s \n", buf);


			memset(sha1_data, 0x0, SHA_DIGEST_LENGTH * 2);
			memset(sha1_hash, 0x0, SHA_DIGEST_LENGTH);
			memset(sha2_data, 0x0, SHA256_DIGEST_LENGTH * 2);
			memset(sha2_hash, 0x0, SHA256_DIGEST_LENGTH);
			memset(sha224_data, 0x0, SHA224_DIGEST_LENGTH * 2);
			memset(sha224_hash, 0x0, SHA224_DIGEST_LENGTH);
			memset(sha3_data, 0x0, SHA384_DIGEST_LENGTH * 2);
			memset(sha3_hash, 0x0, SHA384_DIGEST_LENGTH);
			memset(sha5_data, 0x0, SHA512_DIGEST_LENGTH * 2);
			memset(sha5_hash, 0x0, SHA512_DIGEST_LENGTH);

			// encrypt sha3, sha2, sha1 3 way function
			SHA512(buf, strlen(buf), sha5_hash);
			for (i = 0; i < SHA512_DIGEST_LENGTH; i++)
			{
				sprintf((char *)&(sha5_data[i * 2]), "%02x", sha5_hash[i]);
			}

			char temp_five[SHA512_DIGEST_LENGTH];
			strcpy(temp_five, sha5_data);   
			temp_five[6] = '\0'; //truncate to 20 bits for hex
			char *hex5_five = HexToBin(temp_five);
			x = binaryToDecimal(hex5_five);		
			// bloom2[ (x % bloom_max) ] = 1;
			SetBit(bloom2, (x % bloom_max));

			printf("512. temp %s \n", temp_five);
			printf("512. binary is %s \t dec is %d\n", hex5_five, x);
			printf("512. %d modulus by %d is %d. (note: set by 1)\n", x, bloom_max, (x % bloom_max));
			
			SHA384(sha5_hash, strlen(sha5_hash), sha3_hash);
			for (i = 0; i < SHA384_DIGEST_LENGTH; i++)
			{
				sprintf((char *)&(sha3_data[i * 2]), "%02x", sha3_hash[i]);
			}

			char temp_three[SHA384_DIGEST_LENGTH];
			strcpy(temp_three, sha3_data);   
			temp_three[6] = '\0'; //truncate to 20 bits for hex
			char *hex5_three = HexToBin(temp_three);
			x = binaryToDecimal(hex5_three);		
			//bloom2[ (x % bloom_max) ] = 1;
			SetBit(bloom2, (x % bloom_max));

			printf("384. temp %s \n", temp_three);
			printf("384. binary is %s \t dec is %d\n", hex5_three, x);
			printf("384. %d modulus by %d is %d. (note: set by 1)\n", x, bloom_max, (x % bloom_max));


			SHA256(sha3_hash, strlen(sha3_hash), sha2_hash);
			for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
			{
				sprintf((char *)&(sha2_data[i * 2]), "%02x", sha2_hash[i]);
			}
			
			char temp_256[SHA256_DIGEST_LENGTH];
			strcpy(temp_256, sha2_data);   
			temp_256[6] = '\0'; //truncate to 20 bits for hex
			char *hex5_256 = HexToBin(temp_256);
			x = binaryToDecimal(hex5_256);		
			//bloom2[ (x % bloom_max) ] = 1;
			SetBit(bloom2, (x % bloom_max));

			printf("256. temp %s \n", temp_256);
			printf("256. binary is %s \t dec is %d\n", hex5_256, x);
			printf("256. %d modulus by %d is %d. (note: set by 1)\n", x, bloom_max, (x % bloom_max));


			SHA224(sha2_hash, strlen(sha2_hash), sha224_hash);
			for (i = 0; i < SHA224_DIGEST_LENGTH; i++)
			{
				sprintf((char *)&(sha224_data[i * 2]), "%02x", sha224_hash[i]);
			}

			char temp_224[SHA256_DIGEST_LENGTH];
			strcpy(temp_224, sha224_data);   
			temp_224[6] = '\0'; //truncate to 20 bits for hex
			char *hex5_224= HexToBin(temp_224);
			x = binaryToDecimal(hex5_224);		
			// bloom2[ (x % bloom_max) ] = 1;
			SetBit(bloom2, (x % bloom_max));
	
			printf("224. temp %s \n", temp_224);
			printf("224. binary is %s \t dec is %d\n", hex5_224, x);
			printf("224. %d modulus by %d is %d. (note: set by 1)\n", x, bloom_max, (x % bloom_max));


			SHA1(sha224_hash, strlen(sha224_hash), sha1_hash);
			for (i = 0; i < SHA_DIGEST_LENGTH; i++)
			{
				sprintf((char *)&(sha1_data[i * 2]), "%02x", sha1_hash[i]);
			}

			char temp_1[SHA_DIGEST_LENGTH];
			strcpy(temp_1, sha1_data);   
			temp_1[6] = '\0'; //truncate to 20 bits for hex
			char *hex5_1= HexToBin(temp_1);
			x = binaryToDecimal(hex5_1);		
			// bloom2[ (x % bloom_max) ] = 1;
			SetBit(bloom2, (x % bloom_max));

			printf("1. temp %s \n", temp_1);
			printf("1. binary is %s \t dec is %d\n", hex5_1, x);
			printf("1. %d modulus by %d is %d. (note: set by 1)\n", x, bloom_max, (x % bloom_max));

			buf[0] = '\0';

		} // finish reading dictionary

		fclose(three_way_hash_file);
		fclose(five_way_hash_file);

	} // end of dictionary_opt == 1


	long bloom_checker = 0;
	// fgets(buf2, sizeof(buf2), input_file); remove because it skips first line 
	while (fgets(buf2, sizeof(buf2), input_file) != NULL)
	{
		bloom_checker = 0;
		printf("\n-----------------------------------------------------------------------------------\n");
		printf("this section is hash 3 bloom checker");
		printf("\n-----------------------------------------------------------------------------------\n");

		printf("String is %s\n", buf2);

		memset(sha1_data, 0x0, SHA_DIGEST_LENGTH * 2);
		memset(sha1_hash, 0x0, SHA_DIGEST_LENGTH);
		memset(sha2_data, 0x0, SHA256_DIGEST_LENGTH * 2);
		memset(sha2_hash, 0x0, SHA256_DIGEST_LENGTH);
		memset(sha3_data, 0x0, SHA384_DIGEST_LENGTH * 2);
		memset(sha3_hash, 0x0, SHA384_DIGEST_LENGTH);

		buf2[strlen(buf2) - 1] = '\0';

		SHA384(buf2, strlen(buf2), sha3_hash);
		for (i = 0; i < SHA384_DIGEST_LENGTH; i++)
		{
			sprintf((char *)&(sha3_data[i * 2]), "%02x", sha3_hash[i]);
		}

		char temp[SHA384_DIGEST_LENGTH];
		strcpy(temp, sha3_data);   
		temp[6] = '\0'; //truncate to 20 bits for hex
		char *hex3 = HexToBin(temp);
		int x = binaryToDecimal(hex3);	

		//if (bloom1[ (x % bloom_max) ] == 1) {
		//	bloom_checker++;
		//}

		if (GetBit(bloom1, (x % bloom_max) ) == 1) {
			bloom_checker++;
		}

			
		printf("384. temp %s \n", temp);
		printf("384. binary is %s\t dec is %d\n", hex3, x);
		printf("384. %d modulus by %d is %d. (note: set by 1)\n", x, bloom_max, (x % bloom_max));


		SHA256_Init(&ctx2);
		SHA256_Update(&ctx2, sha3_hash, strlen(sha3_hash));
		SHA256_Final(sha2_hash, &ctx2);
		for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		{
			sprintf((char *)&(sha2_data[i * 2]), "%02x", sha2_hash[i]);
		}

		temp[0] = '\0';
		strcpy(temp, sha2_data);  
		temp[6] = '\0'; //truncate to 20 bits for hex
		char *hex2 = HexToBin(temp);
		x = binaryToDecimal(hex2);

		//if (bloom1[ (x % bloom_max) ] == 1) {
		//	bloom_checker++;
		//}

		if (GetBit(bloom1, (x % bloom_max) ) == 1) {
			bloom_checker++;
		}



		printf("256. temp %s \n", temp);
		printf("256. binary is %s \t dec is %d\n", hex2, x);
		printf("256. %d modulus by %d is %d. (note: set by 1)\n", x, bloom_max, (x % bloom_max));


		
		SHA1(sha2_hash, strlen(sha2_hash), sha1_hash);
		for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		{
			sprintf((char *)&(sha1_data[i * 2]), "%02x", sha1_hash[i]);
		}
		temp[0] = '\0';
		strcpy(temp, sha1_data);  
		temp[6] = '\0'; //truncate to 20 bits for hex
		char *hex1 = HexToBin(temp);
		x = binaryToDecimal(hex1 );
		//if (bloom1[ (x % bloom_max) ] == 1) {
		//	bloom_checker++;
		//}
		
		if (GetBit(bloom1, (x % bloom_max) ) == 1) {
			bloom_checker++;
		}


	
		printf("128. temp %s \n", temp);
		printf("128. binary is %s \t dec is %d\n", hex1, x);
		printf("128. %d modulus by %d is %d. (note: set by 1)\n", x, bloom_max, (x % bloom_max));

		if (bloom_checker == 3){
			fprintf(output3, "maybe \n");
			printf("------------ Maybe  ---------\n");
		}else {
			fprintf(output3, "no \n");
			printf("------------ No  ---------\n");
		}
		bloom_checker = 0;


		printf("\n-----------------------------------------------------------------------------------\n");
		printf("this section is hash 5 bloom checker");
		printf("\n-----------------------------------------------------------------------------------\n");

		memset(sha1_data, 0x0, SHA_DIGEST_LENGTH * 2);
		memset(sha1_data, 0x0, SHA_DIGEST_LENGTH*2);
    		memset(sha1_hash, 0x0, SHA_DIGEST_LENGTH);
		memset(sha2_data, 0x0, SHA256_DIGEST_LENGTH*2);
    		memset(sha2_hash, 0x0, SHA256_DIGEST_LENGTH);
		memset(sha224_data, 0x0, SHA224_DIGEST_LENGTH*2);
    		memset(sha224_hash, 0x0, SHA224_DIGEST_LENGTH);
		memset(sha3_data, 0x0, SHA384_DIGEST_LENGTH*2);
    		memset(sha3_hash, 0x0, SHA384_DIGEST_LENGTH);
		memset(sha5_data, 0x0, SHA512_DIGEST_LENGTH*2);
    		memset(sha5_hash, 0x0, SHA512_DIGEST_LENGTH);
		
		
		printf("String is %s\n", buf2);
		// encrypt sha3, sha2, sha1 3 way function
		SHA512(buf2, strlen(buf2), sha5_hash);
		for (i = 0; i < SHA512_DIGEST_LENGTH; i++)
		{
			sprintf((char *)&(sha5_data[i * 2]), "%02x", sha5_hash[i]);
		}

		temp[0] = '\0';
		strcpy(temp, sha5_data);  
		temp[6] = '\0'; //truncate to 20 bits for hex
		char *hex5_512 = HexToBin(temp);
		x = binaryToDecimal(hex5_512);
		//if (bloom2 [(x % bloom_max) ] == 1) {
		//	bloom_checker++;
		//}

		if (GetBit(bloom2, (x % bloom_max) ) == 1) {
			bloom_checker++;
		}

		printf("512. temp %s \n", temp);
		printf("512. binary is %s \t dec is %d\n", hex5_512, x);
		printf("512. %d modulus by %d is %d. (note: set by 1)\n", x, bloom_max, (x % bloom_max));



		SHA384(sha5_hash, strlen(sha5_hash), sha3_hash);
		for (i = 0; i < SHA384_DIGEST_LENGTH; i++)
		{
			sprintf((char *)&(sha3_data[i * 2]), "%02x", sha3_hash[i]);
		}
		temp[0] = '\0';
		strcpy(temp, sha3_data);  
		temp[6] = '\0'; //truncate to 20 bits for hex
		char *hex5_384 = HexToBin(temp);
		x = binaryToDecimal(hex5_384 );
		//if (bloom2[ (x % bloom_max) ] == 1) {
		//	bloom_checker++;
		//}

		if (GetBit(bloom2, (x % bloom_max) ) == 1) {
			bloom_checker++;
		}

		printf("384. temp %s \n", temp);
		printf("384. binary is %s \t dec is %d\n", hex5_384, x);
		printf("384. %d modulus by %d is %d. (note: set by 1)\n", x, bloom_max, (x % bloom_max));




		SHA256(sha3_hash, strlen(sha3_hash), sha2_hash);
		for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		{
			sprintf((char *)&(sha2_data[i * 2]), "%02x", sha2_hash[i]);
		}
		temp[0] = '\0';
		strcpy(temp, sha5_data);  
		temp[6] = '\0'; //truncate to 20 bits for hex
		char *hex5_256 = HexToBin(temp);
		x = binaryToDecimal(hex5_256 );
		// if (bloom2[ (x % bloom_max) ] == 1) {
		//	bloom_checker++;
		//}

		if (GetBit(bloom2, (x % bloom_max) ) == 1) {
			bloom_checker++;
		}

		printf("256. temp %s \n", temp);
		printf("256. binary is %s \t dec is %d\n", hex5_256, x);
		printf("256. %d modulus by %d is %d. (note: set by 1)\n", x, bloom_max, (x % bloom_max));



		SHA224(sha2_hash, strlen(sha2_hash), sha224_hash);
		for (i = 0; i < SHA224_DIGEST_LENGTH; i++)
		{
			sprintf((char *)&(sha224_data[i * 2]), "%02x", sha224_hash[i]);
		}
		temp[0] = '\0';
		strcpy(temp, sha224_data);  
		temp[6] = '\0'; //truncate to 20 bits for hex
		char *hex5_224= HexToBin(temp);
		x = binaryToDecimal(hex5_224);
		//if (bloom2[ (x % bloom_max) ] == 1) {
		//	bloom_checker++;
		//}
		if (GetBit(bloom2, (x % bloom_max) ) == 1) {
			bloom_checker++;
		}


		printf("224. temp %s \n", temp);
		printf("224. binary is %s \t dec is %d\n", hex5_224, x);
		printf("224. %d modulus by %d is %d. (note: set by 1)\n", x, bloom_max, (x % bloom_max));



		SHA1(sha224_hash, strlen(sha224_hash), sha1_hash);
		for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		{
			sprintf((char *)&(sha1_data[i * 2]), "%02x", sha1_hash[i]);
		}
		temp[0] = '\0';
		strcpy(temp, sha1_data);  
		temp[6] = '\0'; //truncate to 20 bits for hex
		char *hex5_1= HexToBin(temp);
		x = binaryToDecimal(hex5_1);
		//if (bloom2[ (x % bloom_max) ] == 1) {
		//	bloom_checker++;
		//}

		if (GetBit(bloom2, (x % bloom_max) ) == 1) {
			bloom_checker++;
		}

		printf("1. temp %s \n", temp);
		printf("1. binary is %s \t dec is %d\n", hex5_1, x);
		printf("1. %d modulus by %d is %d. (note: set by 1)\n", x, bloom_max, (x % bloom_max));

		if (bloom_checker == 5){
			fprintf(output5, "maybe \n");
			printf("------------ Maybe  ---------\n");
		}else {
			fprintf(output5, "no \n");
			printf("------------ No  ---------\n");
		}

		bloom_checker = 0;
	}

	

	printf("Total line %d \n", totalLine);

	fclose(input_file);
	fclose(seq);
	fclose(seq2);
	fclose(output3);
	fclose(output5);
	fclose(dictionary);

	//  fclose(output);

	return 0;
}

char *HexToBin(char *hexdec)
{
	long int i = 0;
	char *bin = malloc(sizeof(char) * 9999999);
	while (hexdec[i])
	{
		switch (hexdec[i])
		{
		case '0':
			strcat(bin, "0000");
			break;
		case '1':
			strcat(bin, "0001");
			break;
		case '2':
			strcat(bin, "0010");
			break;
		case '3':
			strcat(bin, "0011");
			break;
		case '4':
			strcat(bin, "0100");
			break;
		case '5':
			strcat(bin, "0101");
			break;
		case '6':
			strcat(bin, "0110");
			break;
		case '7':
			strcat(bin, "0111");
			break;
		case '8':
			strcat(bin, "1000");
			break;
		case '9':
			strcat(bin, "1001");
			break;
		case 'A':
		case 'a':
			strcat(bin, "1010");
			break;
		case 'B':
		case 'b':
			strcat(bin, "1011");
			break;
		case 'C':
		case 'c':
			strcat(bin, "1100");
			break;
		case 'D':
		case 'd':
			strcat(bin, "1101");
			break;
		case 'E':
		case 'e':
			strcat(bin, "1110");
			break;
		case 'F':
		case 'f':
			strcat(bin, "1111");
			break;
		}

		i++;
	}
	bin[i * 4] = '\0';
	return bin;
}

int binaryToDecimal(char *n)
{
    int dec_value = 0;
 
    // Initializing base value to 1, i.e 2^0
    int base = 1;
 
    int len = strlen(n);
    int i = 0;
    for (i = len - 1; i >= 0; i--) {
        if (n[i] == '1')
            dec_value += base;
        base = base * 2;
    }
 
    return dec_value;
}

void  SetBit( int A[],  int k )
{
    A[k/32] |= 1 << (k%32);  // Set the bit at the k-th position in A[i]
}

int GetBit( int A[], int k ) 
{
     return ( (A[k/32] & (1 << (k%32) )) != 0 );  // Get the bit at the k-th position in A[i]
} 
