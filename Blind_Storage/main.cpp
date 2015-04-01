#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdio>

#include <sha.h>
#include <osrng.h>
#include <hex.h>
#include <cmac.h>
#include "AES_RNG.h"

#include <iomanip>
#include <windows.h>

#pragma comment(lib, "cryptlib.lib")

/*
	f(x) = 12 + 16x
	f(1020) = 16332, it will let server store 1023.25MB encryption data, each file will be lesser than 16KB
	f(252) = 4044, it will let server store 255.25MB enctyption data, each file will be lesser than 4KB
	sizeof(bs_data) = 40 + BS_BLOCK_DATA_SIZE
 */
#define BS_BLOCK_DATA_SIZE 28
#define BS_BLOCK_HASH_SIZE 32
#define CIPHER_BLOCK_SIZE 16
#define BS_BLOCK_NUMBER 65536

using namespace std;
using namespace CryptoPP;

/* primitive function */
string sha256(string text); // full-domain collision resistant hash function, output size is 16 bytes
string PRF(byte *VK, int VK_len, string message); // pseudorandom function, output size is 16 bytes
inline string FD_PRF(byte *VK, int VK_len, string message); // full-domain pseudorandom function, implemented by applying PRF() to the output of sha256(), output size is 16 bytes
string PRG(byte *input_seed, int input_len, int output_len); // pseudorandom generator, output size is variable

/* action function */
unsigned short int* parse_2bytes_sequence(byte *seed, int seed_len, byte *random_data, int random_data_size); // generate a subset to index array D

/* auxiliary function */
string AES_CMAC_128(byte *user_key, int user_key_len, string plain); // input: 16 bytes key, output: 16 bytes CMAC (cipher-based message authentication code)
inline void string_to_byte(byte *b_text, string s_text, int b_text_len);  // parse a string raw data to an array
// For byte to string, we can use the string constructor, i.e. string (const char* s, size_t n);


/* primitive function */
string sha256(string text)
{
	SHA256 hash;
	//string text = "Test";
	string result;
	string encoded;

	StringSource ss1(text, true,
		new HashFilter(hash,
		new StringSink(result)
		) // HashFilter 
		); // StringSource
	//cout << "DEBUG: result.size() = " << result.size() << endl;

	StringSource ss2(result, true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource

	//cout << "Data: " << text << endl << "SHA-256 hash: " << encoded << endl;

	return result;
}

string PRF(byte *VK, int VK_len, string message)
{
	byte key[16] = { 0x00 };

	if (VK_len == 16)
	{
		//cout << "Use original key." << endl;
		memcpy(key, VK, sizeof(key));
	}
	else
	{
		//cout << "Generate a new key." << endl;
		string VK_str((char*)VK, VK_len);
		/*
		cout << "DEBUG: VK_str.size() = " << VK_str.size() << endl;
		for (int i = 0; i < VK_len; i++)
		{
		printf("DEBUG: VK_str[%d] = %X\n", i, VK_str.c_str()[i]);
		}
		*/
		string new_key = AES_CMAC_128(key, sizeof(key), VK_str);
		//cout << "DEBUG: new_key.size() = " <<new_key.size() << endl;
		string_to_byte(key, new_key, 16);

	}

	return AES_CMAC_128(key, 16, message);
}

inline string FD_PRF(byte *VK, int VK_len, string message)
{
	string hash_output = sha256(message);
	string reesult = PRF(VK, VK_len, hash_output);
	return reesult;
}

string PRG(byte *input_seed, int input_len, int output_len)
{
	string decoded;
	SecByteBlock seed(input_seed, input_len);
	//OS_GenerateRandomBlock(false, seed, seed.size());

	AES_RNG prng(seed, seed.size());

	SecByteBlock t(output_len);
	prng.GenerateBlock(t, t.size());

	string s;
	HexEncoder hex(new StringSink(s));

	hex.Put(t, t.size());
	hex.MessageEnd();

	//cout << "Random: " << s << endl;

	HexDecoder decoder;

	decoder.Put((byte*)s.data(), s.size());
	decoder.MessageEnd();

	word64 size = decoder.MaxRetrievable();
	if (size && size <= SIZE_MAX)
	{
		decoded.resize(size);
		decoder.Get((byte*)decoded.data(), decoded.size());
	}

	return decoded;
}


/* action function */
unsigned short int* parse_2bytes_sequence(byte *seed, int seed_len, byte *random_data, int random_data_size) // The number of output is (random_data_size / 2), because we parse the unsigned short integer (each integer has 2 bytes)
{
	string random = PRG(seed, seed_len, random_data_size);
	string_to_byte(random_data, random, random_data_size);
	unsigned short int *ptr_2byte = (unsigned short int*)random_data;
	return ptr_2byte;
}


/* auxiliary function */
string AES_CMAC_128(byte *user_key, int user_key_len, string plain) // user_key_len must be equal to AES::DEFAULT_KEYLENGTH
{
	//byte user_key[16] = {0x00};
	SecByteBlock key(user_key, user_key_len);

	//string plain = "CMAC Test";
	string mac, encoded;

	// Pretty print key
	encoded.clear();
	StringSource ss1(key, key.size(), true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource

	//cout << "key: " << encoded << endl;
	//cout << "plain text: " << plain << endl;

	try
	{
		CMAC< AES > cmac(key.data(), key.size());

		StringSource ss2(plain, true,
			new HashFilter(cmac,
			new StringSink(mac)
			) // HashFilter      
			); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	// Pretty print
	encoded.clear();
	StringSource ss3(mac, true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource

	//cout << "cmac: " << encoded << endl;

	return mac;
}

inline void string_to_byte(byte *b_text, string s_text, int b_text_len)
{
	memcpy((char*)b_text, s_text.c_str(), b_text_len);
}


/* The scheme of each block in array D */
struct bs_data 
{
	int size; // number of block use for a file, ONLY the first block of file has the value which is not equal to zero, the others is set to 0
	char hash[32];
	char data[BS_BLOCK_DATA_SIZE]; // each block can store 12 bytes of encryption data
	int version_number; // initial to 0
};


class bstore
{
public:
	byte key_Phi[16]; // key for PRF
	byte key_ID[16]; // key for FD_PRF

	void keygen()
	{
		for (int i = 0; i < 16; i++)
		{
			key_Phi[i] = 0x00;
			key_ID[i] = 0x00;
		}

	}

	void build(string *id, int file_number) // id is a point to a string array include a set of file name
	{
		if ((sizeof(bs_data) - sizeof(int)) % CIPHER_BLOCK_SIZE != 0) // check that data size which we want to encrypt is a multiple of CIPHER_BLOCK_SIZE
		{
			cout << "Error: the size of each block in array D is incorrect." << endl;
			system("PAUSE");
			exit(EXIT_FAILURE);
		}

		/* create an array D and initialization */
		int D_size = BS_BLOCK_NUMBER;
		bs_data *D = new bs_data[D_size];
		for (int i = 0; i < D_size; i++)
		{
			D[i].size = 0;
			memset(D[i].hash, 0, sizeof(D[i].hash));
			memset(D[i].data, 0, sizeof(D[i].data));
			D[i].version_number = 0;
		}
		/* create an array D and initialization */

		fstream src_file;// the source file object
		//char buf[BS_BLOCK_DATA_SIZE] = { 0 };	// exact equal to block size of D
		//int version = 0; // version number

		long long length; // to calculate the file size

		int block_number; // the number of blocks will for a file

		string seed; // a seed for each file with type string
		byte seed_byte[16] = { 0x00 }; // the seed with type byte

		byte *random;
		int alpha = 4;
		int random_size; // numbers of output is (random_size / 2)
		unsigned short int *random_subset;

		int output_number;

		string hash;
		int write_i = 0;
		char free[BS_BLOCK_HASH_SIZE] = { 0 }; // for checking whether D[random_subset[write_i]] is free or not

		for (int i = 0; i < file_number; i++) // process each file in file list id
		{
			src_file.open(id[i], ios::in | ios::binary);
			if (!src_file)
			{
				cerr << "Source file: " << id[i] << " open failed..." << endl << endl;
				continue;
			}

			/* Calculate file size (bytes) */
			src_file.seekg(0, ios::end);
			length = src_file.tellg(); // the size of the file
			src_file.seekg(0, ios::beg);
			cout << "Source file: " << id[i] << " is " << length << " bytes." << endl;
			/* Calculate file size (bytes) */

			/* Calculate the number of blocks in an encoding data */
			block_number = (length / BS_BLOCK_DATA_SIZE);
			if (length % BS_BLOCK_DATA_SIZE != 0)
				block_number++;
			cout << "Numbers of block will use for " << id[i] << ": " << block_number << endl;
			/* Calculate the number of blocks in an encoding data */

			/* Generate a seed by file id */
			seed = FD_PRF(key_Phi, 16, id[i]);
			string_to_byte(seed_byte, seed, 16);
			/* Generate a seed by file id */

			/* Generate a pseudorandom subset S_f with size max(alpha * size_f, kappa) which is a subset of D */
			random_size = alpha * (2 * block_number); // numbers of output is (random_size / 2)
			random = new byte[random_size];
			random_subset = parse_2bytes_sequence(seed_byte, sizeof(seed_byte), random, random_size);

			output_number = random_size / 2;
			cout << "Generate a pseudorandom subset S_f with size " << output_number << " for " << id[i] << endl;
			/*
			for (int i = 0; i < output_number; i++)
			{
				cout << "random_subset[" << i <<"] = "<< random_subset[i] << endl;
			}
			*/
			
			/* Generate a pseudorandom subset S_f with size max(alpha * size_f, kappa) which is a subset of D */

			hash = sha256(id[i]);

			write_i = 0;
			int read_count; // count the actually read byte
			while (!src_file.eof())
			{
				if (strncmp(free, D[random_subset[write_i]].hash, BS_BLOCK_HASH_SIZE) == 0) // check D[random_subset[write_i]] is free
				{
					D[random_subset[write_i]].size = block_number; // write the block number to FIRST block for each file in D
					block_number = 0; // let others block has the size value 0
					string_to_byte((byte*)&(D[random_subset[write_i]].hash), hash, BS_BLOCK_HASH_SIZE); // write hash(id) to array D
					src_file.read(D[random_subset[write_i]].data, BS_BLOCK_DATA_SIZE); // write raw data to array D
					read_count = src_file.gcount(); // the actual read byte
					if (read_count != BS_BLOCK_DATA_SIZE) // for padding the last block 
					{
						cout << "DEBUG: Read in " << read_count << " bytes" << endl;
						cout << "DEBUG: Pading " << BS_BLOCK_DATA_SIZE - read_count << " bytes in D[" << random_subset[write_i] << "]" << endl;
						
						D[random_subset[write_i]].data[read_count] = 0x80; // pad with 0x80 followed by zero bytes (OneAndZeroes Padding)
						for (int i = read_count + 1; i < BS_BLOCK_DATA_SIZE; i++)
						{
							D[random_subset[write_i]].data[i] = 0x00;
						}
					}
					//D[random_subset[write_i]].version_number = version; // write version number to array D, initiation is zero
					write_i++;
				}
				else // show collision for a file
				{
					//cout << "write_i = " << write_i << endl;
					//cout << "DEBUG: D[" << random_subset[write_i] << "] is not free" << endl;
					write_i++;
				}
			}
			//cout << "DEBUG: write_i = " << write_i << endl;
			src_file.close();
			cout << id[i] << " is already stored to array D" << endl << endl;
		}


		/* Encryption and write to sever */
		fstream enc_dest; // the destination encryption file object
		char *array_op_ptr = (char*)D; // change the pointer type to operate each byte
		string IV_str, ver_str, index_str, cipher; // initialization vector, version number, index in array D, cipher with type string
		byte cipher_byte[16]; // to store the 

		int percent = 0; // to show the encryption progress
		char enc_file_name[32] = { 0 };

		cout << "Encrypting..." << endl << "Each block in array D is " << sizeof(bs_data) << " bytes" << endl;

		for (int k = 0; k < D_size; k++) // for each block D[k]
		{
			sprintf(enc_file_name, "EncData\\D[%d].enc", k);
			ver_str = ver_str.assign((char*)(array_op_ptr + sizeof(bs_data) * k + sizeof(bs_data) - sizeof(int)), sizeof(int)); // read D[k].version_number and transform it to string
			index_str = index_str.assign((char*)&k, sizeof(k));
			IV_str = index_str + ver_str; // version number || index of D, || is concatenation

			for (int j = 0; j < sizeof(bs_data) - sizeof(int); j++)
			{
				if (j % CIPHER_BLOCK_SIZE == 0)
				{
					IV_str.replace(2, 1, 1, (j / CIPHER_BLOCK_SIZE)); // string.replace(x, 1, 1, y): replace position x with y, as a block counter
					cipher = PRF(key_Phi, sizeof(key_Phi), IV_str); // generate cipher block
					string_to_byte(cipher_byte, cipher, cipher.size());
				}
				*(array_op_ptr + sizeof(bs_data) * k + j) = *(array_op_ptr + sizeof(bs_data) * k + j) ^ cipher_byte[j % CIPHER_BLOCK_SIZE]; // Encryption of each block is carried out by XOR the contents of the block with the output of a PRE
			}

			enc_dest.open(enc_file_name, ios::out | ios::binary);
			if (!enc_dest)
				cerr << "Destination file create failed." << endl << endl;
			enc_dest.write(array_op_ptr + sizeof(bs_data) * k, sizeof(bs_data)); // write array D to the server
			enc_dest.close();

			if (k % (D_size / 100) == 0)
			{
				cout << percent << "%...";
				percent++;
			}
		}
		cout << endl;
		/* Encryption and write to sever */

		delete[](random);
		delete[](D);
	}

	void access(string  id, string dest_dec_file_name) // id is the file name you want to READ
	{
		/* Generate a seed by file id which is you want to access */
		string hash = sha256(id);
		string seed = FD_PRF(key_Phi, 16, id);
		byte seed_byte[16] = { 0x00 };
		string_to_byte(seed_byte, seed, 16);
		/* Generate a seed by file id which is you want to access */

		/* Generate a pseudorandom subset S_f_0 with size kappa which is a subset of D */
		byte *random;
		int kappa = 45;
		int random_size = 2 * kappa; // numbers of output is (random_size / 2)
		random = new byte[random_size];
		unsigned short int *random_subset = parse_2bytes_sequence(seed_byte, sizeof(seed_byte), random, random_size);
		cout << "Generate a pseudorandom subset S_f_0 with size " << kappa << " for " << id << endl;
		/* Generate a pseudorandom subset S_f_0 with size kappa which is a subset of D */
		
		bs_data dec_D[1]; // as a buffer
		int index; // index in D
		string ver_str, IV_str, index_str, cipher;
		byte cipher_byte[16];

		char read_record[BS_BLOCK_NUMBER] = { 0 }; // to deal with collision; every block must be read once for a file

		char *array_op_ptr = (char*)dec_D; // change the pointer type to operate each byte

		fstream src_enc_file, dest_dec_file;
		char src_enc_file_name[32] = { 0 };

		int padding_number = 0; // to count the padding data
		char check_flag = 0x80; // padding headder
		int block_number = 0;
		int dec_counter = 0; //to count the numbers of block which is decrypted

		/* Search file id in subset S_f_0 */
		cout << "Searching " << id << "...";
		for (int i = 0; i < kappa; i++)
		{
			cout << "...";

			sprintf(src_enc_file_name, "EncData\\D[%d].enc", random_subset[i]);
			//cout << "Open " << src_enc_file_name << endl;

			src_enc_file.open(src_enc_file_name, ios::in | ios::binary);
			if (!src_enc_file)
				cerr << "Source encryption file open failed." << endl << endl;
			src_enc_file.read(array_op_ptr, sizeof(bs_data)); // read encryption file to buffer
			src_enc_file.close();
			
			//cout << "DEBUG: Version number of block D[" << random_subset[i] << "]: " << dec_D[0].version_number << endl;

			ver_str = ver_str.assign((char*)(array_op_ptr + sizeof(bs_data) - sizeof(int)), sizeof(int)); // read D[i].version_number and transform it to string
			index = random_subset[i];
			index_str = index_str.assign((char*)&index, sizeof(index));
			IV_str = index_str + ver_str; // version number || index of D, || is concatenation

			padding_number = 0; // to count the padding data
			block_number = 0; // size_f
			check_flag = 0x80; // padding headder

			/* firsst decryption */
			for (int j = 0; j < sizeof(bs_data) - sizeof(int); j++)
			{
				if (j % CIPHER_BLOCK_SIZE == 0) // counter for each block in one D
				{
					IV_str.replace(2, 1, 1, (j / CIPHER_BLOCK_SIZE)); // string.replace(x, 1, 1, y): replace position x with y, as a block counter
					cipher = PRF(key_Phi, sizeof(key_Phi), IV_str);
					string_to_byte(cipher_byte, cipher, cipher.size());
				}
				*(array_op_ptr + j) = *(array_op_ptr + j) ^ cipher_byte[j % CIPHER_BLOCK_SIZE];

				/* count padding bytes */
				if (*(array_op_ptr + j) == check_flag) // padding data
				{
					padding_number++;
					check_flag = 0x00;
				}
				else
				{
					padding_number = 0;
					check_flag = 0x80;
				}
				/* count padding bytes */
			}
			/* first decryption */

			if (strncmp(hash.c_str(), dec_D[0].hash, BS_BLOCK_HASH_SIZE) == 0)
			{
				dec_counter++; // coute the numbers of decryption blocks actually for a file
				read_record[index] = 1; // mark that D[index] already was read
				block_number = dec_D[0].size;
				cout << "\nThis file occupies " << block_number << " block(s)" << endl;

				dest_dec_file.open(dest_dec_file_name, ios::out | ios::binary);
				if (!dest_dec_file)
					cerr << "Destination decryption file create failed." << endl << endl;
				
				if (block_number > 1)
				{
					dest_dec_file.write(array_op_ptr + sizeof(dec_D->size) + sizeof(dec_D->hash), BS_BLOCK_DATA_SIZE); // write decryption data to the destination file
					break; // remaining blocks decrypt by next stage
				}
				else if (block_number == 1)
				{
					cout << "DEBUG: This block has " << padding_number <<" bytes padding data" << endl;
					dest_dec_file.write(array_op_ptr + sizeof(dec_D->size) + sizeof(dec_D->hash), BS_BLOCK_DATA_SIZE - padding_number); // write decryption data to the destination file
					cout << "Output file: " << dest_dec_file_name << endl << endl;
					dest_dec_file.close();
					delete[](random);
					return;
				}
			}
		}
		delete[](random);

		if (block_number == 0)
		{
			cout << "\nCan not find file: " << id << endl << endl;
			return;
		}		
		/* Search file id in subset S_f_0 */

		if (block_number > 1)
		{
			/* Generate a pseudorandom subset S_f with size max(alpha * size_f, kappa) which is a subset of D */
			byte *random;
			int alpha = 4;
			random_size = alpha * (2 * block_number); // numbers of output is (random_size / 2)
			random = new byte[random_size];
			random_subset = parse_2bytes_sequence(seed_byte, sizeof(seed_byte), random, random_size);
			int output_number = random_size / 2;
			cout << "Generate a pseudorandom subset S_f with size " << output_number << " for " << id << endl;
			/* Generate a pseudorandom subset S_f with size max(alpha * size_f, kappa) which is a subset of D */

			int dec_range = block_number;
			for (int i = 1; i < dec_range; i++)
			{
				index = random_subset[i];
				if (read_record[index] == 0)
				{
					sprintf(src_enc_file_name, "EncData\\D[%d].enc", random_subset[i]);
					//cout << "Open " << src_enc_file_name << endl;

					src_enc_file.open(src_enc_file_name, ios::in | ios::binary);
					if (!src_enc_file)
						cerr << "Source encryption file open failed." << endl << endl;
					src_enc_file.read(array_op_ptr, sizeof(bs_data)); // read encryption file to buffer
					src_enc_file.close();
					//cout << "This block has version number: " << dec_D[0].version_number << endl;

					ver_str.clear();
					ver_str = ver_str.assign((char*)(array_op_ptr + sizeof(bs_data) - sizeof(int)), sizeof(int)); // read D[index].version_number and transform it to string
					index_str.clear();
					index_str = index_str.assign((char*)&index, sizeof(index));
					IV_str = index_str + ver_str; // version number || index of D, || is concatenation
					padding_number = 0;
					check_flag = 0x80; // padding headder

					/* Decryption */
					for (int j = 0; j < sizeof(bs_data) - sizeof(int); j++)
					{
						if (j % CIPHER_BLOCK_SIZE == 0) // counter for each block in one D
						{
							IV_str.replace(2, 1, 1, (j / CIPHER_BLOCK_SIZE)); // string.replace(x, 1, 1, y): replace position x with y, as a block counter
							cipher = PRF(key_Phi, sizeof(key_Phi), IV_str);
							string_to_byte(cipher_byte, cipher, cipher.size());
						}
						*(array_op_ptr + j) = *(array_op_ptr + j) ^ cipher_byte[j % CIPHER_BLOCK_SIZE];

						/* count padding bytes */
						if (*(array_op_ptr + j) == check_flag)
						{
							padding_number++;
							check_flag = 0x00;
						}
						else
						{
							padding_number = 0;
							check_flag = 0x80;
						}
						/* count padding bytes */
					}
					/* Decryption */

					if (strncmp(hash.c_str(), dec_D[0].hash, 32) == 0)
					{
						dec_counter++;
						read_record[index] = 1;
						if (dec_counter == block_number)
						{
							cout << "DEBUG: This block has " << padding_number << " bytes padding data" << endl;
							dest_dec_file.write(array_op_ptr + sizeof(dec_D->size) + sizeof(dec_D->hash), BS_BLOCK_DATA_SIZE - padding_number);
						}
						else
						{
							dest_dec_file.write(array_op_ptr + sizeof(dec_D->size) + sizeof(dec_D->hash), BS_BLOCK_DATA_SIZE);
						}
					}
					else // hash value is not matching
					{
						dec_range++;
						if (dec_range == random_size / 2)
							break;
					}
				}
				else // read_record[index] != 0, i.e., D[index] has been read ago
				{
					dec_range++;
					if (dec_range == random_size / 2)
						break;
				}
			}
			//cout << "Decryption " << dec_counter << "  blocks" << endl;
			//cout << "DEBUG: dec_range = " << dec_range << endl;
			cout << "Output file: " << dest_dec_file_name << endl << endl;
			dest_dec_file.close();
		}
	}
};


int main()
{

	LARGE_INTEGER startTime, endTime, fre;
	double times;


	bstore bstore_obj;
	string file_name[5];
	string prefix = "DEC_";
	file_name[0] = "RFC4493.txt";
	file_name[1] = "RFC4615.txt";
	file_name[2] = "Test.txt";
	file_name[4] = "WindMD5.exe";
	bstore_obj.keygen();

	QueryPerformanceFrequency(&fre); //取得CPU頻率
	QueryPerformanceCounter(&startTime); //取得開機到現在經過幾個CPU Cycle

	bstore_obj.build(file_name, 5);

	QueryPerformanceCounter(&endTime); //取得開機到程式執行完成經過幾個CPU Cycle
	times = ((double)endTime.QuadPart - (double)startTime.QuadPart) / fre.QuadPart;

	for (int i = 0; i < 5; i++)
	{
		bstore_obj.access(file_name[i], prefix + file_name[i]);
	}

	cout << fixed << setprecision(16) << "Encryption time: " << times << 's' << endl; // Show the building time

	system("PAUSE");
	return 0;
}
