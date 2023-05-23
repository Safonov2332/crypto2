/*
 * main.cpp
 *
 *  Created on: 23 мая 2023 г.
 *      Author: Evgeniy
 */



#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <cerrno>
#include <stdexcept>
#include <functional>
#include <random>
#include <vector>
#include <algorithm>


#include <cassert>
#include <utility>
#include <string_view>
#include <vector>

#include <libgen.h>

#pragma pack(push,1)
struct CryptoContainerHeader
{
	uint64_t orig_size;
	uint32_t orig_name_leght;
	uint32_t block_size;
};

#pragma pack(pop)

const size_t SOME_TEST_ROUNDS = 9;
const size_t SOME_TEST_KEY_SIZE = SOME_TEST_ROUNDS * 4;

uint32_t some_test_crypro_func(uint32_t a, const uint8_t *k)
{
	const uint32_t *kk = reinterpret_cast<const uint32_t*>(k);
	return ((a+1) ^ (*kk)) +1;
}

using CryptoFunc64 = std::function<uint32_t(uint32_t, const uint8_t*)>;

void feistel_crypt64(const char * input,
		char * output,
		size_t rounds,
		size_t key_size,
		const uint8_t * key,
		bool encrypt,
		CryptoFunc64 func)
{
	struct Block { uint32_t right, left;};
	const Block * orig_block = reinterpret_cast<const Block*>(input);
	uint32_t right= orig_block->right;
	uint32_t left= orig_block->left;
	uint32_t t;
	size_t key_element_size = key_size / rounds;
	const uint8_t * key_first = key;
	int key_offset = key_element_size;
	if (not encrypt){
		key_offset = -key_offset;
		key_first = key + key_element_size * (rounds -1);
	}

	for(size_t r=0; r<rounds; r++)
	{
		t = right;
		right = left ^ func(t, key_first);
		left = t;
		key_first += key_offset;
	}

	Block * out_block = reinterpret_cast<Block*>(output);
	out_block->right = left;
	out_block->left = right;
}

void encrypt_file(const char * filename_in, const char * filename_out,
		size_t block_size, const uint8_t * key_data)
{


	CryptoContainerHeader header;
	auto orig_filename = basename(const_cast<char *>(filename_in));
	std::ifstream inp { filename_in, std::ios::binary | std::ios::ate};
	if(not inp.is_open()){
		throw std::runtime_error("не могу открыть входной файл");
	}

	std::ofstream outp { filename_out, std::ios::binary};
	if(not outp.is_open()){
		throw std::runtime_error("не могу открыть выходной файл");
	}

	header.orig_size = inp.tellg();
	header.orig_name_leght = strlen(orig_filename);
	header.block_size = block_size;
	inp.seekg(0);

	auto blocks = header.orig_size/ block_size;
	if(header.orig_size % block_size > 0 ) blocks++;

	outp.write(reinterpret_cast<const char*>(&header), sizeof(header));
	outp.write(orig_filename, header.orig_name_leght);

	for(size_t i=0; i<blocks; i++)
	{
		char buffer[block_size] {};
		inp.read(buffer, block_size);

		feistel_crypt64(buffer, buffer, SOME_TEST_ROUNDS, SOME_TEST_KEY_SIZE, key_data, true, some_test_crypro_func); // @suppress("Invalid arguments")


		outp.write(buffer, block_size);

	}
}

void decrypt_file(const char * filename_in,
		const char * filename_out, const uint8_t * key_data)
{


	CryptoContainerHeader header;

	std::ifstream inp { filename_in, std::ios::binary};
	if(not inp.is_open()){
		throw std::runtime_error(std::string("не могу открыть входной файл")+std::string(strerror(errno)));
	}

	inp.read(reinterpret_cast<char*>(&header), sizeof(header));
	char orig_filename[header.orig_name_leght + 1]{};
	inp.read(orig_filename, header.orig_name_leght);
	if (filename_out == nullptr) filename_out = orig_filename;

	std::ofstream outp { filename_out, std::ios::binary};
	if(not outp.is_open()){
		throw std::runtime_error(std::string("не могу открыть выходной файл")+std::string(strerror(errno)));
	}

	size_t blocks = header.orig_size/ header.block_size;
	if(header.orig_size % header.block_size > 0 ) blocks++;

	for(size_t i=0; i<blocks; i++)
	{
		char buffer[header.block_size];
		inp.read(buffer, header.block_size);

		//шифрование

		feistel_crypt64(buffer, buffer, SOME_TEST_ROUNDS, SOME_TEST_KEY_SIZE, key_data, false, some_test_crypro_func); // @suppress("Invalid arguments")

		if (header.orig_size > header.block_size){
			outp.write(buffer, header.block_size);
			header.orig_size -= header.block_size;
		}else{
			outp.write(buffer, header.orig_size);
		}

	}
	inp.close();
	outp.close();
}

void write_key_data(const char * filename, void * data, size_t length)
{
	std::ofstream key_file { filename, std::ios::binary};
	if(not key_file.is_open()){
		throw std::runtime_error(std::string("не могу открыть ключевой файл")+std::string(strerror(errno)));
	}
	key_file.write(reinterpret_cast<const char*>(data), length);
	key_file.close();
}

std::vector<uint8_t> read_key_data(const char * filename)
{
	std::vector<uint8_t> result;
	std::ifstream key_file {filename, std::ios::binary | std::ios::ate };
	if(not key_file.is_open()){
		throw std::runtime_error(std::string("не могу открыть ключевой файл")+std::string(strerror(errno)));
	}
	size_t length = key_file.tellg();
	key_file.seekg(0);
	result.resize(length);
	key_file.read(reinterpret_cast<char*>(result.data()), length);
	key_file.close();
	return result;

}

void generate_key_from_password(const char * filename, size_t key_size)
{
	std::cout << "Введите пароль: ";
	std::string pw;
	std::getline(std::cin, pw);
	std::vector<char> key_data(key_size);
	int i;

	std::mt19937 mt;
	std::vector<std::mt19937::result_type> seed_data(std::mt19937::state_size);
	std::generate(std::begin(seed_data), std::end(seed_data),
			[&](){return pw[(i++)&pw.length()]; });
	std::seed_seq seeds(std::begin(seed_data), std::end(seed_data));
	mt.seed(seeds);
	std::generate(std::begin(key_data), std::end(key_data), [&](){return (mt() >> 5) & 0xff; });
	write_key_data(filename, key_data.data(), key_size);

}

void generate_random_key(const char * filename, size_t key_size)
{
	std::random_device rdev;
	std::mt19937 mt;
	std::vector<std::mt19937::result_type> seed_data(std::mt19937::state_size);
	std::generate(std::begin(seed_data), std::end(seed_data), [&](){return rdev(); });

	std::seed_seq seeds(std::begin(seed_data), std::end(seed_data));
	mt.seed(seeds);

	std::vector<char> key_data(key_size);
	std::generate(std::begin(key_data), std::end(key_data), [&](){return (mt() >> 5) & 0xff; });


	write_key_data(filename, key_data.data(), key_size);

}

int main (int argc, char ** argv){

	const char * operation = argv[1];
	const char * input_file_name = argv[2];
	const char * output_file_name = argv[3];
	const char * third_file_name = argv[4];

	if(argc < 2){
		std::cerr << "не хзватает параметров" << std:: endl;
		return 1;
	}

	switch (operation[0])
	{
	case 'e':
		std::cout << "входной файл:" << input_file_name << std:: endl;
		std::cout << "выходной файл:" << output_file_name << std:: endl;
		std::cout << "ключевой файл:" << third_file_name << std:: endl;
		std::cout << "Зашифрование" << std::endl;
		encrypt_file(input_file_name,output_file_name, 8, read_key_data(third_file_name).data());
		break;
	case 'd':
		std::cout << "входной файл:" << input_file_name << std:: endl;
		std::cout << "выходной файл:" << output_file_name << std:: endl;
		std::cout << "ключевой файл:" << third_file_name << std:: endl;
		std::cout << "Расшифрование" << std::endl;
		decrypt_file(input_file_name,output_file_name, read_key_data(third_file_name).data());
		break;
	case 'g':
		std::cout << "генерация ключа:" << input_file_name << std:: endl;
		std::cout << "ключевой файл:" << input_file_name << std:: endl;
		if (operation[1] == '1'){
			std::cout << "- на основе гпсч" << std:: endl;
			generate_random_key(input_file_name, SOME_TEST_KEY_SIZE);
		}else if (operation[1] == '2'){
			std::cout << "- на основе пароля" << std:: endl;
			generate_key_from_password(input_file_name, SOME_TEST_KEY_SIZE);
		}else{
			std::cout << "неизвестный способ генерации" << std:: endl;
		}
		break;
	default:
		std::cerr << "Неверная операция" << std::endl;
	}

	return 0;
}


