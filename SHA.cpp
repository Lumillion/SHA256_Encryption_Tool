#include <iostream>
#include <string>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>


//Convert hash to hex
std::string to_hex(const unsigned char *hash, size_t len){
    std::ostringstream os;
    for (size_t i = 0; i < len; ++i){
        os << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return os.str();
}


//Hash input
std::string sha256(const std::string &input){
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.size());
    SHA256_Final(hash, &sha256);
    return to_hex(hash, SHA256_DIGEST_LENGTH);
}

int main(){

    std::string name;
    std::cout << "Enter Name: ";
    std::getline(std::cin, name);

    std::string StationName;
    std::cout << "Enter Station: ";
    std::getline(std::cin, StationName);

    std::string salt;
    std::cout << "Enter salt: ";
    std::getline(std::cin, salt);

    std::string concat = name + StationName + salt;
    std::string hash = sha256(concat);
    std::cout << "SHA256 HASH: " <<  hash << std::endl;

    return 0;
}