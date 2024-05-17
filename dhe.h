#include <ostream>
#include <fstream>
#include <iosfwd>

#include "osrng.h"
#include "nbtheory.h"
#include "integer.h"
#include "secblock.h"
#include "queue.h"
#include "asn.h"
#include "base64.h"
#include "files.h"
#include "filters.h"
#include "dh.h"


using namespace std;
using CryptoPP::SecByteBlock;
using CryptoPP::Integer;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::PrimeAndGenerator;
using CryptoPP::RabinMillerTest;
using CryptoPP::ByteQueue;
using CryptoPP::DERSequenceEncoder;
using CryptoPP::BERSequenceDecoder;
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::Redirector;
using CryptoPP::DH;

void PrintHex(const string& label, const SecByteBlock& data);
void GenerateAndSaveParameters(const string& filename, int bitLength);
void LoadParametersAndEmpheralKeys(const string& filename, const string& privKeyFile, const string& pubKeyFile);
string EncodePublicKey(const SecByteBlock& pubkey);
void ComputeSharedKey();
