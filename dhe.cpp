#include "dhe.h"

AutoSeededRandomPool rng;

void PrintHex(const string &label, const SecByteBlock &data)
{
}

void GenerateAndSaveParameters(const string &filename, int bitLength)
{
    Integer p, q, g;

    bool isValidPrime = false;

    while (!isValidPrime)
    {
        PrimeAndGenerator pg(1, rng, bitLength, bitLength - 1);

        p = pg.Prime();
        q = pg.SubPrime();
        g = pg.Generator();

        isValidPrime = RabinMillerTest(rng, p, 10) && RabinMillerTest(rng, q, 10);
    }

    ByteQueue queue;
    DERSequenceEncoder seq(queue);

    p.DEREncode(seq);
    q.DEREncode(seq);
    g.DEREncode(seq);
    seq.MessageEnd();

    string encoded;
    Base64Encoder encoder(new StringSink(encoded), true, 64);
    queue.CopyTo(encoder);
    encoder.MessageEnd();

    ofstream file(filename);

    file << "-----BEGIN DH PARAMETERS-----\n";
    file << encoded;
    file << "-----END DH PARAMETERS-----\n";

    file.close();
}

void LoadParametersAndEmpheralKeys(const string &filename, const string &privKeyFile, const string &pubKeyFile)
{
    ifstream file(filename);
    string pem((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());

    size_t begin = pem.find("-----BEGIN DH PARAMETERS-----");
    size_t end = pem.find("-----END DH PARAMETERS-----");

    if (begin == string::npos || end == string::npos)
    {
        throw runtime_error("Invalid PEM format");
    }

    begin += 30;
    end -= 1;

    string base64 = pem.substr(begin, end - begin);

    ByteQueue queue;
    StringSource(base64, true, new Base64Decoder(new Redirector(queue)));

    Integer p, q, g;
    BERSequenceDecoder seq(queue);
    p.BERDecode(seq);
    q.BERDecode(seq);
    g.BERDecode(seq);

    seq.MessageEnd();

    DH dh;
    dh.AccessGroupParameters().Initialize(p, q, g);

    size_t privKeyLength = (q.BitCount() + 7) / 8;

    Integer privInt;
    privInt.Randomize(rng, Integer::One(), q - Integer::One());

    SecByteBlock privKey(privKeyLength);
    privInt.Encode(privKey.BytePtr(), privKey.SizeInBytes());

    SecByteBlock pubKey(dh.PublicKeyLength());
    dh.GeneratePublicKey(rng, privKey, pubKey);

    string privKeyEncoded;

    Base64Encoder privKeyEncoder(new StringSink(privKeyEncoded), true, 64);
    privKeyEncoder.Put(privKey, privKey.size());
    privKeyEncoder.MessageEnd();

    ofstream privFile(privKeyFile);
    privFile << "-----BEGIN PRIVATE KEY-----\n";
    privFile << privKeyEncoded;
    privFile << "-----END PRIVATE KEY-----\n";

    privFile.close();

    string pubKeyEncoded = EncodePublicKey(pubKey);
    ofstream pubFile(pubKeyFile);
    pubFile << pubKeyEncoded;
    pubFile.close();
}

string EncodePublicKey(const SecByteBlock &pubKey)
{
    string encoded;
    Base64Encoder encoder(new StringSink(encoded), true, 64);
    encoder.Put(pubKey, pubKey.size());
    encoder.MessageEnd();
    return "-----BEGIN PUBLIC KEY-----\n" + encoded + "-----END PUBLIC KEY-----";
}

int main(int argc, char const *argv[])
{
    if (argc < 2)
    {
        cerr << "Usage: " << argv[0] << " [generate|load] <parameters>" << endl;
    }
    
    string mode = argv[1];

    if (mode == "generate")
    {
        if (argc != 4)
        {
            cerr << "Usage " << argv[0] << " generate <filename> <bitlength>" << endl;
            return 1;
        }
        else
        {
            string filename = argv[2];
            int bitLength = stoi(argv[3]);

            GenerateAndSaveParameters(filename, bitLength);

            cout << "Parameters generated and saved to " << filename << endl;
        }
    }
    else if (mode == "load")
    {
        if (argc != 5) {
             cerr << "Usage " << argv[0] << " load <filename> <privateFileName> <publicFileName>" << endl;
            return 1;
        } else {
            string fileName = argv[2];
            string privFileName = argv[3];
            string pubFileName = argv[4];

            LoadParametersAndEmpheralKeys(fileName, privFileName, pubFileName);

            cout << "Private key saved to " << privFileName << endl;
            cout << "Public key saved to " << pubFileName << endl;
        }
    }

    return 0;
}
