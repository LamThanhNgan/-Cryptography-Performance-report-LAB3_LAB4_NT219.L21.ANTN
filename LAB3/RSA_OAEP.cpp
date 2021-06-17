/*
* Support Tiếng Việt
* compute in z_p
* Load key from file
*/
#include <fstream>
#include "include/cryptopp/rsa.h"
using CryptoPP::RSA;
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "include/cryptopp/sha.h"       //sha1 sha2 sha256 sha512 sha384
using CryptoPP::SHA512;

#include "include/cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include "include/cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "include/cryptopp/queue.h"
using CryptoPP::ByteQueue;

#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "include/cryptopp/secBlock.h"
using CryptoPP::SecByteBlock;

#include "include/cryptopp/cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;
using CryptoPP::BufferedTransformation;

#include <string>
using std::string;
using std::wstring;

#include <exception>
using std::exception;

#include <iostream>
using std::wcout;
using std::wcin;
using std::cerr;
using std::endl;

#include <assert.h>

#include <stdexcept>
using std::runtime_error;

#include "include/cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

/* Set _setmode()*/ 
#ifdef _WIN32
#include <io.h> 
#include <fcntl.h>
#else
#endif
/* String convert */
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;

/* Integer convert */
#include <sstream>
using std::ostringstream;

/* Vietnames convert function def*/
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);
wstring integer_to_wstring (const CryptoPP::Integer& t);

/*load key X.509 binary */
void Load(const string& filename, BufferedTransformation& bt);
void LoadPublicKey(const string& filename, PublicKey& key);
void LoadPrivateKey(const string& filename, PrivateKey& key);

/*Load key base64 */
void LoadBase64PrivateKey(const string& filename, PrivateKey& key);
void LoadBase64PublicKey(const string& filename, PublicKey& key);
void LoadBase64(const string& filename, BufferedTransformation& bt);

/*Save key to file*/
void SavePrivateKey(const string& filename, const PrivateKey& key);
void SavePublicKey(const string& filename, const PublicKey& key);
void Save(const string& filename, const BufferedTransformation& bt);

// compute in interger 
#include <iomanip>
#include "include/cryptopp/integer.h"     // integer
#include "include/cryptopp/nbtheory.h"    // a_time_b
#include "include/cryptopp/modarith.h"    //.mul()

int main(int argc, char* argv[])
{
        /*Set mode support Vietnamese*/
	    #ifdef __linux__
	    setlocale(LC_ALL,"");
	    #elif _WIN32
	    _setmode(_fileno(stdin), _O_U16TEXT);
 	    _setmode(_fileno(stdout), _O_U16TEXT);
    	#else
	    #endif

        int start_s, stop_s;
        double t, total_time = 0; 
        ////////////////////////////////////////////////
        // Generate keys
        AutoSeededRandomPool rng;
        //InvertibleRSAFunction parameters;
        //parameters.GenerateRandomWithKeySize( rng, 3072 );

        RSA::PrivateKey privateKey;
        RSA::PublicKey publicKey;
        
        wcout << L"Bạn muốn sinh Key như thế nào? "<<endl;
        wcout << L"1-Key random."<<endl;
        wcout << L"2-Key từ file."<<endl;
        
        int GenerateKeyOption = 1;
        wcin >> GenerateKeyOption;

        if(GenerateKeyOption == 1)
        {
            privateKey.GenerateRandomWithKeySize(rng,3072);
            RSA::PublicKey publicKey1(privateKey);
            SavePublicKey("publicKeyRandom.key", publicKey1);
            LoadPublicKey("publicKeyRandom.key",publicKey);
            //SavePrivateKey("rsa-private.key",privateKey);
        }
        if(GenerateKeyOption == 2)
        {
            /*load key from file - binary key*/
            LoadPublicKey("rsa-public.key",publicKey);
            LoadPrivateKey("rsa-private.key", privateKey);
        }
        /*RSA parameters  */

        wcout << "RSA parameters "<<endl;
        wcout << "Public modunlo  n= " << integer_to_wstring(publicKey.GetModulus()) << endl;
		wcout << "Public key  e= " << integer_to_wstring(publicKey.GetPublicExponent()) << endl;
		wcout << "Private prime number  p= " << integer_to_wstring(privateKey.GetPrime1()) << endl;
		wcout << "Private prime number  q= " << integer_to_wstring(privateKey.GetPrime2()) << endl;
		wcout << "Private key  d= " << integer_to_wstring(privateKey.GetPrivateExponent()) << endl;
        
        // compute integer
        CryptoPP::Integer Modulus_n, Prime_q,Prime_p,PK_e,SK_d;
		Modulus_n = publicKey.GetModulus();
        PK_e =  publicKey.GetPublicExponent();

		Prime_p = privateKey.GetPrime1();
		Prime_q = privateKey.GetPrime2();
		SK_d = privateKey.GetPrivateExponent();
        
		CryptoPP::ModularArithmetic ma(Modulus_n);

		// compute n = p.q ? 
		wcout << string_to_wstring("p.q = " )<< integer_to_wstring(ma.Multiply(Prime_q,Prime_p))<<endl;    // p.q mod n == 0   => q.p = n 
        int option; 
        wcout << L"1 - Mã hóa\n2 - Giải mã\n";
        wcin >> option;
        switch (option)
        {
        case 1:
            try 
            {
                string plain, cipher;
                
                string line;
                wstring wplain;
                wcout << L"Bạn muốn nhập plaintext như thế nào? " <<endl;
                wcout << L"1 - Tự nhập plaintext\n2 - Lấy plaintext từ file plaintext.txt"<<endl;

                std::ifstream myfile("plaintext.txt");

                int opPlain;
                wcin>>opPlain;
                
                switch (opPlain)
                {
                case 1:
                    wcin.ignore(1);
                    wcout << L"Nhập plaintext: ";
                    wplain.clear();
                    wcin.ignore();
                    std::getline(std::wcin,wplain);
                    plain = wstring_to_string(wplain);
                    break;
                case 2: 
                    /*input plaintext from file*/
                    if(myfile.is_open())
                    {
                        int i = 0;
                        while(getline(myfile ,line))
                        {
                            if(i!=0) line = '\n'+line;
                            plain += line;
                            ++i;
                        }
                        myfile.close();
                    }
                    else wcout << L"Không thể mở file."<<endl;
                    break;
                }
                if(plain == "") 
                {
                    wcout << L"Chưa nhập plaintext"<<endl;
                    return 0;
                }
                wcout << L"Plaintext của bạn là:  " << string_to_wstring(plain) << endl;
                ////////////////////////////////////////////////
                string encoded;
                // Encryption
                for(int i =0; i<1000; i++)
                {
                    cipher.clear();
                    start_s=clock();
                    RSAES_OAEP_SHA_Encryptor e( publicKey );

                    StringSource( plain, true,
                        new PK_EncryptorFilter( rng, e,
                        new StringSink( cipher )   // c = m^e
                        ) // PK_EncryptorFilter
                    ); // StringSource
                    /*Check c = m^e or not ? */ 
                    encoded.clear();
                    StringSource( cipher, true,
                        new HexEncoder(new StringSink(encoded)
                        ) // PK_EncryptorFilter
                    ); // StringSource
                    stop_s=clock();
                    t = (stop_s-start_s)/double(CLOCKS_PER_SEC)*1000;
                    total_time += t;
                }

                wcout << L"Cipher text : " << string_to_wstring(encoded) << endl;
                wcout << L"Thời gian mã hóa trung bình 1000 lần: " << total_time / 1000 << " ms"<<endl;
            }
            catch( CryptoPP::Exception& e )
            {
                cerr << "Caught Exception..." << endl;
                cerr << e.what() << endl;
            }
            break;
        case 2:
            try 
            {
                ////////////////////////////////////
                // Decryption
                string ncipher, str = "";
                string nline, recovered;
                wstring wcipher;   // cipher input from screen
                std::ifstream myfile("ciphertext.txt");
                wcout << L"Bạn muốn nhập ciphertext như thế nào? " <<endl;
                wcout << L"1 - Tự nhập ciphertext\n2 - Lấy ciphertext từ file ciphertext.txt"<<endl;
                
                int opCipher;
                wcin>>opCipher;

                switch (opCipher)
                {
                case 1:
                    wcout << L"Nhập ciphertext: ";
                    wcin >> wcipher;
                    break;
                case 2:
                    /*input plaintext from file*/
                    if(myfile.is_open())
                    {
                        int i = 0;
                        while(getline(myfile ,nline))
                        {
                            if(i!=0) nline = '\n'+nline;
                            str += nline;
                            ++i;
                        }
                        wcipher = string_to_wstring(str);
                        myfile.close();
                    }
                    else wcout << L"Không thể mở file."<<endl;
                    break;
                default:
                    break;
                }
                if(wcipher == string_to_wstring("")) 
                {
                    wcout << L"Chưa nhập ciphetext"<<endl;
                    return 0;
                }

                wcout << L"Ciphertext của bạn là:  " << wcipher << endl;
                for(int i =0; i < 1000;i++)
                {
                ncipher.clear();

                start_s=clock();
                // hex encode cipher-input 
                StringSource( wstring_to_string(wcipher),true,
                new HexDecoder(new StringSink(ncipher)
                )   
                ); // stringsource 


                RSAES_OAEP_SHA_Decryptor d( privateKey );
                recovered.clear();
                StringSource( ncipher, true,
                new PK_DecryptorFilter( rng, d,
                new StringSink( recovered )
                ) // PK_EncryptorFilter
                ); // StringSource
                // decode cho ra plaintext
                    stop_s=clock();
                    t = (stop_s-start_s)/double(CLOCKS_PER_SEC)*1000;
                    total_time += t;
                }
                wcout << L"recovered: " << string_to_wstring(recovered) << endl;
                assert( plain == recovered );
                wcout << L"Thời gian giải mã trung bình 1000 lần: " << total_time/1000 << " ms"<<endl;
                }
            catch( CryptoPP::Exception& e )
            {
                cerr << "Caught Exception..." << endl;
                cerr << e.what() << endl;
            }
            break;
        default:
            break;
        }
        
       
    system("pause");
	return 0;
    /*tiếng việt*/
}

/* Convert interger to wstring */
wstring integer_to_wstring (const CryptoPP::Integer& t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t; // pumb t to oss
    std::string encoded(oss.str()); // to string 
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(encoded); // string to wstring 
}

/* convert string to wstring */
wstring string_to_wstring (const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string (const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
} 


void LoadPrivateKey(const string& filename, PrivateKey& key)
{
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);	
}

void LoadPublicKey(const string& filename, PublicKey& key)
{
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);	
}

void Load(const string& filename, BufferedTransformation& bt)
{
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

/*load key base64 from file*/
void LoadBase64PrivateKey(const string& filename, PrivateKey& key)
{
	throw runtime_error("Not implemented");
}

void LoadBase64PublicKey(const string& filename, PublicKey& key)
{
	throw runtime_error("Not implemented");
}

void LoadBase64(const string& filename, BufferedTransformation& bt)
{
	throw runtime_error("Not implemented");
}

/*Save key*/
void SavePrivateKey(const string& filename, const PrivateKey& key)
{
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void SavePublicKey(const string& filename, const PublicKey& key)
{
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void Save(const string& filename, const BufferedTransformation& bt)
{
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}