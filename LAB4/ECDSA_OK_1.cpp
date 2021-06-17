// ECDSA.KeyGen.cpp : Defines the entry point for the console application.
//
//header
/* Vietnamese support */
        
/* Set _setmode()*/ 
#ifdef _WIN32
#include <io.h> 
#include <fcntl.h>
#else
#endif

#include <fstream>

#include <assert.h>

#include <iostream>
using namespace std;

#include <string>
using std::wstring;

#include "cryptopp/osrng.h"
// using CryptoPP::AutoSeededX917RNG;
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/integer.h"
#include "cryptopp/nbtheory.h"
using CryptoPP::Integer;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;

#include "cryptopp/filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;

#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;
//using CryptoPP::byte;

#include "cryptopp/eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

#include "cryptopp/oids.h"
using CryptoPP::OID;
// Hex encode, decode
#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

using byte = CryptoPP::byte;

 // Funtions
bool GeneratePrivateKey( const OID& oid, ECDSA<ECP, SHA1>::PrivateKey& key );
bool GeneratePublicKey( const ECDSA<ECP, SHA1>::PrivateKey& privateKey, ECDSA<ECP, SHA1>::PublicKey& publicKey );
void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA1>::PrivateKey& key );
void SavePublicKey( const string& filename, const ECDSA<ECP, SHA1>::PublicKey& key );
void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA1>::PrivateKey& key );
void LoadPublicKey( const string& filename, ECDSA<ECP, SHA1>::PublicKey& key );

void PrintDomainParameters( const ECDSA<ECP, SHA1>::PrivateKey& key );
void PrintDomainParameters( const ECDSA<ECP, SHA1>::PublicKey& key );
void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params );
void PrintPrivateKey( const ECDSA<ECP, SHA1>::PrivateKey& key );
void PrintPublicKey( const ECDSA<ECP, SHA1>::PublicKey& key );

bool SignMessage( const ECDSA<ECP, SHA1>::PrivateKey& key, const string& message, string& signature );
bool VerifyMessage( const ECDSA<ECP, SHA1>::PublicKey& key, const string& message, const string& signature );

/* String convert */
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8_utf16;

/* Integer convert */
#include <sstream>
using std::ostringstream;

/* Vietnames convert function def*/
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);
wstring integer_to_wstring (const CryptoPP::Integer& t);

//////////////////////////////////////////
// In 2010, use SHA-256 and P-256 curve
//////////////////////////////////////////

int main(int argc, char* argv[])
{

    // main 
    /*Set mode support Vietnamese*/
	#ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif 

    // Scratch result
    bool result = false;   
    
    // Private and Public keys
    ECDSA<ECP, SHA1>::PrivateKey privateKey;
    ECDSA<ECP, SHA1>::PublicKey publicKey;
    
    /////////////////////////////////////////////
    int start=clock();
    // Generate Keys
    result = GeneratePrivateKey( CryptoPP::ASN1::secp256r1(), privateKey );
    // assert( true == result );
    // if( !result ) { return -1; }

    result = GeneratePublicKey( privateKey, publicKey );
    // assert( true == result );
    // if( !result ) { return -2; }
    int stop=clock();
    double t1 = (stop-start)/double(CLOCKS_PER_SEC)*1000;
    wcout<< "Key Generation time: "<< t1 << "ms"<< endl;
    // Load key in PKCS#9 and X.509 format     

    /////////////////////////////////////////////
    //Print Domain Parameters and Keys   
    PrintDomainParameters(publicKey );
    PrintPrivateKey( privateKey );
    PrintPublicKey( publicKey );
    
    /////////////////////////////////////////////
    // Save key in PKCS#9 and X.509 format    
    // SavePrivateKey( "ec.private.key", privateKey );
    // SavePublicKey( "ec.public.key", publicKey );
    
    /////////////////////////////////////////////


    /////////////////////////////////////////////
    // Print Domain Parameters and Keys    
    // PrintDomainParameters( publicKey );
    // PrintPrivateKey( privateKey );
    // PrintPublicKey( publicKey );
        
    /////////////////////////////////////////////
    // Sign and Verify a message 
    // Load from file      
    //wstring message = L"Chủ tịch Quốc hội Vương Đình Huệ";
    string mess;
    string line;
    ifstream myfile("message.txt");
    if(myfile.is_open())
    {
       while (getline(myfile ,line))
       {
           mess += line;
       }
        myfile.close();
    }
    else wcout << "Unable to open file"<<endl;
    wstring message = string_to_wstring(mess);
    string signature_r;
    wstring message_r=string_to_wstring(mess);
    wcout << "input message from file :"<< message << endl;
    
    // Switch signing function or the verify function

    int OP ; 
    
    wstring  encode;
    string signature;

    // Pretty print signature
    AutoSeededRandomPool prng;
    // Load secret key
    LoadPrivateKey( "ec.private.key", privateKey);
    // Print parameters //
    wcout << std::hex << "Prime number p=" <<integer_to_wstring(privateKey.GetGroupParameters().GetCurve().GetField().GetModulus()) <<endl;
    wcout << "Secret key d:" << std::hex << integer_to_wstring(privateKey.GetPrivateExponent()) << endl;
    // Public keys:
    privateKey.MakePublicKey(publicKey);
    
    //Public poins:
    wcout <<"Public key Qx=" << std::hex <<integer_to_wstring(publicKey.GetPublicElement().x) << endl;
    wcout << "Public key Qy=" << std::hex << integer_to_wstring(publicKey.GetPublicElement().y) << endl;
    
    // Verify by any peope: input publicKey, message, signature=(r,s)
    // Edit: verifier parameters : Public key hex encoded; (r, s) hex encoded
    ECDSA<ECP, SHA1>::PublicKey publicKey_r;
    LoadPublicKey("ec.public.key", publicKey_r);

    wcout<< "Type 1 to select Signing function\nType 2 to select verify function "<<endl;
    std::wcin >> OP;
    int start_s,stop_s;
    double t;
    switch (OP)
    {
    case 1:
        start_s=clock();
         //siging message
        signature.erase();    
        StringSource(wstring_to_string(message), true,
        new SignerFilter( prng,
            ECDSA<ECP,SHA1>::Signer(privateKey),
            new HexEncoder(new StringSink( signature))
        )
        );
        stop_s=clock();
        wcout << "signature (r,s):" << string_to_wstring(signature)<< endl;
        t = (stop_s-start_s)/double(CLOCKS_PER_SEC)*1000;
        wcout << "Signature Generation time: " << t << "ms"<<endl;
        break; 
    case 2:
        start_s=clock();
        signature.erase();    
        StringSource(wstring_to_string(message), true,
        new SignerFilter( prng,
            ECDSA<ECP,SHA1>::Signer(privateKey),
            new HexEncoder(new StringSink( signature))
        )
        );
        // Hex decode signature
        StringSource (signature, true,
        new HexDecoder(
        new StringSink(signature_r)
        ) // HexDecoder
        ); //

        result = VerifyMessage(publicKey_r,wstring_to_string( message_r),signature_r);
        // assert( true == result );
        stop_s=clock();
        wcout << "Verify the signature on m:" << result << endl;
        t = (stop_s-start_s)/double(CLOCKS_PER_SEC)*1000;
        wcout << "Signature Verification time: " << t << "ms"<<endl;
        break;
    default:
        wcout<< "Wrong option.";
        break;
    }
    system("pause");
    return 0;
}

/* Def functions*/

bool GeneratePrivateKey( const OID& oid, ECDSA<ECP, SHA1>::PrivateKey& key )
{
    AutoSeededRandomPool prng;

    key.Initialize( prng, oid );
    assert( key.Validate( prng, 3 ) );
    return key.Validate( prng, 3 );
}

bool GeneratePublicKey( const ECDSA<ECP, SHA1>::PrivateKey& privateKey, ECDSA<ECP, SHA1>::PublicKey& publicKey )
{
    AutoSeededRandomPool prng;

    // Sanity check
    assert( privateKey.Validate( prng, 3 ) );

    privateKey.MakePublicKey(publicKey);
    assert( publicKey.Validate( prng, 3 ) );

    return publicKey.Validate( prng, 3 );
}

void PrintDomainParameters( const ECDSA<ECP, SHA1>::PrivateKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const ECDSA<ECP, SHA1>::PublicKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );

}

void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params )
{
    wcout << endl;
    wcout << "Modulus:" << endl;
    wcout << " " <<integer_to_wstring( params.GetCurve().GetField().GetModulus()) << endl;
    
    wcout << "Coefficient A:" << endl;
    wcout << " " <<integer_to_wstring( params.GetCurve().GetA()) << endl;
    
    wcout << "Coefficient B:" << endl;
    wcout << " " << integer_to_wstring( params.GetCurve().GetB()) << endl;
    
    wcout << "Base Point:" << endl;
    wcout << " X: " << integer_to_wstring( params.GetSubgroupGenerator().x )<< endl; 
    wcout << " Y: " <<integer_to_wstring( params.GetSubgroupGenerator().y) << endl;
    
    wcout << "Subgroup Order:" << endl;
    wcout << " " << integer_to_wstring(params.GetSubgroupOrder()) << endl;
    
    wcout << "Cofactor:" << endl;
    wcout << " " << integer_to_wstring(params.GetCofactor()) << endl;    
}

void PrintPrivateKey( const ECDSA<ECP, SHA1>::PrivateKey& key )
{   
    wcout << endl;
    wcout << "Private Exponent:" << endl;
    wcout << " " << integer_to_wstring(key.GetPrivateExponent() )<< endl; 
}

void PrintPublicKey( const ECDSA<ECP, SHA1>::PublicKey& key )
{   
    wcout << endl;
    wcout << "Public Element:" << endl;
    wcout << " X: " << integer_to_wstring(key.GetPublicElement().x )<< endl; 
    wcout << " Y: " << integer_to_wstring(key.GetPublicElement().y) << endl;
}

void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA1>::PrivateKey& key )
{
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void SavePublicKey( const string& filename, const ECDSA<ECP, SHA1>::PublicKey& key )
{   
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA1>::PrivateKey& key )
{   
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

void LoadPublicKey( const string& filename, ECDSA<ECP, SHA1>::PublicKey& key )
{
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

bool SignMessage( const ECDSA<ECP, SHA1>::PrivateKey& key, const string& message, string& signature )
{
    AutoSeededRandomPool prng;
    
    signature.erase();    

    StringSource( message, true,
        new SignerFilter( prng,
            ECDSA<ECP,SHA1>::Signer(key),
            new StringSink( signature )
        ) // SignerFilter
    ); // StringSource
    
    return !signature.empty();
}

bool VerifyMessage( const ECDSA<ECP, SHA1>::PublicKey& key, const string& message, const string& signature )
{
    bool result = false;

    StringSource( signature+message, true,
        new SignatureVerificationFilter(
            ECDSA<ECP,SHA1>::Verifier(key),
            new ArraySink( (byte*)&result, sizeof(result) )
        ) // SignatureVerificationFilter
    );
    
    return result;
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
    wstring_convert<codecvt_utf8_utf16<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string (const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
} 
