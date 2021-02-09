#include "LUT_lib.h"

int main(int argc, char **argv)
{
    // # Initialization
    long m=0, p=257, r=1; // Native plaintext space
                          // Computations will be 'modulo p'
    int bitSize = log2(p);
    long L=256;           // Levels
    long c=6;             // Columns in key switching matrix
    long w=128;           // Hamming weight of secret key
    long d=0;
    long security = 64;
    int used_bits = 3;    // Number of bits we use
    NTL::ZZX G;
    m = FindM(security,L,c,p, d, 0, 0);
	
	helib::Context context(m, p, r);
    buildModChain(context, L, c);
    helib::SecKey secKey(context);
    const helib::PubKey& pubKey = secKey;

    G = context.alMod.getFactorsOverZZ()[0];

    secKey.GenSecKey(w);
    addSome1DMatrices(secKey);
    EncryptedArray ea(context, G);
    long nslots = ea.size();
    cout << "Our bitsize is: " << bitSize << endl;
    cout << "Using an encrypted input in our LUT" << endl << endl;
    
    // # Input
    std::vector<helib::Ctxt> encrypted_num(bitSize, helib::Ctxt(pubKey, 0));
    std::vector<helib::Ctxt> output_Line;
    std::vector<long> res;

    long number;
    cout << "Enter a number (0-7) to calculate upon:" << endl;
    cin >> number;
    cout << "=- The input is: " << number << endl;

    // Encrypt the input, bit by bit
    for (long i = bitSize-1; i >=0 ; i--)
      secKey.Encrypt(encrypted_num[i], NTL::ZZX((number >> i) & 1));

    // # Calculation
    // Calculate an encrypted 1 bit, by using OR on all the input bits
    Ctxt enc_one_clean = encrypted_num[0];
    for (int i=0;i<(used_bits-1);i++){
      Ctxt c = or_op(encrypted_num[i], encrypted_num[(i+1)]);
      enc_one_clean = or_op(enc_one_clean,c);
    }
    print_value(ea, secKey, enc_one_clean, "The calculated 1 decrypted value is: ");
    
    // Calculate an encrypted 0 bit, by subtracting the encrypted 1 by itself
    Ctxt enc_zero_clean  = enc_one_clean;
    enc_zero_clean -= enc_one_clean;

    // Set the output for each possible value
    std::vector<helib::Ctxt> output(bitSize, enc_one_clean);
    // Return 0 for all even inputs, return 1 otherwise.
    output[0] = enc_zero_clean;
    output[1] = enc_one_clean;
    output[2] = enc_zero_clean;
    output[3] = enc_one_clean;
    output[4] = enc_zero_clean;
    output[5] = enc_one_clean;
    output[6] = enc_zero_clean;
    output[7] = enc_one_clean;

    // Return the value in the output by the encrypted input
    output_Line = LUT_compute(output, encrypted_num, enc_one_clean, bitSize);

    // Sum the row values
    Ctxt ctSum = output_Line[0];
    for(int i=1;i<8;i++){
      ctSum += output_Line[i];
    }

    // # Decryption
    // Decrypt and print the output
    cout << "Line values are" << endl;
    for(int i=0;i<8;i++){
      ea.decrypt(output_Line[i], secKey, res);
      cout << res[0] << ", ";
    }
    cout << endl;
    
    ea.decrypt(ctSum, secKey, res);
    cout << "\tThe sum, or final result is: " << res[0] << endl;

    cout << "Finished" << endl;
    return 0;
}