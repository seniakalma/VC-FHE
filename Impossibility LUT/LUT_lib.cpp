#include "LUT_lib.h"

// OR operator for 2 encrypted values, implemented as
// (v1 + v2) - (v1 * v2)
Ctxt or_op(Ctxt& v1, Ctxt& v2){
  Ctxt a = v1;
  Ctxt b = v1;

  a += v2;
  b *= v2;
  Ctxt c = a;
  c-=b;
  return c;
}

// Flips the bit value (0 will be changed to 1, vice versa)
Ctxt flip(Ctxt& bit, Ctxt& enc_one){
  Ctxt ctSum = enc_one;
  // (1-bit)   - Flip the bit value
  ctSum -= bit;
  return ctSum;
}

// Print the decrypted value of a number
void print_value(EncryptedArray& ea, helib::SecKey& secKey, helib::Ctxt& number, string prefix){
    std::vector<long> res;
    ea.decrypt(number, secKey, res);
    if(prefix == "")
      cout << "The value is:" << res[0] << endl;
    else
      cout << prefix << res[0] << endl;
}

// Print the decrypted values of an encrypted vector
void print_vec(EncryptedArray& ea, helib::SecKey& secKey, std::vector<helib::Ctxt>& vec, int bit_size){
    std::vector<long> res;
    for(int i=0;i<bit_size;i++){
      ea.decrypt(vec[i], secKey, res);
      cout << res[0];
    }
    cout << endl;
}

// Returns a vector of length bitSize, where each element is 0 expect the element at the index that equals to encrypted_number value,
// which will be set to the output at the same index
std::vector<helib::Ctxt> LUT_compute(std::vector<helib::Ctxt>& output, std::vector<helib::Ctxt>& encrypted_number, Ctxt& enc_one, int bitSize){
    int bits = log2(bitSize);
    std::vector<long> res;
    std::vector<helib::Ctxt> enc_neg(bitSize, enc_one);

    // Set the negated bits of the input
    for(int i=0;i<bits;i++)
      enc_neg[i] = flip(encrypted_number[i], enc_one);
    
    // For value 0- [ neg(b_0) * neg(b_1) * neg(b_2) ] * output_0 ]
    // For value 1- [ neg(b_0) * neg(b_1) * (b_2)    ] * output_1 ]
    // ..
    // For value 7- [ (b_0)    * (b_1)    * (b_2)    ] * output_7 ]
    
    std::vector<helib::Ctxt> output_Line(bitSize, enc_one);

    // Go over all the possible number values (ex. 0-7)
    for(int i=0;i<bitSize;i++){
      // Go over every bit of the encrypted number (ex. b_0, b_1, b_2)
      for(int j=0;j<bits;j++){
        // Get the current bit value of the number
        bool bit = ((i >> j) & 1);

          // If the current bit is 0- Use the negated bit of the input
        if(bit == 0){
          if(j==0){
            output_Line[i] = enc_neg[0];
            continue;
          }

          output_Line[i] *= enc_neg[j];
        } // If the current bit is 1- Use the bit of the input
        else{
          if(j==0){
            output_Line[i] = encrypted_number[0];
            continue;
          }

          output_Line[i] *= encrypted_number[j];
        }
      }
    }

    // Multiply each line by the correlated output
    for(int i=0;i<bitSize;i++)
      output_Line[i] *= output[i];

    return output_Line;
}