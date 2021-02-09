#include <helib/FHE.h>

using namespace helib;
using namespace std;

// OR operator for 2 encrypted values, implemented as
// (v1 + v2) - (v1 * v2)
Ctxt or_op(Ctxt& v1, Ctxt& v2);

// Flips the bit value (0 will be changed to 1, vice versa)
Ctxt flip(Ctxt& bit, Ctxt& enc_one);

// Print the decrypted value of a number
void print_value(EncryptedArray& ea, helib::SecKey& secKey, helib::Ctxt& number, string prefix="");

// Print the decrypted values of an encrypted vector
void print_vec(EncryptedArray& ea, helib::SecKey& secKey, std::vector<helib::Ctxt>& vec, int bit_size=3);

// Returns a vector of length bitSize, where each element is 0 expect the element at the index that equals to encrypted_number value,
// which will be set to the output at the same index
std::vector<helib::Ctxt> LUT_compute(std::vector<helib::Ctxt>& output, std::vector<helib::Ctxt>& enc_num, Ctxt& enc_one, int bitSize);