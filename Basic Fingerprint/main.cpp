// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include <bitset>
#include <algorithm>
#include <cctype>
#include <string>

using namespace std;
using namespace seal;


double calc_polynomial(double x, double y) {
    return ((2 * x) + y + 3);
}

// Print a number in binary, splitted to space at each side
void VC_print(int val, int space) {
    int mask, masked_n, thebit;
    for (int i = ((space*2) - 1); i >= 0; i--) {
        mask = 1 << i;
        masked_n = val & mask;
        thebit = masked_n >> i;
        cout << thebit;
        if (i == (space))
            cout << " | ";
    }
    cout << endl;
}

// Decrypte and decode an encrypted value
float ckks_decode_float(Ciphertext enc, Decryptor& decryptor, CKKSEncoder& encoder) {
    vector<double> res;
    Plaintext tmp;
    
    decryptor.decrypt(enc, tmp);
    encoder.decode(tmp, res);

    return res[0];
}

// Decrypte and decode an encrypted value as an integer
int ckks_decode(Ciphertext enc, Decryptor& decryptor, CKKSEncoder& encoder) {
    return int((0.5 + ckks_decode_float(enc, decryptor, encoder)));
}

// Encryted an integer
Ciphertext Enc_num(long long int input, Encryptor &encryptor, CKKSEncoder &encoder, double scale, bool show_debug = false)
{
    Ciphertext encrypted;
    Plaintext tmp;

    vector<double> res;
    if (show_debug)
        cout << "Encrypt x_plain to x_encrypted." << endl;
    encoder.encode(input, scale, tmp);
    encryptor.encrypt(tmp, encrypted);

    return encrypted;
}

// Add a cleartext integer value to an encryted number by the VC-FHE scheme, where the integer will be added to both of the parts
Ciphertext VC_add(Ciphertext encrypted, int num, Evaluator &evaluator, scheme_type scheme, CKKSEncoder &encoder, double scale, int bits) {
    Plaintext plain;
    encoder.encode(num, scale, plain);
    evaluator.add_plain_inplace(encrypted, plain);
    
    // Also for the other MSB side, offseted by the number of bits
    int moved = num;
    moved *= pow(2, bits);
    Plaintext plain_moved;
    encoder.encode(moved, scale, plain_moved);
    evaluator.add_plain_inplace(encrypted, plain_moved);

    return encrypted;
}

// Use the function above and also output cleartext debugging info
Ciphertext VC_add_ver(Ciphertext encrypted, int num, Evaluator& evaluator, scheme_type scheme, CKKSEncoder& encoder, double scale, int bits, Decryptor& decryptor) {
    int val = ckks_decode(encrypted, decryptor, encoder);
    cout << "\t Encrypted " << val << " will be added " << num << " and (" << num << " Lsh " << bits << ") => +(" << num << ") +(" << (num<<bits)  << ")" << endl;
    cout << "\t " << val << " + " << num + (num << bits) << "= " << (val+num+(num<<bits)) << endl;
    
    return VC_add(encrypted, num, evaluator, scheme, encoder, scale, bits);
}


void VC_FHE_example()
{
    print_example_banner("VC-FHE example, F(x, y) = (2 * x) + y + 3");

    // Initialization
    EncryptionParameters parms;
    scheme_type scheme = scheme_type::CKKS;
    parms = EncryptionParameters(scheme);
    int plaintxt_mod = 8192;
    size_t poly_modulus_degree = plaintxt_mod;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    double scale = pow(2.0, 40);
    auto context = SEALContext::Create(parms);
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();

    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    auto relin_keys = keygen.relin_keys();

    // Calculate the number of bits each of the parts (fingerprint, calculation) will have
    bool show_debug = true;
    int total_bits = log2(plaintxt_mod);
    int space_bits = total_bits / 2;

    // Set the fingerprint values
    int x_fp = 3, y_fp = 2;

    double x_input, y_input;
    double x, y;

    cout << "Our fingerprint values are F(" << x_fp << ", " << y_fp << ") = " << calc_polynomial(x_fp, y_fp) << endl;
    cout << "Each part(side) has " << space_bits << " bits allocated," << endl;
    cout << endl;

    // Get x of as the input
    cout << "Enter 2 values:" << endl;
    cin >> x_input;

    if (x_input > pow(2, space_bits)) {
        cout << "The value for x is too big" << endl;
        return;
    }

    // Position the x value of the input on the left part of the variable (Lsh6)
    x = x_input;
    x *= pow(2, space_bits);

    // Add the fingerprint to the shifted input value
    x += x_fp;

    Ciphertext enc_x = Enc_num(x, encryptor, encoder, scale);

    // Get y of the input
    cin >> y_input;

    if (y_input > pow(2, space_bits)) {
        cout << "The value for y is too big" << endl;
        return;
    }

    // Position the y value of the input on the left part of the variable (Lsh6)
    y = y_input;
    y *= pow(2, space_bits);

    // Add the fingerprint to the shifted input value
    y += y_fp;
    Ciphertext enc_y = Enc_num(y, encryptor, encoder, scale);

    cout << endl;
    cout << "We expect to get the fingerprint value of F(" << x_fp << ", " << y_fp << ") = " << calc_polynomial(x_fp, y_fp) << " at the LSB side" << endl;
    cout << "We expect to get the user result of       F(" << x_input << ", " << y_input << ") = " << calc_polynomial(x_input, y_input) << " at the MSB side" << endl;
    cout << calc_polynomial(x_input, y_input) << " left shifted by " << space_bits << " is " << calc_polynomial(x_input, y_input) << space_bits << endl;

    cout << "After positioning the input values (" << x_input << ", " << y_input << ") at Lsh " << space_bits << " along with the fingerprint (" << x_fp << ", " << y_fp << ") we get:" << endl;
    cout << "=X IS: " << x << "\t binary: ";
    VC_print(x, space_bits);
    cout << "=Y IS: " << y << "\t binary: ";
    VC_print(y, space_bits);
    cout << endl;
    
    // F(x, y) = ((2 * X) + y + 3

    // Declare variables for use in the calculations
    Plaintext x_decrypted;
    Plaintext y_decrypted;

    Ciphertext encrypted_result;
    Ciphertext enc_2_x;
    Ciphertext enc_y_3;
    Ciphertext enc_2_x_y_3;

    // Declare and calculate the plaintext variables for use in the calculations
    Plaintext plain_three;
    encoder.encode(3, scale, plain_three);

    Plaintext plain_two;
    encoder.encode(2, scale, plain_two);

    // == Calculations ==
    // Calculate 2 * X in the variable             # enc_2_x #
    cout << "-Calculating (2*X)" << endl;
    evaluator.multiply_plain(enc_x, plain_two, enc_2_x);
    evaluator.relinearize_inplace(enc_2_x, relin_keys);
    evaluator.rescale_to_next_inplace(enc_2_x);
    // Verify
    cout << "2 * X VC is: " << ckks_decode(enc_2_x, decryptor, encoder) << endl;

    // Calculate Y + 3 in the variable             # enc_y_3 #
    cout << "-Calculating Y + 3" << endl;
    enc_y_3 = VC_add_ver(enc_y, 3, evaluator, scheme, encoder, scale, space_bits, decryptor);
    evaluator.relinearize_inplace(enc_y_3, relin_keys);
    // Verify
    cout << "Y VC + 3 is: " << ckks_decode(enc_y_3, decryptor, encoder) << endl;

    // Calculate (2*X) + Y+3 in the variable       # enc_2_x_y_3 #
    // Before that, we have to make the scale of 2*X equal the (initial) scale of Y+3
    enc_2_x.scale() = scale;
    // And fixing the encryption parameters using modulus switching
    parms_id_type last_parms_id = enc_2_x.parms_id();
    evaluator.mod_switch_to_inplace(enc_y_3, last_parms_id);

    cout << "-Calculating (2*X) + Y+3" << endl;
    evaluator.add(enc_2_x, enc_y_3, enc_2_x_y_3);
    // Verify
    int full_result = ckks_decode(enc_2_x_y_3, decryptor, encoder);
    cout << "(2*X) + Y+3 is: " << full_result << endl;

    cout << "## The final result is: " << full_result << endl;
    VC_print(full_result, space_bits);
    int l_res = (full_result >> 6);     // Get the value at the 6 MSB
    int r_res = (full_result & 0x3F);   // Get the value at the 6 LSB
    cout << "MSB side is: " << l_res << " | LSB side is: " << r_res << endl;

    // Compare the VC-FHE result to a the polynomial computer regulary
    if (l_res == calc_polynomial(x_input, y_input))
        cout << "We have recieved the correct result of the calculation of " << l_res << " at the left part !" << endl;
    else
        cout << "Problem at the MSB side." << endl;
    
    if (r_res == calc_polynomial(x_fp, y_fp))
        cout << "We have recieved the expected result of the fingerprint of " << r_res << " at the right part !" << endl;
    else
        cout << "Problem at the LSB side." << endl;

    cout << endl;   
}