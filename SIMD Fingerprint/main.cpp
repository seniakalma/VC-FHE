// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include <bitset>
#include <algorithm>
#include <cctype>
#include <string>

using namespace std;
using namespace seal;

// Calculate the polynomial
double calc_polynomial(double x, double y) {
    return ((((2 * x) + 1) * (y * 3)) + 5);
}

// Decrypte and decode an encrypted value, returns the first element in the vector
double ckks_decode(Ciphertext enc, Decryptor& decryptor, CKKSEncoder& encoder) {
    vector<double> res;
    Plaintext tmp;

    decryptor.decrypt(enc, tmp);
    encoder.decode(tmp, res);

    return res[0];
}

// Encryted an integer, by receving a vector of values
Ciphertext Enc_num_SIMD(vector<double> input, Encryptor &encryptor, CKKSEncoder &encoder, double scale, bool show_debug = false)
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

void VC_FHE_SIMD_example()
{
    print_example_banner("VC-FHE SIMD example, F(x, y) = (((2 * X) + 1) * (Y * 3)) + 5");

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
    int fp_x = 3, fp_y = 2;
    int fp_index = 0;

    double input_x, input_y;
    double x, y;

    cout << "We have " << slot_count << " elements in our vector." << endl;
    cout << "Our fingerprint values are F(" << fp_x << ", " << fp_y << ") = " << calc_polynomial(fp_x, fp_y) << endl;
    cout << "The fingerprint will reside in index " << fp_index << " in the vector" << endl;
    cout << endl;

    vector<double> true_result;
    vector<double> input_vec_x, input_vec_y;
    input_vec_x.reserve(slot_count);
    input_vec_y.reserve(slot_count);
    true_result.reserve(slot_count);

    input_vec_x.push_back(fp_x); input_vec_y.push_back(fp_y);
    true_result.push_back(calc_polynomial(fp_x, fp_y));

    double curr_point = 0;
    double step_size = 0.01;
    for (size_t i = 1; i < slot_count; i++, curr_point += step_size)
    {
        input_vec_x.push_back(curr_point);
        input_vec_y.push_back(2 + curr_point);
        true_result.push_back(calc_polynomial(curr_point, 2+ curr_point));
    }
    cout << "Input vector: " << endl;
    print_vector(input_vec_x, 3, 7);
    print_vector(input_vec_y, 3, 7);

    Ciphertext enc_x = Enc_num_SIMD(input_vec_x, encryptor, encoder, scale);
    Ciphertext enc_y = Enc_num_SIMD(input_vec_y, encryptor, encoder, scale);

    cout << endl;
    cout << "We expect to get the fingerprint value of F(" << fp_x << ", " << fp_y << ") = " << calc_polynomial(fp_x, fp_y) << " at the index " << fp_index << endl;

    // F(x, y) = (((2 * X) + 1) * (Y * 3)) + 5

    // Declare variables for use in the calculations
    Plaintext x_decrypted;
    Plaintext y_decrypted;

    Ciphertext encrypted_result;
    Ciphertext enc_2_x;
    Ciphertext enc_2_x_1;
    Ciphertext enc_y_3;
    Ciphertext enc_x_y;
    Ciphertext enc_x_y_5;

    // For changing the context parameters
    parms_id_type last_parms_id;

    // Declare and calculate the plaintext variables for use in the calculations
    Plaintext plain_2;
    encoder.encode(2, scale, plain_2);

    Plaintext plain_1;
    encoder.encode(1, scale, plain_1);

    Plaintext plain_3;
    encoder.encode(3, scale, plain_3);

    Plaintext plain_5;
    encoder.encode(5, scale, plain_5);

    cout << "All shown calculation results are concerning only the fingerprint element" << endl;
    cout << endl;

    // == Calculations ==
    cout << "-Calculating (2*X)" << endl;
    // In the variable # enc_2_x #
    evaluator.multiply_plain(enc_x, plain_2, enc_2_x);
    evaluator.relinearize_inplace(enc_2_x, relin_keys);
    evaluator.rescale_to_next_inplace(enc_2_x);
    // Verify
    cout << "2 * X is: " << ckks_decode(enc_2_x, decryptor, encoder) << endl;

    cout << "-Calculating 2*X + 1" << endl;
    // In the variable # enc_2_x_1 #
    // Before that, we have to make the scale of 2*X equal the (initial) scale of 1
    enc_2_x.scale() = scale;
    // And fixing the encryption parameters using modulus switching
    last_parms_id = enc_2_x.parms_id();
    evaluator.mod_switch_to_inplace(plain_1, last_parms_id);
    evaluator.add_plain(enc_2_x, plain_1, enc_2_x_1);
    evaluator.relinearize_inplace(enc_2_x_1, relin_keys);
    // Verify
    cout << "2*X + 1 is: " << ckks_decode(enc_2_x_1, decryptor, encoder) << endl;

    cout << "-Calculating Y * 3" << endl;
    // In the variable # enc_y_3 #
    evaluator.multiply_plain(enc_y, plain_3, enc_y_3);
    evaluator.relinearize_inplace(enc_y_3, relin_keys);
    evaluator.rescale_to_next_inplace(enc_y_3);
    // Verify
    cout << "Y * 3 is: " << ckks_decode(enc_y_3, decryptor, encoder) << endl;

    cout << "-Calculating (2*X)+1 * (Y*3)" << endl;
    // In the variable # enc_x_y #
    evaluator.multiply(enc_2_x_1, enc_y_3, enc_x_y);
    evaluator.relinearize_inplace(enc_x_y, relin_keys);
    evaluator.rescale_to_next_inplace(enc_x_y);
    // Verify
    cout << "(2*X)+1 * (Y*3) is: " << ckks_decode(enc_x_y, decryptor, encoder) << endl;

    cout << "-Calculating (2*X)+1*(Y*3) + 5" << endl;
    // In the variable # enc_x_y_5 #
    // Before that, we have to make the scale of 2*X equal the (initial) scale of 0.5
    enc_x_y.scale() = scale;
    // And fixing the encryption parameters using modulus switching
    last_parms_id = enc_x_y.parms_id();
    evaluator.mod_switch_to_inplace(plain_5, last_parms_id);

    evaluator.add_plain(enc_x_y, plain_5, enc_x_y_5);
    evaluator.relinearize_inplace(enc_x_y_5, relin_keys);
    // Verify
    double full_result = ckks_decode(enc_x_y_5, decryptor, encoder);
    cout << "(2*X) + Y+3 is: " << full_result << endl;

    cout << "The true result, computed with regular arithmetics, is:" << endl;
    print_vector(true_result, 3, 7);

    Plaintext plain_result;
    decryptor.decrypt(enc_x_y_5, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "    + Computed FHE SIMD result:" << endl;
    print_vector(result, 3, 7);

    if (((int)result[fp_index]) == ((int)calc_polynomial(fp_x, fp_y))) {
        cout << "The integer value of the fingerprint element (index " << fp_index << ")" <<
            " is " << ((int)result[fp_index]) << " and it equals to the expected value of " << ((int)calc_polynomial(fp_x, fp_y)) << "." << endl;
    }
    else {
        cout << "Error." << endl;
    }

    cout << endl;
}