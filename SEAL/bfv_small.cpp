    
using namespace std;
using namespace seal;
    
void bfv_small(){
    // tree parameters
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192; // lower than this is refused for this code
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree)); // it chose {43,43,44,44,44}
    // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60,40,60}));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // value that will be used to do modulus switching
    auto qualifiers = context.last_context_data();
    auto last_level_param_id = qualifiers->parms_id();

    // generate all keys
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    // create the objects that will do all the work
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    
    // encoding of my two matrices
    BatchEncoder batch_encoder(context);
    
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;

    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    pod_matrix[0] = 0ULL;
    pod_matrix[1] = 1ULL;
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL;
    pod_matrix[row_size + 1] = 5ULL;
    pod_matrix[row_size + 2] = 6ULL;
    pod_matrix[row_size + 3] = 7ULL;

    cout << "    First matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    Plaintext plain_matrix;
    batch_encoder.encode(pod_matrix, plain_matrix);

    vector<uint64_t> pod_matrix2;
    for (size_t i = 0; i < slot_count; i++) {
        pod_matrix2.push_back((i & size_t(0x1)) + 1);
    }
    Plaintext plain_matrix2;
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    cout << "    Second matrix:" << endl;
    print_matrix(pod_matrix2, row_size);

    cout << "    The first matrix will be shifted one to the left."
            "\n    Then both matrices will be added."
            "\n    Then square the result and return" << endl;

    // encrypt both matrices
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);

    Ciphertext encrypted_matrix2;
    encryptor.encrypt(plain_matrix2, encrypted_matrix2);

    Plaintext plain_result;

    // operation start
    auto t_start = std::chrono::high_resolution_clock::now();

    //shift first matrix one to the left
    evaluator.rotate_rows_inplace(encrypted_matrix, 1, galois_keys);
    // add both matrices
    evaluator.add_inplace(encrypted_matrix, encrypted_matrix2);
    // square
    evaluator.square_inplace(encrypted_matrix);
    // square is a multiplication, relinearize to save noise budget
    evaluator.relinearize_inplace(encrypted_matrix, relin_keys);
    // operation is over, modulus switch to reduce size of ciphertext
    evaluator.mod_switch_to_inplace(encrypted_matrix, last_level_param_id);

    // decrypt result
    vector<uint64_t> pod_result;
    decryptor.decrypt(encrypted_matrix, plain_result);

    auto t_end = std::chrono::high_resolution_clock::now();
    double elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end - t_start).count();

    batch_encoder.decode(plain_result, pod_result);
    cout << "    final result" << endl;
    print_matrix(pod_result, row_size);
    cout << "    Final noise budget:  " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits"
         << endl;
    cout << "\tIt took: " << elapsed_time_ms << " miliseconds" << endl;
}
