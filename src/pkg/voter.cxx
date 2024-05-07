#include "../../include/pkg/voter.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/election.hpp"
#include "util.hpp"

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Constructor
 */
VoterClient::VoterClient(std::shared_ptr<NetworkDriver> network_driver,
                         std::shared_ptr<CryptoDriver> crypto_driver,
                         VoterConfig voter_config, CommonConfig common_config) {
  // Make shared variables.
  this->voter_config = voter_config;
  this->common_config = common_config;
  this->network_driver = network_driver;
  this->crypto_driver = crypto_driver;
  this->cli_driver = std::make_shared<CLIDriver>();
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(this->common_config.db_path);
  this->db_driver->init_tables();
  this->cli_driver->init();
//   this->t = 5;
//   this->k = 5;
//   assert(this->k <= this->t && "the allowed voting number is too large");
  initLogger();


  // Load election public key
  try {
    LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                          this->EG_arbiter_public_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading arbiter public keys; "
                                    "application may be non-functional.");
  }

  // Load registrar public key
  try {
    LoadRSAPublicKey(common_config.registrar_verification_key_path,
                     this->RSA_registrar_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading registrar public key; "
                                    "application may be non-functional.");
  }

  // Load tallyer public key
  try {
    LoadRSAPublicKey(common_config.tallyer_verification_key_path,
                     this->RSA_tallyer_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Error loading tallyer public key; application may be non-functional.");
  }

  // Load vote info (vote, zkp, registrar signature, and blind)
  // This is info voter should generate or receive after registering
  try {
    Multi_Vote_Ciphertext votes;
    LoadVotes(this->voter_config.voter_vote_path, votes);
    this->votes = votes;

    Multi_VoteZKP_Struct zkps;
    LoadVoteZKPs(this->voter_config.voter_vote_zkp_path, zkps);
    this->vote_zkps = zkps;

    Multi_Integer registrar_signatures;
    LoadIntegers(this->voter_config.voter_registrar_signature_path,
                registrar_signatures);
    this->registrar_signatures = registrar_signatures;

    Multi_Integer blinds;
    LoadIntegers(this->voter_config.voter_blind_path, blinds);
    this->blinds = blinds;

    CryptoPP::Integer t;
    LoadInteger(this->voter_config.voter_number_path, t);
    this->t = static_cast<int>(t.ConvertToLong());
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Error loading vote info; voter may still need to register.");
  }
}

/**
 * Run REPL
 */
void VoterClient::run() {
  // Start REPL
  REPLDriver<VoterClient> repl = REPLDriver<VoterClient>(this);
  repl.add_action("register", "register <address> <port> {0/1,0/1,0/1...}",
                  &VoterClient::HandleRegister);
  repl.add_action("vote", "vote <address> <port>", &VoterClient::HandleVote);
  repl.add_action("verify", "verify", &VoterClient::HandleVerify);
  repl.run();
}

/**
 * Key exchange with either registrar or tallyer
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
VoterClient::HandleKeyExchange(CryptoPP::RSA::PublicKey verification_key) {
  // Generate private/public DH values
  auto dh_values = this->crypto_driver->DH_initialize();

  // Send g^a
  UserToServer_DHPublicValue_Message user_public_value_s;
  user_public_value_s.public_value = std::get<2>(dh_values);
  std::vector<unsigned char> user_public_value_data;
  user_public_value_s.serialize(user_public_value_data);
  this->network_driver->send(user_public_value_data);

  // 2) Receive m = (g^a, g^b) signed by the server
  std::vector<unsigned char> server_public_value_data =
      this->network_driver->read();
  ServerToUser_DHPublicValue_Message server_public_value_s;
  server_public_value_s.deserialize(server_public_value_data);

  // Verify signature
  bool verified = this->crypto_driver->RSA_verify(
      verification_key,
      concat_byteblocks(server_public_value_s.server_public_value,
                        server_public_value_s.user_public_value),
      server_public_value_s.server_signature);
  if (!verified) {
    this->cli_driver->print_warning("Signature verification failed");
    throw std::runtime_error("Voter: failed to verify server signature.");
  }
  if (server_public_value_s.user_public_value != std::get<2>(dh_values)) {
    this->cli_driver->print_warning("Session validation failed");
    throw std::runtime_error(
        "Voter: inconsistencies in voter public DH value.");
  }

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      server_public_value_s.server_public_value);
  CryptoPP::SecByteBlock AES_key =
      crypto_driver->AES_generate_key(DH_shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      crypto_driver->HMAC_generate_key(DH_shared_key);
  return std::make_pair(AES_key, HMAC_key);
}

/**
 * Handle registering with the registrar. This function:
 * 1) Handle key exchange.
 * 2) ElGamal encrypt the raw vote and generate a ZKP for it
 *    through `ElectionClient::GenerateVote`.
 * 3) Blind the vote and send it to the registrar.
 * 4) Receive the blind signature from the registrar and save it.
 * 5) Receives and saves the signature from the server.
 */
void VoterClient::HandleRegister(std::string input) {
  // Parse input and connect to registrar
  std::vector<std::string> args = string_split(input, ' ');
  if (args.size() != 4) {
    this->cli_driver->print_warning("usage: register <address> <port> <vote>");
    return;
  }
  this->network_driver->connect(args[1], std::stoi(args[2]));

  // Load some info from config into variables
  std::string voter_id = this->voter_config.voter_id;
  std::vector<CryptoPP::Integer> raw_votes;
    std::vector<std::string> raw_vote_strings;
    std::stringstream ss(args[3]);
    std::string raw_vote_string;
    while (std::getline(ss, raw_vote_string, ',')) {
        raw_votes.push_back(CryptoPP::Integer(std::stoi(raw_vote_string)));
    }
    

  // TODO: implement me!
    // 1) Handle key exchange.
    auto keys = HandleKeyExchange(RSA_registrar_verification_key);
    this->AES_key = keys.first;
    this->HMAC_key = keys.second;

    VoterToRegistrar_Register_Messages v2r;
    v2r.id = voter_id;
    this->t = 0;


    for(auto &raw_vote: raw_votes) {
        this->t ++;
        // 2) ElGamal encrypt the raw vote and generate a ZKP for it
        // through `ElectionClient::GenerateVote`.
        std::pair<Vote_Ciphertext, VoteZKP_Struct> encrypted_vote_and_zkp = ElectionClient::GenerateVote(raw_vote, this->EG_arbiter_public_key);
        Vote_Ciphertext vote_s = encrypted_vote_and_zkp.first;
        VoteZKP_Struct vote_zkp = encrypted_vote_and_zkp.second;
        // std::cout<<"EN RESULT:"<<" ";
        // std::vector<unsigned char> en_data_vote;
        // vote_s.serialize(en_data_vote);
        // std::cout<<chvec2str(en_data_vote)<<std::endl;
        //3) Blind the vote and send it to the registrar.
        auto msgs = crypto_driver->RSA_BLIND_blind(RSA_registrar_verification_key, vote_s); //std::pair<CryptoPP::Integer, CryptoPP::Integer> 
        CryptoPP::Integer blinded_msg = msgs.first;
        CryptoPP::Integer blind = msgs.second;

        v2r.votes.ints.push_back(blinded_msg);
        
        this->votes.ct.push_back(vote_s);
        this->vote_zkps.zkp.push_back(vote_zkp);
        this->blinds.ints.push_back(blind);
    }

    std::vector<unsigned char> v2r_raw_data = crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &v2r);
    network_driver->send(v2r_raw_data);

    //4) Receive the blind signature from the registrar and save it.
    //5) Receives and saves the signature from the server.
    std::vector<unsigned char> en_r2v_data = network_driver->read();
    auto r2v_data = crypto_driver->decrypt_and_verify(AES_key, HMAC_key, en_r2v_data);
    if(!r2v_data.second) {
        std::cerr<<"invalid message!"<<std::endl;
        return;
    }
    RegistrarToVoter_Blind_Signature_Messages r2v_sig_s;
    r2v_sig_s.deserialize(r2v_data.first);

    this->registrar_signatures = r2v_sig_s.registrar_signatures;






    // Save the ElGamal encrypted vote, ZKP, registrar signature, and blind
    // to both memory and disk
    // [STUDENTS] You may have named the RHS variables below differently.
    // Rename them to match your code.
    
    // this->vote = vote_s;
    // this->vote_zkp = vote_zkp;
    // this->registrar_signature = r2v_sig_s.registrar_signature; // checked
    // this->blind = blind;
    SaveVotes(this->voter_config.voter_vote_path, this->votes);
    SaveVoteZKPs(this->voter_config.voter_vote_zkp_path, this->vote_zkps);
    SaveIntegers(this->voter_config.voter_registrar_signature_path,
                this->registrar_signatures);
    SaveIntegers(this->voter_config.voter_blind_path, this->blinds);
    SaveInteger(this->voter_config.voter_number_path, this->t);

  this->cli_driver->print_info(
      "Voter registered! Vote saved at " + this->voter_config.voter_vote_path +
      " and vote zkp saved at " + this->voter_config.voter_vote_zkp_path);
  this->network_driver->disconnect();
}

/**
 * Handle voting with the tallyer. This function:
 * 1) Handles key exchange.
 * 2) Unblinds the registrar signature that is stored in
 * `this->registrar_signature`. 3) Sends the vote, ZKP, and unblinded signature
 * to the tallyer.
 */
void VoterClient::HandleVote(std::string input) {
  // Parse input and connect to tallyer
  std::vector<std::string> args = string_split(input, ' ');
  if (args.size() != 3) {
    this->cli_driver->print_warning("usage: vote <address> <port>");
    return;
  }
  this->network_driver->connect(args[1], std::stoi(args[2]));

  // TODO: implement me!
    // std::cout<<"Handle vote!"<<std::endl;
    //1) Handles key exchange.
    auto keys = HandleKeyExchange(RSA_tallyer_verification_key);//todo: which verification key, when registering?
    this->AES_key = keys.first;
    this->HMAC_key = keys.second;
    // std::cout<<"unbind registrar!"<<std::endl;

    // 2) Unblinds the registrar signature that is stored in this->registrar_signature`.
    Multi_Integer registrar_signatures_unbinded;
    std::cout<<"t:"<<this->t<<std::endl;

    for(int i = 0 ; i < this->t; i++) {
        CryptoPP::Integer registrar_signature_unbinded = 
            crypto_driver->RSA_BLIND_unblind(RSA_registrar_verification_key, this->registrar_signatures.ints[i], this->blinds.ints[i]);
        registrar_signatures_unbinded.ints.push_back(registrar_signature_unbinded);
    }

    //3) Sends the vote, ZKP, and unblinded signature to the tallyer.
    VoterToTallyer_Vote_Message v2t;
    
    v2t.votes = this->votes;
    v2t.unblinded_signatures = registrar_signatures_unbinded;
    v2t.zkps = this->vote_zkps;
    
    // std::cout<<"real votes size:"<<v2t.votes.ct.size();
    // std::cout<<"real sign size:"<<v2t.unblinded_signatures.ints.size();
    // std::cout<<"real zkps size:"<<v2t.zkps.zkp.size();

    // std::vector<unsigned char> raw_data;
    // v2t.serialize(raw_data);
    // VoterToTallyer_Vote_Message test_v2t;
    // test_v2t.deserialize(raw_data);
    // std::cout<<"votes size:"<<test_v2t.votes.ct.size();
    // std::cout<<"sign size:"<<test_v2t.unblinded_signatures.ints.size();
    // std::cout<<"zkps size:"<<test_v2t.zkps.zkp.size();

    std::vector<unsigned char> v2t_raw_data = crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &v2t);
    network_driver->send(v2t_raw_data);
    

  // --------------------------------
  // Exit cleanly.
  this->network_driver->disconnect();
  
}

/**
 * Handle verifying the results of the election.
 */
void VoterClient::HandleVerify(std::string input) {
  // Verify
  this->cli_driver->print_info("Verifying election results...");
  auto result = this->DoVerify();

  // Error if election failed
  if (!std::get<0>(result)) {
    this->cli_driver->print_warning("Election failed!");
    throw std::runtime_error("Election failed!");
  }

  // Print results
  this->cli_driver->print_success("Election succeeded!");
//   this->cli_driver->print_success("Number of votes for 0: " +
//                                   CryptoPP::IntToString(std::get<0>(result)));
    auto vote_results = result.second;
    for(int i = 0; i < vote_results.size(); i++) {
        this->cli_driver->print_success("Number of voter " + CryptoPP::IntToString(i) + "is: " + 
                                  CryptoPP::IntToString(vote_results[i]));
    }
 
}

/**
 * Handle verifying the results of the election. This function
 * 1) Verifies all vote ZKPs and their signatures
 * 2) Verifies all partial decryption ZKPs
 * 3) Combines the partial decryptions to retrieve the final result
 * 4) Returns a vector - the number of votes every candidate receives
 * If a vote is invalid, simply *ignore* it: do not throw an error.
 */
std::pair<bool, std::vector<CryptoPP::Integer>> VoterClient::DoVerify() {
  // TODO: implement me!
    //1) Verifies all vote ZKPs and their signatures
    // TallyerToWorld_Vote_Message
    std::cout<<"all votes!"<<std::endl;

    std::vector<VoteRow> votes = db_driver->all_votes();
    //check every voter:
    for (auto it = votes.begin(); it != votes.end(); ) {
        auto &vMsg = *it;
        if(!crypto_driver->RSA_verify(RSA_tallyer_verification_key, 
            concat_votes_zkps_and_signatures(vMsg.votes, vMsg.zkps, vMsg.unblinded_signatures), vMsg.tallyer_signatures)) {
            it = votes.erase(it);
            std::cout<<"RSA VERIFY FAILED!"<<std::endl;
        } else {
            ++it;
        }
    }
    std::cout<<"check votes!"<<std::endl;

    //check every voter's single vote and combine them
    std::vector<Vote_Ciphertext> combine_votes;
    for(int i = 0; i < this->t; i++) { // 对于每一纵列（candidate），按照原有的程序进行
        Vote_Ciphertext combine_vote;
        combine_vote.a = 1;
        combine_vote.b = 1;
        for(auto &vMsg: votes) {
            Vote_Ciphertext vote = vMsg.votes.ct[i];
            VoteZKP_Struct zkp = vMsg.zkps.zkp[i];
            CryptoPP::Integer unblinded_signature = vMsg.unblinded_signatures.ints[i];
            if(!ElectionClient::VerifyVoteZKP(std::make_pair(vote, zkp), this->EG_arbiter_public_key)) {
                std::cout<<"ZKP VERIFY FAILED!"<<std::endl;
                continue;
            }
            if(!crypto_driver->RSA_BLIND_verify(RSA_registrar_verification_key, vote, unblinded_signature)) {
                std::cout<<"registrar VERIFY FAILED!"<<std::endl;
                continue;    
            } 
            combine_vote.a = a_times_b_mod_c(combine_vote.a, vote.a, DL_P);
            combine_vote.b = a_times_b_mod_c(combine_vote.b, vote.b, DL_P);
        }
       combine_votes.push_back(combine_vote);
    }    
    std::cout<<"start partial dec!"<<std::endl;

    std::vector<CryptoPP::Integer> res;
    for(int i = 0; i < this->t; i ++) {
        std::vector<PartialDecryptionRow> partial_dec = db_driver->row_partial_decryptions(i); //这里改了，对于第i列（也就是第i个candidate），求取它的情况
        std::vector<PartialDecryptionRow> valid_partial_decryptions;
        for(auto dec_msg: partial_dec) {
            CryptoPP::Integer pki;
            LoadInteger(dec_msg.arbiter_vk_path, pki);
            if(!ElectionClient::VerifyPartialDecryptZKP(dec_msg, pki)) {
                std::cout<<"VerifyPartialDecryptZKP fail!"<<std::endl;
                continue;
            }

            valid_partial_decryptions.push_back(dec_msg);
        }
        
        Vote_Ciphertext combine_vote = combine_votes[i];
        CryptoPP::Integer ret = ElectionClient::CombineResults(combine_vote, valid_partial_decryptions);
        if(ret == -1) {
            std::cout<<"error for finding the final result!"<<std::endl;
            return std::make_pair(false, res);
        }
        
        std::cout<<"As for candidate "<<i<<", it receives vote "<<ret<<std::endl;
        res.push_back(ret);
    }
    return std::make_pair(true, res);

  
}
