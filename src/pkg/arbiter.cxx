#include "../../include/pkg/arbiter.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/election.hpp"

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
ArbiterClient::ArbiterClient(ArbiterConfig arbiter_config,
                             CommonConfig common_config) {
  // Make shared variables.
  this->arbiter_config = arbiter_config;
  this->common_config = common_config;
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = std::make_shared<CryptoDriver>();
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(this->common_config.db_path);
  this->db_driver->init_tables();
  this->cli_driver->init();

  // Load arbiter keys.
  try {
    LoadInteger(arbiter_config.arbiter_secret_key_path,
                this->EG_arbiter_secret_key);
    LoadInteger(arbiter_config.arbiter_public_key_path,
                this->EG_arbiter_public_key_i);
    LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                          this->EG_arbiter_public_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Could not find arbiter keys; you might consider generating some!");
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
}

void ArbiterClient::run() {
  // Start REPL
  REPLDriver<ArbiterClient> repl = REPLDriver<ArbiterClient>(this);
  repl.add_action("keygen", "keygen", &ArbiterClient::HandleKeygen);
  repl.add_action("adjudicate", "adjudicate", &ArbiterClient::HandleAdjudicate);
  repl.run();
}

/**
 * Handle generating election keys
 */
void ArbiterClient::HandleKeygen(std::string _) {
  // Generate keys
  this->cli_driver->print_info("Generating keys, this may take some time...");
  std::pair<CryptoPP::Integer, CryptoPP::Integer> keys =
      this->crypto_driver->EG_generate();

  // Save keys
  SaveInteger(this->arbiter_config.arbiter_secret_key_path, keys.first);
  SaveInteger(this->arbiter_config.arbiter_public_key_path, keys.second);
  LoadInteger(arbiter_config.arbiter_secret_key_path,
              this->EG_arbiter_secret_key);
  LoadInteger(arbiter_config.arbiter_public_key_path,
              this->EG_arbiter_public_key_i);
  LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                        this->EG_arbiter_public_key);
  this->cli_driver->print_success("Keys succesfully generated and saved!");
}

/**
 * Handle partial decryption. This function:
 * 1) Updates the ElectionPublicKey to the most up to date (done for you).
 * 2) Gets all of the votes from the database.
 * 3) Verifies all of the vote ZKPs and their signatures.
 *    If a vote is invalid, simply ignore it.
 * 4) Combines all valid votes into one vote via `Election::CombineVotes`.
 * 5) Partially decrypts the combined vote.
 * 6) Publishes the decryption and zkp to the database.
 */
void ArbiterClient::HandleAdjudicate(std::string _) {
  // Ensure we have the most up-to-date election key
  LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                        this->EG_arbiter_public_key);
  // TODO: implement me!
    //2) Gets all of the votes from the database.
    std::vector<VoteRow>  allV = this->db_driver->all_votes(); // std::vector<VoteRow> 
    std::vector<VoteRow> valid_vote;
    for(auto &vMsg: allV) {
        if(!crypto_driver->RSA_BLIND_verify(this->RSA_registrar_verification_key, vMsg.vote, vMsg.unblinded_signature)) {
            throw std::runtime_error("Arbiter:blind verification fails!");
            continue;
        }
        if(ElectionClient::VerifyVoteZKP(std::make_pair(vMsg.vote, vMsg.zkp), this->EG_arbiter_public_key)) {
            throw std::runtime_error("Arbiter:ZKP verification fails!");
            continue;
        }
        std::vector<unsigned char> vote_cipher_data;
        vMsg.vote.serialize(vote_cipher_data);
        std::vector<unsigned char> zkp_data;
        vMsg.zkp.serialize(zkp_data);
        std::string sign_tallyer = chvec2str(vote_cipher_data) + chvec2str(zkp_data) + integer_to_string(vMsg.unblinded_signature); 
        if(!crypto_driver->RSA_verify(this->RSA_tallyer_verification_key, str2chvec(sign_tallyer), vMsg.tallyer_signature)) {
            throw std::runtime_error("Arbiter:tallyer_signature verification fails!");
            continue;
        }
        valid_vote.push_back(vMsg);
    }
    //4) Combines all valid votes into one vote via `Election::CombineVotes`.
    Vote_Ciphertext combined_vote = ElectionClient::CombineVotes(valid_vote);

    //5) Partially decrypts the combined vote.
    auto partial_decrypt = ElectionClient::PartialDecrypt(combined_vote, this->EG_arbiter_public_key_i, this->EG_arbiter_secret_key);
    
    //6) Publishes the decryption and zkp to the database.
    PartialDecryptionRow partialRow;
    partialRow.arbiter_id = arbiter_config.arbiter_id;
    partialRow.arbiter_vk_path = arbiter_config.arbiter_public_key_path;
    partialRow.dec = partial_decrypt.first;
    partialRow.zkp = partial_decrypt.second;
    this->db_driver->insert_partial_decryption(partialRow);

}
