#include "../../include/pkg/tallyer.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include/pkg/election.hpp"
#include "constants.hpp"
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
TallyerClient::TallyerClient(TallyerConfig tallyer_config,
                             CommonConfig common_config) {
  // Make shared variables.
  this->tallyer_config = tallyer_config;
  this->common_config = common_config;
  this->cli_driver = std::make_shared<CLIDriver>();
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(this->common_config.db_path);
  this->db_driver->init_tables();
  this->cli_driver->init();

  // Load tallyer keys.
  try {
    LoadRSAPrivateKey(tallyer_config.tallyer_signing_key_path,
                      this->RSA_tallyer_signing_key);
    LoadRSAPublicKey(common_config.tallyer_verification_key_path,
                     this->RSA_tallyer_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Could not find tallyer keys, generating them instead.");
    CryptoDriver crypto_driver;
    auto keys = crypto_driver.RSA_generate_keys();
    this->RSA_tallyer_signing_key = keys.first;
    this->RSA_tallyer_verification_key = keys.second;
    SaveRSAPrivateKey(tallyer_config.tallyer_signing_key_path,
                      this->RSA_tallyer_signing_key);
    SaveRSAPublicKey(common_config.tallyer_verification_key_path,
                     this->RSA_tallyer_verification_key);
  }

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
}

/**
 * Run server.
 */
void TallyerClient::run(int port) {
  // Start listener thread
  std::thread listener_thread(&TallyerClient::ListenForConnections, this, port);
  listener_thread.detach();

  // Wait for a sign to exit.
  std::string message;
  this->cli_driver->print_info("enter \"exit\" to exit");
  while (std::getline(std::cin, message)) {
    if (message == "exit") {
      this->db_driver->close();
      return;
    }
  }
}

/**
 * Listen for new connections.
 */
void TallyerClient::ListenForConnections(int port) {
  while (1) {
    // Create new network driver and crypto driver for this connection
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();
    network_driver->listen(port);
    std::thread connection_thread(&TallyerClient::HandleTally, this,
                                  network_driver, crypto_driver);
    connection_thread.detach();
  }
}

/**
 * Handle key exchange with voter
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
TallyerClient::HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                                 std::shared_ptr<CryptoDriver> crypto_driver) {
  // Generate private/public DH keys
  auto dh_values = crypto_driver->DH_initialize();

  // Listen for g^a
  std::vector<unsigned char> user_public_value = network_driver->read();
  UserToServer_DHPublicValue_Message user_public_value_s;
  user_public_value_s.deserialize(user_public_value);

  // Respond with m = (g^b, g^a) signed with our private RSA key
  ServerToUser_DHPublicValue_Message public_value_s;
  public_value_s.server_public_value = std::get<2>(dh_values);
  public_value_s.user_public_value = user_public_value_s.public_value;
  public_value_s.server_signature = crypto_driver->RSA_sign(
      this->RSA_tallyer_signing_key,
      concat_byteblocks(public_value_s.server_public_value,
                        public_value_s.user_public_value));

  // Sign and send message
  std::vector<unsigned char> message_bytes;
  public_value_s.serialize(message_bytes);
  network_driver->send(message_bytes);

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      user_public_value_s.public_value);
  CryptoPP::SecByteBlock AES_key =
      crypto_driver->AES_generate_key(DH_shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      crypto_driver->HMAC_generate_key(DH_shared_key);
  return std::make_pair(AES_key, HMAC_key);
}

/**
 * Handle tallying a new vote. This function:
 * 1) Handles key exchange.
 * 2) Receives a vote from the user, makes sure the user hasn't voted yet,
 *    verifies the server's signature, and verify the zkp.
 * 3) Signs the vote and publishes it to the database if it is valid.
 * 4) Mark this user as having already voted.
 * Disconnect and throw an error if any MACs, signatures, or zkps are invalid
 * or if the user has already voted.
 */
void TallyerClient::HandleTally(std::shared_ptr<NetworkDriver> network_driver,
                                std::shared_ptr<CryptoDriver> crypto_driver) {
  // TODO: implement me!
    // 1) Handles key exchange.
    auto keys = HandleKeyExchange(network_driver, crypto_driver);
    CryptoPP::SecByteBlock AES_key = keys.first;
    CryptoPP::SecByteBlock HMAC_key = keys.second;
    // 2) Receives a vote from the user, makes sure the user hasn't voted yet,
    // verifies the server's signature, and verify the zkp.
    std::vector<unsigned char> en_v2t_data = network_driver->read();
    auto v2t_data = crypto_driver->decrypt_and_verify(AES_key, HMAC_key, en_v2t_data);
    if(!v2t_data.second) {
        std::cerr<<"invalid message!"<<std::endl;
        return;
    }
    VoterToTallyer_Vote_Message v2t;
    v2t.deserialize(v2t_data.first);
    // makes sure the user hasn't voted yet,
    if(db_driver->vote_exists(v2t.vote)) {
        std::cerr<< "has voted!"<<std::endl;
        network_driver->disconnect();
        return;
    }
    
    //verifies the server's signature, and verify the zkp.
    if(!crypto_driver->RSA_BLIND_verify(this->RSA_registrar_verification_key, v2t.vote, v2t.unblinded_signature)) {
        std::cerr<< "blind verification fails!"<<std::endl;
        network_driver->disconnect();
        return;
    }
    if(!ElectionClient::VerifyVoteZKP(std::make_pair(v2t.vote, v2t.zkp), this->EG_arbiter_public_key)) {
        std::cerr<< "SKP verification fails!"<<std::endl;
        network_driver->disconnect();
        return;
    }

    //3) Signs the vote and publishes it to the database if it is valid.
    //4) Mark this user as having already voted.
    std::vector<unsigned char> vote_cipher_data;
    v2t.vote.serialize(vote_cipher_data);
    std::vector<unsigned char> zkp_data;
    v2t.zkp.serialize(zkp_data);
    
    std::string sign_tallyer = chvec2str(vote_cipher_data) + chvec2str(zkp_data) + integer_to_string(v2t.unblinded_signature);
    std::string signature_tallyer = crypto_driver->RSA_sign(RSA_tallyer_signing_key, str2chvec(sign_tallyer)); //string
    
    VoteRow t2w_msg;
    t2w_msg.vote = v2t.vote;
    t2w_msg.zkp = v2t.zkp;
    t2w_msg.unblinded_signature = v2t.unblinded_signature;
    t2w_msg.tallyer_signature = signature_tallyer;

    db_driver->insert_vote(t2w_msg);

    //  Disconnect and throw an error if any MACs, signatures, or zkps are invalid
    //  or if the user has already voted.


// --------------------------------
  // Exit cleanly.
  network_driver->disconnect();
}
