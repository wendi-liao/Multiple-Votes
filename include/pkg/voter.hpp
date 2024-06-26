#pragma once

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>
#include <crypto++/rsa.h>

#include "../../include-shared/config.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/db_driver.hpp"
#include "../../include/drivers/network_driver.hpp"

class VoterClient {
public:
  VoterClient(std::shared_ptr<NetworkDriver> network_driver,
              std::shared_ptr<CryptoDriver> crypto_driver,
              VoterConfig voter_config, CommonConfig common_config);
  void run();
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleKeyExchange(CryptoPP::RSA::PublicKey verification_key);
  void HandleRegister(std::string input);
  void HandleVote(std::string input);
  void HandleVerify(std::string input);
//   std::tuple<CryptoPP::Integer, CryptoPP::Integer, bool> DoVerify();
  std::pair<bool, std::vector<CryptoPP::Integer>> DoVerify();
private:
  std::string id;

  VoterConfig voter_config;
  CommonConfig common_config;
  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<DBDriver> db_driver;
  std::shared_ptr<NetworkDriver> network_driver;

  CryptoPP::Integer EG_arbiter_public_key; // The election's EG public key
  CryptoPP::SecByteBlock AES_key;
  CryptoPP::SecByteBlock HMAC_key;

//   Vote_Ciphertext vote;
  Multi_Vote_Ciphertext votes;
//   VoteZKP_Struct vote_zkp;
  Multi_VoteZKP_Struct vote_zkps;
//   CryptoPP::Integer registrar_signature;
  Multi_Integer registrar_signatures;
//   CryptoPP::Integer blind;
  Multi_Integer blinds;

  CryptoPP::RSA::PrivateKey RSA_voter_signing_key;
  CryptoPP::RSA::PublicKey RSA_registrar_verification_key;
  CryptoPP::RSA::PublicKey RSA_tallyer_verification_key;

  //add for final projects
  int t; // t candidates 
  int k; // most votes k candidates(k < t) and now set k =t  
};
