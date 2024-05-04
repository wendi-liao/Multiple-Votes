#pragma once
#include <iostream>
#include <mutex>
#include <sqlite3.h>
#include <string>

#include "../../include-shared/messages.hpp"

typedef RegistrarToVoter_Blind_Signature_Message VoterRow;
typedef TallyerToWorld_Vote_Message VoteRow;
typedef ArbiterToWorld_PartialDecryption_Message PartialDecryptionRow;

class DBDriver {
public:
  DBDriver();
  int open(std::string dbpath);
  int close();

  void init_tables();
  void reset_tables();

  VoterRow find_voter(std::string id, std::string candidate_id);
  VoterRow insert_voter(VoterRow voter, std::string candidate_id);

  std::vector<VoteRow> all_votes();
  VoteRow find_vote(Vote_Ciphertext vote);
  VoteRow insert_vote(VoteRow vote);
  bool vote_exists(Multi_Vote_Ciphertext votes);

  std::vector<PartialDecryptionRow> all_partial_decryptions();
  PartialDecryptionRow find_partial_decryption(std::string arbiter_id);
  PartialDecryptionRow
  insert_partial_decryption(PartialDecryptionRow partial_decryption);
  std::vector<PartialDecryptionRow> row_partial_decryptions(int id);
  PartialDecryptionRow insert_partial_decryptions(std::vector<PartialDecryptionRow> &partial_decryptions);

private:
  std::mutex mtx;
  sqlite3 *db;
};
