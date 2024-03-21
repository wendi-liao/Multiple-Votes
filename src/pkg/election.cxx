#include "../../include/pkg/election.hpp"
#include "../../include-shared/logger.hpp"

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Generate Vote and ZKP.
 */
std::pair<Vote_Ciphertext, VoteZKP_Struct>
ElectionClient::GenerateVote(CryptoPP::Integer vote, CryptoPP::Integer pk) {
  initLogger();
  // TODO: implement me!
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::Integer r;
    do {
        r.Randomize(rng, 2, DL_Q - 1); 
    } while (CryptoPP::GCD(r, DL_Q) != 1); 

    Vote_Ciphertext vote_cipher;
    vote_cipher.a = ModularExponentiation(DL_G, r, DL_P);
    vote_cipher.b = a_times_b_mod_c(ModularExponentiation(pk, r, DL_P), ModularExponentiation(DL_G, vote, DL_P), DL_P);

    VoteZKP_Struct zkp;
    if(vote == 0) {
        // zkp.c1.Randomize(rng, 0, n);//what is n??
        zkp.c1.Randomize(rng, 1, DL_Q);//what is n??
        zkp.r1.Randomize(rng, 1, DL_Q);
        CryptoPP::Integer b_ = a_times_b_mod_c(vote_cipher.b, EuclideanMultiplicativeInverse(DL_G, DL_P), DL_P);
        CryptoPP::Integer ac1 = ModularExponentiation(vote_cipher.a, zkp.c1, DL_P);
        zkp.a1 = a_times_b_mod_c(ModularExponentiation(DL_G, zkp.r1, DL_P), EuclideanMultiplicativeInverse(ac1, DL_P), DL_P);
        CryptoPP::Integer bc1 = ModularExponentiation(b_, zkp.c1, DL_P);
        zkp.b1 = a_times_b_mod_c(ModularExponentiation(pk, zkp.r1, DL_P), EuclideanMultiplicativeInverse(bc1, DL_P), DL_P);
        
        CryptoPP::Integer r0_;
        r0_.Randomize(rng, 1, DL_Q);
        zkp.a0 = ModularExponentiation(DL_G, r0_, DL_P);
        zkp.b0 = ModularExponentiation(pk, r0_, DL_P);

        CryptoPP::Integer c = hash_vote_zkp(pk, vote_cipher.a, vote_cipher.b, zkp.a0, zkp.b0, zkp.a1, zkp.b1) % DL_Q;
        zkp.c0 = ((c - zkp.c1) % DL_Q + DL_Q) % DL_Q;
        zkp.r0 = (r0_ + zkp.c0 * r)% DL_Q;
    }else {
        zkp.c0.Randomize(rng, 1, DL_Q);//
        zkp.r0.Randomize(rng, 1, DL_Q);
        CryptoPP::Integer ac0 = ModularExponentiation(vote_cipher.a, zkp.c0, DL_P);
        CryptoPP::Integer bc0 = ModularExponentiation(vote_cipher.b, zkp.c0, DL_P);
        zkp.a0 = a_times_b_mod_c(ModularExponentiation(DL_G, zkp.r0, DL_P), EuclideanMultiplicativeInverse(ac0, DL_P), DL_P);
        zkp.b0 = a_times_b_mod_c(ModularExponentiation(pk, zkp.r0, DL_P), EuclideanMultiplicativeInverse(bc0, DL_P), DL_P);

        CryptoPP::Integer r1_;
        r1_.Randomize(rng, 1, DL_Q);
        zkp.a1 = ModularExponentiation(DL_G, r1_, DL_P);
        zkp.b1 = ModularExponentiation(pk, r1_, DL_P);

        CryptoPP::Integer c = hash_vote_zkp(pk, vote_cipher.a, vote_cipher.b, zkp.a0, zkp.b0, zkp.a1, zkp.b1) % DL_Q;
        zkp.c1 = ((c - zkp.c0) % DL_Q + DL_Q) % DL_Q;
        zkp.r1 = (r1_ + zkp.c1 * r) % DL_Q;
    }
    return std::make_pair(vote_cipher, zkp);
}

/**
 * Verify vote zkp.
 */

bool ElectionClient::VerifyVoteZKP(
    std::pair<Vote_Ciphertext, VoteZKP_Struct> vote, CryptoPP::Integer pk) {
    
  initLogger();
  // TODO: implement me!
    Vote_Ciphertext vote_cipher = vote.first;
    VoteZKP_Struct zkp = vote.second;

    if(ModularExponentiation(DL_G, zkp.r0, DL_P) != a_times_b_mod_c(zkp.a0, ModularExponentiation(vote_cipher.a, zkp.c0, DL_P), DL_P)) return false;
    if(ModularExponentiation(DL_G, zkp.r1, DL_P) != a_times_b_mod_c(zkp.a1, ModularExponentiation(vote_cipher.a, zkp.c1, DL_P), DL_P)) return false;

    if(ModularExponentiation(pk, zkp.r0, DL_P) != a_times_b_mod_c(zkp.b0, ModularExponentiation(vote_cipher.b, zkp.c0, DL_P), DL_P)) return false;

    CryptoPP::Integer b_inv_g = a_times_b_mod_c(vote_cipher.b, EuclideanMultiplicativeInverse(DL_G, DL_P), DL_P);
    if(ModularExponentiation(pk, zkp.r1, DL_P) != a_times_b_mod_c(zkp.b1, ModularExponentiation(b_inv_g, zkp.c1, DL_P), DL_P)) return false;
    
    if((zkp.c0 + zkp.c1) % DL_Q != hash_vote_zkp(pk, vote_cipher.a, vote_cipher.b, zkp.a0, zkp.b0, zkp.a1, zkp.b1) % DL_Q) return false;

    return true;
}

/**
 * Generate partial decryption and zkp.
 */
std::pair<PartialDecryption_Struct, DecryptionZKP_Struct>
ElectionClient::PartialDecrypt(Vote_Ciphertext combined_vote,
                               CryptoPP::Integer pk, CryptoPP::Integer sk) {
  initLogger();
  // TODO: implement me!
  /*// Struct for a pd of `aggregate_ciphertext` (d) = (g^{r sk_i})
struct PartialDecryption_Struct : public Serializable {
  CryptoPP::Integer d;
  Vote_Ciphertext aggregate_ciphertext;*/
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::Integer r;
    r.Randomize(rng, 1, DL_Q); 
    CryptoPP::Integer u = ModularExponentiation(combined_vote.a, r, DL_P);
    CryptoPP::Integer v = ModularExponentiation(DL_G, r, DL_P);
    CryptoPP::Integer c = hash_dec_zkp(pk, combined_vote.a, combined_vote.b, u, v);
    CryptoPP::Integer s = (r + a_times_b_mod_c(c, sk, DL_Q)) % DL_Q;
    CryptoPP::Integer d = ModularExponentiation(combined_vote.a, sk, DL_P);

    if(ModularExponentiation(combined_vote.a, s, DL_P) != a_times_b_mod_c(u, ModularExponentiation(d, c, DL_P), DL_P)
        || ModularExponentiation(DL_G, s, DL_P) != a_times_b_mod_c(v, ModularExponentiation(pk, c, DL_P), DL_P)){
            std::cerr<<"PartialDecrypt verification error"<<std::endl;
        }

    PartialDecryption_Struct partial_de;
    partial_de.aggregate_ciphertext = combined_vote;
    partial_de.d = d;
    
    DecryptionZKP_Struct de_zkp;
    de_zkp.u = u;
    de_zkp.v = v;
    de_zkp.s = s;

    return std::make_pair(partial_de, de_zkp);
}

/**
 * Verify partial decryption zkp.
 */

bool ElectionClient::VerifyPartialDecryptZKP(
    ArbiterToWorld_PartialDecryption_Message a2w_dec_s, CryptoPP::Integer pki) {
  initLogger();
  // TODO: implement me!
    Vote_Ciphertext combined_vote = a2w_dec_s.dec.aggregate_ciphertext;
    CryptoPP::Integer c = hash_dec_zkp(pki, combined_vote.a, combined_vote.b, a2w_dec_s.zkp.u, a2w_dec_s.zkp.v);
    if(ModularExponentiation(combined_vote.a, a2w_dec_s.zkp.s, DL_P) != a_times_b_mod_c(a2w_dec_s.zkp.u, ModularExponentiation(a2w_dec_s.dec.d, c, DL_P), DL_P)
        || ModularExponentiation(DL_G, a2w_dec_s.zkp.s, DL_P) != a_times_b_mod_c(a2w_dec_s.zkp.v, ModularExponentiation(pki, c, DL_P), DL_P)){
            return false;
        }
    return true;
}

/**
 * Combine votes into one using homomorphic encryption.
 */
Vote_Ciphertext ElectionClient::CombineVotes(std::vector<VoteRow> all_votes) {
  initLogger();
  // TODO: implement me!
    Vote_Ciphertext combine_vote;
    combine_vote.a = 1;
    combine_vote.b = 1;
    for(auto &vote_msg: all_votes) {
        combine_vote.a = a_times_b_mod_c(combine_vote.a, vote_msg.vote.a, DL_P);
        combine_vote.b = a_times_b_mod_c(combine_vote.b, vote_msg.vote.b, DL_P);
    }
    return combine_vote;
}

/**
 * Combine partial decryptions into final result.
 */
CryptoPP::Integer ElectionClient::CombineResults(
    Vote_Ciphertext combined_vote,
    std::vector<PartialDecryptionRow> all_partial_decryptions) {
  initLogger();
  // TODO: implement me!
  /*  std::string arbiter_id;
  std::string arbiter_vk_path;
  PartialDecryption_Struct dec;
  DecryptionZKP_Struct zkp;*/
    CryptoPP::Integer d_mul = 1;
    for(auto &part_dec: all_partial_decryptions) {
        d_mul = a_times_b_mod_c(d_mul, part_dec.dec.d, DL_P); //mod p or not?
    }
    CryptoPP::Integer g_m = a_times_b_mod_c(combined_vote.b, EuclideanMultiplicativeInverse(d_mul, DL_P), DL_P);
    for(CryptoPP::Integer i = 0; i < 1000; i++) {
        if(ModularExponentiation(DL_G, i, DL_P) == g_m) return i;
    }
    std::cerr<<"cant find matching m!"<<std::endl;
    return -1;
}

