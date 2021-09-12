#pragma once
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <utilities/ossl_pointers.hpp>

#include "file_parser.hpp"
#include "kat.hpp"

class KdfKAT final : public KAT
{
  public:
    explicit KdfKAT(const FileParser::Section& section);
    void Execute() override;

  private:
    std::vector<std::string> params_;
    ossl::EvpKdfPtr kdf_;
    size_t keySize_{0};
};