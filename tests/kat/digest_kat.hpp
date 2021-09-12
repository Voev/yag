#pragma once
#include <openssl/evp.h>
#include <utilities/ossl_pointers.hpp>

#include "file_parser.hpp"
#include "kat.hpp"

class DigestKAT final : public KAT
{
  public:
    explicit DigestKAT(const FileParser::Section& section);
    void Execute() override;

  private:
    std::vector<uint8_t> message_;
    ossl::EvpMdPtr digest_;
};