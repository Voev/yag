#include "file_parser.hpp"
#include "kat.hpp"
#include <openssl/evp.h>

class DigestKAT final : public KAT
{
  public:
    explicit DigestKAT(const FileParser::Section& section);
    void Execute() override;

  private:
    std::vector<uint8_t> message_;
    const EVP_MD* digest_ = nullptr;
};