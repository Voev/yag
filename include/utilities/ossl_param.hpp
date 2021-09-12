#pragma once
#include <memory>
#include <vector>
#include <string>
#include <stdexcept>
#include <openssl/params.h>

namespace ossl
{

class Params
{
  public:
    explicit Params(const std::vector<std::string>& opts,
                    const OSSL_PARAM* settableParams)
    {
        params_.resize(opts.size() + 1);
        for (auto i = 0U; i < opts.size(); ++i)
        {
            auto opt = opts[i];
            auto idx = opt.find(':');

            if (idx == std::string::npos)
            {
                throw std::runtime_error("invalid option format");
            }

            auto key = opt.substr(0, idx);
            auto val = opt.substr(idx + 1, opt.size());

            if (!OSSL_PARAM_allocate_from_text(&params_[i], settableParams,
                                               key.c_str(), val.c_str(),
                                               val.length(), nullptr))
            {
                throw std::runtime_error("failed to alloc from text");
            }
        }
    }

    ~Params()
    {
        for (auto& it : params_)
        {
            OPENSSL_free(it.data);
        }
    }

    OSSL_PARAM* data()
    {
        return params_.data();
    }

  private:
    std::vector<OSSL_PARAM> params_;
};

} // namespace ossl
