#include <secp256k1_addon.h>

#include <napi.h>

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("Secp256k1", Secp256k1Addon::Init(env));
  return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)
