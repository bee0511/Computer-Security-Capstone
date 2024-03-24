#include "sadb.h"

#include <arpa/inet.h>
#include <linux/pfkeyv2.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <span>
#include <string>
#include <vector>

std::optional<ESPConfig> getConfigFromSADB() {
  // Allocate buffer
  std::vector<uint8_t> message(65536);
  struct sadb_msg msg;
  bzero(&msg, sizeof(msg));
  msg.sadb_msg_version = PF_KEY_V2;
  msg.sadb_msg_type = SADB_DUMP;
  msg.sadb_msg_satype = SADB_SATYPE_ESP;
  msg.sadb_msg_len = sizeof(msg) / 8;
  msg.sadb_msg_pid = getpid();

  // Create a PF_KEY_V2 socket and send the SADB_DUMP request111
  int s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
  if (write(s, &msg, sizeof(msg)) < 0) {
    std::cerr << "Failed to write SADB_DUMP request." << std::endl;
    return std::nullopt;
  }

  int msglen = read(s, message.data(), message.size());
  close(s);

  // Has SADB entry
  if (msglen != sizeof(sadb_msg)) {
    ESPConfig config{};
    struct sadb_ext *ext;
    struct sadb_sa *sa;
    struct sadb_address *addr;
    struct sadb_key *key;
    std::span<uint8_t> auth_key;
    std::span<uint8_t> encrypt_key;

    msglen -= sizeof(struct sadb_msg);
    ext = reinterpret_cast<struct sadb_ext *>(reinterpret_cast<sadb_msg *>(message.data()) + 1);

    while (msglen > 0) {
      switch (ext->sadb_ext_type) {
        case SADB_EXT_SA:
          sa = (struct sadb_sa *)ext;
          break;
        case SADB_EXT_ADDRESS_SRC:
          addr = (struct sadb_address *)ext;
          config.remote = ipToString(((struct sockaddr_in *)(addr + 1))->sin_addr.s_addr);
          break;
        case SADB_EXT_ADDRESS_DST:
          addr = (struct sadb_address *)ext;
          config.local = ipToString(((struct sockaddr_in *)(addr + 1))->sin_addr.s_addr);
          break;
        case SADB_EXT_KEY_AUTH:
          key = (struct sadb_key *)ext;
          auth_key = std::span<uint8_t>((uint8_t *)(key + 1), key->sadb_key_bits / 8);
          break;
        case SADB_EXT_KEY_ENCRYPT:
          key = (struct sadb_key *)ext;
          encrypt_key = std::span<uint8_t>((uint8_t *)(key + 1), key->sadb_key_bits / 8);
          break;
        default:
          break;
      }
      msglen -= ext->sadb_ext_len << 3;
      ext = reinterpret_cast<struct sadb_ext *>(reinterpret_cast<char *>(ext)
                                                + (ext->sadb_ext_len << 3));
    }
    // TODO: Parse SADB message
    config.spi = ntohl(sa->sadb_sa_spi);
    config.aalg = std::make_unique<ESP_AALG>(sa->sadb_sa_auth, auth_key);
    if (sa->sadb_sa_encrypt != SADB_EALG_NONE) {
      // Have enc algorithm
      config.ealg = std::make_unique<ESP_EALG>(sa->sadb_sa_encrypt, encrypt_key);
    } else {
      // No enc algorithm
      config.ealg = std::make_unique<ESP_EALG>(SADB_EALG_NONE, std::span<uint8_t>{});
    }
    return config;
  } else {
    std::cerr << "SADB entry not found." << std::endl;
    return std::nullopt;
  }
}

std::ostream &operator<<(std::ostream &os, const ESPConfig &config) {
  os << "------------------------------------------------------------" << std::endl;
  os << "AALG  : ";
  if (!config.aalg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.aalg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "EALG  : ";
  if (!config.ealg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.ealg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "Local : " << config.local << std::endl;
  os << "Remote: " << config.remote << std::endl;
  os << "SPI   : " << config.spi << std::endl;
  os << "------------------------------------------------------------";
  return os;
}
