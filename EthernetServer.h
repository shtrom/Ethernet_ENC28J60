#ifndef EthernetServer_h
#define EthernetServer_h

#include "Print.h"

class EthernetClient;

class EthernetServer : public Print {
private:
  uint16_t _port;
  void accept();
public:
  EthernetServer(uint16_t);
  EthernetClient available();
  void begin();
  virtual size_t write(uint8_t);
  virtual size_t write(const char *str);
  virtual size_t write(const uint8_t *buf, size_t size);
};

#endif
